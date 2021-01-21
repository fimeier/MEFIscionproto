// Copyright 2019 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package respool

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/go/dispatcher/internal/metrics"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

var packetPool = sync.Pool{
	New: func() interface{} {
		return newPacket()
	},
}

func GetPacket() *Packet {
	pkt := packetPool.Get().(*Packet)
	*pkt.refCount = 1
	return pkt
}

// Packet describes a SCION packet. Fields might reference each other
// (including hidden fields), so callers should only write to freshly created
// packets, and readers should take care never to mutate data.
type Packet struct {
	UnderlayRemote *net.UDPAddr

	SCION slayers.SCION
	// FIXME(roosd): currently no support for extensions.
	UDP  slayers.UDP
	SCMP slayers.SCMP

	// L4 indicates what type is at layer 4.
	L4 gopacket.LayerType

	// parser is tied to the layers in this packet.
	// IngoreUnsupported is set to true.
	parser *gopacket.DecodingLayerParser
	// buffer contains the raw slice that other fields reference
	buffer common.RawBytes

	mtx      sync.Mutex
	refCount *int

	// PacketTSExtension contains additional data to support timestamps
	common.PacketTSExtension
}

// Len returns the length of the packet.
func (p *Packet) Len() int {
	return len(p.buffer)
}

func newPacket() *Packet {
	refCount := 1
	pkt := &Packet{
		buffer:   GetBuffer(),
		refCount: &refCount,
	}
	pkt.parser = gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION,
		&pkt.SCION, &pkt.UDP, &pkt.SCMP,
	)
	pkt.parser.IgnoreUnsupported = true
	return pkt
}

// Dup increases pkt's reference count.
//
// Dup panics if it is called after the packet has been freed (i.e., it's
// reference count reached 0).
//
// Modifying a packet after the first call to Dup is racy, and callers should
// use external locking for it.
func (pkt *Packet) Dup() {
	pkt.mtx.Lock()
	if *pkt.refCount <= 0 {
		panic("cannot reference freed packet")
	}
	*pkt.refCount++
	pkt.mtx.Unlock()
}

// CopyTo copies the buffer into the provided bytearray. Returns number of bytes copied.
func (pkt *Packet) CopyTo(p []byte) int {
	n := len(pkt.buffer)
	p = p[:n]
	copy(p, pkt.buffer)
	return n
}

// Free releases a reference to the packet. Free is safe to use from concurrent
// goroutines.
func (pkt *Packet) Free() {
	pkt.mtx.Lock()
	if *pkt.refCount <= 0 {
		panic("reference count underflow")
	}
	*pkt.refCount--
	if *pkt.refCount == 0 {
		pkt.reset()
		pkt.mtx.Unlock()
		packetPool.Put(pkt)
	} else {
		pkt.mtx.Unlock()
	}
}

// DecodeFromConnERRQueue forwards timestamps to the clients
func DecodeFromConnERRQueue(conn *net.UDPConn, fd int, tsRequestChan chan common.TsRequest) error {
	/*
		called by go/dispatcher/dispatcher/underlay.go::func (dp *NetToRingDataplane) Run()
	*/
	tsRequestSet := make(common.TsRequestSet)
	errQueueMsgSet := make(common.ErrQueueMsgs, 0, common.ErrQueueLen)
	bufferIOV := make(common.RawBytes, common.BufferSize)
	bufferControl := make(common.RawBytes, common.MsgControlLenMax)

	var KernelTS syscall.Timespec
	var HwTS syscall.Timespec
	var InterfaceID uint32
	var PktLengthL2 uint32
	var Ipi syscall.Inet4Pktinfo

NEXTROUND:
	for {

		//Reset state
		bufferIOV.Zero()
		bufferIOV = bufferIOV[:cap(bufferIOV)]

		bufferControl.Zero()
		bufferControl = bufferControl[:cap(bufferControl)]

		KernelTS = syscall.Timespec{}
		HwTS = syscall.Timespec{}
		InterfaceID = 0
		PktLengthL2 = 0
		Ipi = syscall.Inet4Pktinfo{}

		//remove Items
		for _, data := range errQueueMsgSet {
			if data.Used {
				if len(errQueueMsgSet) == 1 {
					errQueueMsgSet = errQueueMsgSet[:0]
				} else {
					errQueueMsgSet = errQueueMsgSet[1:]
				}
			} else {
				break
			}
		}

		//len(tsRequestSet) == 0 => if we have nothing to compare we must/will wait
		availableRequests := math.Min(float64(len(tsRequestChan)), 10)
		for availableRequests > 0 {

			tsRequestNew := <-tsRequestChan

			tsRequest, known := tsRequestSet[tsRequestNew.HashPkt]
			if known {
				tsRequest.Count++
				tsRequest.TimeAdded = tsRequestNew.TimeAdded

			} else {
				tsRequest = common.ClientIdentifierTime{
					ClientIdentifier: tsRequestNew.ClientConn.(*reliable.Conn),
					TimeAdded:        tsRequestNew.TimeAdded,
					Count:            1,
				}
			}

			tsRequestSet[tsRequestNew.HashPkt] = tsRequest

			availableRequests--

		}

		//check if we can match some messages from the buffer
		if len(errQueueMsgSet) > 0 {
			for i, data := range errQueueMsgSet {
				//if timeAdded.Add(common.TimeoutTxErrMsg).Before(time.Now()) {
				//	fmt.Printf("removing old data...\n")
				//	delete(errQueueMsgSet, timeAdded)
				//} else {
				tsRequest, known := tsRequestSet[data.HashPkt]
				if known && !data.Used {
					//fmt.Printf("now we can send this packet to the client :-)")
					tsRequest.ClientIdentifier.WriteTo(data.DataBuffer, data.Addr)
					if tsRequest.Count > 1 {
						tsRequest.Count--
						tsRequestSet[data.HashPkt] = tsRequest
					} else {
						delete(tsRequestSet, data.HashPkt)
					}
					//nicht einfach das vorderste löschen

					data.Used = true
					errQueueMsgSet[i] = data
				}
			}
		}

		//hier kann ich vermutlich immer einmal lesen...
		var n, oobn, recvflags int
		var from syscall.Sockaddr
		var err error
		//if len(errQueueMsgSet) == 0 {
		/*
			syscall.MSG_ERRQUEUE|syscall.MSG_WAITALL funktioniert nicht
			pollen => ultra slow
			select => hat bei mir immer blockiert: Nicht klar warum
		*/

		/*
			Recvmsg()-Version direct syscall
		*/
		n, oobn, recvflags, from, err = syscall.Recvmsg(fd, bufferIOV, bufferControl, syscall.MSG_ERRQUEUE)
		if err != nil {
			//fmt.Printf("%v\n", err)
			if err == syscall.EWOULDBLOCK {
				//	time.Sleep(time.Millisecond * 1)
				//continue NEXTROUND
			} else {
				//TBD: but restarting is always a good solution
				//continue NEXTROUND
			}
		}
		/*	Recvmsg()-Version golang and Polling: 1000-10000x slower.... takes 4+ Seconds(!)

			rConn, err := conn.SyscallConn()
			if err != nil {
				fmt.Printf("err=%v\n", err)
			}

			//elapsed=4.645281046s cerr=<nil> n=554 oobn=144, recvflags=8192, from=<nil>
			start := time.Now()
			cerr := rConn.Read(func(fdNotNeeded uintptr) bool {
				n, oobn, recvflags, from, err = syscall.Recvmsg(int(fdNotNeeded), dataBuffer, oobBuffer, syscall.MSG_ERRQUEUE)
				return err != unix.EAGAIN
			})
			t := time.Now()
			elapsed := t.Sub(start)
			fmt.Printf("elapsed=%v cerr=%v n=%v oobn=%v, recvflags=%v, from=%v\n", elapsed, cerr, n, oobn, recvflags, from)
		*/
		//}

		//if we didn't received any new data, we restart (optimization: do not clean state if we haven't used it)
		if n <= 0 || err != nil {
			continue NEXTROUND //<= ugly jump, but better than returning from this function and calling it again (I guess...)
		}
		//fmt.Printf("n=%v oobn=%v, recvflags=%v, from=%v\n", n, oobn, recvflags, from)

		/*
			Parse received message
		*/
		var addr *net.UDPAddr
		switch from := from.(type) {
		case *syscall.SockaddrInet4:
			//should always be nil
			addr = &net.UDPAddr{IP: from.Addr[0:], Port: from.Port}
		}

		if recvflags != 0 {
			//fmt.Printf("flags=%v src=%v\n", recvflags, addr.String())
			var cause string
			switch recvflags {
			case syscall.MSG_CTRUNC:
				cause = "MSG_CTRUNC"
			case syscall.MSG_TRUNC:
				cause = "MSG_TRUNC"
			case syscall.MSG_ERRQUEUE:
				cause = "MSG_ERRQUEUE" //the expected case
			case syscall.MSG_ERRQUEUE | syscall.MSG_TRUNC:
				cause = "MSG_ERRQUEUE | MSG_TRUNC"
			case syscall.MSG_ERRQUEUE | syscall.MSG_CTRUNC:
				cause = "MSG_ERRQUEUE | MSG_CTRUNC"
			default:
				cause = "tbd" //should never happen... during testing add here a fatal kill yourself switch
			}
			if recvflags != syscall.MSG_ERRQUEUE {
				fmt.Printf("flags=%v cause=%s src=%v\n", recvflags, cause, addr.String()) //a breakpoint here for testing: should never be triggered
			}
		}

		bufferIOV = bufferIOV[:n]
		bufferControl = bufferControl[:oobn]

		//parse msg_control
		if len(bufferControl) > 0 {
			oob := bufferControl
			sizeofCmsgHdr := syscall.CmsgLen(0)
			for sizeofCmsgHdr <= len(oob) {
				hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
				if hdr.Len < syscall.SizeofCmsghdr {
					break
				}
				if uint64(hdr.Len) > uint64(len(oob)) {
					break
				}
				switch {
				case hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SO_RXQ_OVFL:
					fmt.Printf("not implemented\n")
				case hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SO_TIMESTAMPNS:
					fmt.Printf("not implemented\n")
				case hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SCM_TIMESTAMPING:
					scmTimestamping := *(*[3]syscall.Timespec)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
					KernelTS = scmTimestamping[0]
					HwTS = scmTimestamping[2]
					if scmTimestamping[2].Sec != 0 {
						fmt.Printf("Received a HW-Timestamp :-D: scmTimestamping[2]=%v scmTimestamping[2].Nsec=%v\n", scmTimestamping[2].Sec, scmTimestamping[2].Nsec)
					}
				case hdr.Level == syscall.SOL_SOCKET && hdr.Type == unix.SCM_TIMESTAMPING_PKTINFO:
					tsInfo := *(*[2]uint32)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
					InterfaceID = tsInfo[0]
					PktLengthL2 = tsInfo[1]
					//fmt.Printf("tsInfo[0]=%v tsInfo[1]=%v\n", tsInfo[0], tsInfo[1])
				case hdr.Level == syscall.IPPROTO_IP && hdr.Type == unix.IP_PKTINFO:
					Ipi = *(*syscall.Inet4Pktinfo)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
					//fmt.Printf("ipi.Ifindex=%v ipi.Spec_dst=%v ipi.Addr=%v\n", Ipi.Ifindex, Ipi.Spec_dst, Ipi.Addr)
				case hdr.Level == syscall.SOL_IP && hdr.Type == syscall.IP_RECVERR:
					var sockErr common.SockExtendedErr
					sockErr = *(*common.SockExtendedErr)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
					/*fmt.Printf("%v %v %v %v %v %v %v %v\n",
						sockErr.Code,
						sockErr.Errno,
						sockErr.Origin,
						sockErr.Type,
						sockErr.Code,
						sockErr.Pad,
						sockErr.Info,
						sockErr.Data,
					)*/
					if sockErr.Errno == uint32(syscall.ENOMSG) && sockErr.Info == unix.SCM_TSTAMP_SND && sockErr.Origin == unix.SO_EE_ORIGIN_TIMESTAMPING {
						//fmt.Printf("everything as excpected. Can be ignored")
					} else {
						fmt.Printf("check this....")
					}

				default:
					fmt.Printf("handleCmsg: Unimplemented case:: hdr.Level=%v hdr.Type=%v", hdr.Level, hdr.Type)
				}
				oob = oob[common.CmsgAlignOf(int(hdr.Len)):]

			}

		}

		bufferIOVWithoutL2 := bufferIOV[42:]
		hashToCompare := sha256.Sum256(bufferIOVWithoutL2)

		//compare the message with tsRequests
		tsRequest, known := tsRequestSet[hashToCompare]
		if !known {
			//vermutlich reichen die Daten welche im Buffer drin sind. speichere sie trotzdem falls es (noch) nützlich sein sollte
			buf := make(common.RawBytes, len(bufferIOVWithoutL2))
			copy(buf, bufferIOVWithoutL2[:])
			var hash common.HashData
			copy(hash[:], hashToCompare[:])
			safeMe := common.SomeInfosTBD{
				HashPkt:     hash,
				TimeAdded:   time.Now(),
				DataBuffer:  buf,
				Addr:        addr,
				KernelTS:    KernelTS,
				HwTS:        HwTS,
				InterfaceId: InterfaceID,
				PktLengthL2: PktLengthL2,
				Ipi:         Ipi,
			}
			//errQueueMsgSet.Enqueue(safeMe)
			errQueueMsgSet = append(errQueueMsgSet, safeMe)

			continue NEXTROUND //<= ugly jump, but better than returning from this function and calling it again (I guess...)
		}

		//we delete the tsRequest, as we will respond now
		if tsRequest.Count > 1 {
			tsRequest.Count--
			tsRequestSet[hashToCompare] = tsRequest
		} else {
			delete(tsRequestSet, hashToCompare)
		}

		clientConn := tsRequest.ClientIdentifier

		//add the timestamps to the databuffer
		offset := len(bufferIOV)
		//Increase the Buffer to add Timestamps
		bufferIOV = bufferIOV[:offset+32]
		binary.LittleEndian.PutUint64(bufferIOV[offset:], uint64(KernelTS.Sec))
		binary.LittleEndian.PutUint64(bufferIOV[offset+8:], uint64(KernelTS.Nsec))
		binary.LittleEndian.PutUint64(bufferIOV[offset+16:], uint64(HwTS.Sec))
		binary.LittleEndian.PutUint64(bufferIOV[offset+24:], uint64(HwTS.Nsec))
		//TODO add other infos if needed. Compare Rx-Timestamps

		//"42" removes L2 Stuff.... without it we get a "parsable" SCION packet
		clientConn.WriteTo(bufferIOV[42:], addr)

	}

}

func (pkt *Packet) DecodeFromConn(conn net.PacketConn) error {
	n, readExtra, err := conn.ReadFrom(pkt.buffer)
	if err != nil {
		return err
	}

	// Ugly Hack to receive meta data (Timestamps) without changing to much in the application logic
	// Hint: n has NOT been changed.
	// TODO: Add failsafe n+32 < p.Cap()
	// TODO2: Use the interface data and ip data for something useful (get them from ReadFrom call)
	// TODO3: Would like to pass pkt into ReadFrom (solve meta data problem), but this seems to be impossible given the current Interface
	if n+52 < len(pkt.buffer) { //hint len(pkt.buffer)==cap(pkt.buffer)
		pkt.KernelTS = syscall.Timespec{
			Sec:  int64(binary.LittleEndian.Uint64(pkt.buffer[n:])),
			Nsec: int64(binary.LittleEndian.Uint64(pkt.buffer[n+8:])),
		}
		pkt.HwTS = syscall.Timespec{
			Sec:  int64(binary.LittleEndian.Uint64(pkt.buffer[n+16:])),
			Nsec: int64(binary.LittleEndian.Uint64(pkt.buffer[n+24:])),
		}
		pkt.InterfaceId = uint32(binary.LittleEndian.Uint32(pkt.buffer[n+32:]))
		pkt.PktLengthL2 = uint32(binary.LittleEndian.Uint32(pkt.buffer[n+36:]))
		pkt.Ipi = syscall.Inet4Pktinfo{Ifindex: int32(binary.LittleEndian.Uint32(pkt.buffer[n+40:]))}
		copy(pkt.Ipi.Spec_dst[:], pkt.buffer[n+44:])
		copy(pkt.Ipi.Addr[:], pkt.buffer[n+48:])
	}

	pkt.buffer = pkt.buffer[:n]
	metrics.M.NetReadBytes().Add(float64(n))

	pkt.UnderlayRemote = readExtra.(*net.UDPAddr)
	if err := pkt.decodeBuffer(); err != nil {
		metrics.M.NetReadPkts(
			metrics.IncomingPacket{
				Result: metrics.PacketResultParseError,
			},
		).Inc()
		return err
	}
	return nil
}

func (pkt *Packet) DecodeFromReliableConn(conn net.PacketConn) error {
	n, readExtra, err := conn.ReadFrom(pkt.buffer)
	if err != nil {
		return err
	}
	pkt.buffer = pkt.buffer[:n]

	if readExtra == nil {
		return serrors.New("missing next-hop")
	}
	pkt.UnderlayRemote = readExtra.(*net.UDPAddr)
	return pkt.decodeBuffer()
}

func (pkt *Packet) decodeBuffer() error {
	decoded := make([]gopacket.LayerType, 3)

	// Unsupported layers are ignored by the parser.
	if err := pkt.parser.DecodeLayers(pkt.buffer, &decoded); err != nil {
		return err
	}
	if len(decoded) < 2 {
		return serrors.New("L4 not decoded")
	}
	l4 := decoded[len(decoded)-1]
	if l4 != slayers.LayerTypeSCMP && l4 != slayers.LayerTypeSCIONUDP {
		return serrors.New("unknown L4 layer decoded", "type", l4)
	}
	pkt.L4 = l4
	return nil
}

func (pkt *Packet) SendOnConn(conn net.PacketConn, address net.Addr) (int, error) {

	//special mode 1: we request timestamps for this outgoing packet
	//The condition is fullfilled, if
	//	a) we have a FD
	//	b) the packet has flags enable to create Tx timestamps (kernel or kernel and hw)
	// Result: special syscall to enable TS's and send the message
	if pkt.UseIpv4underlayFd != 0 && (pkt.TsMode == int(addr.TxKernelRxKernel) || pkt.TsMode == int(addr.TxKernelHwRxKernelHw)) {
		fd := pkt.UseIpv4underlayFd
		toSend := common.RawBytes(pkt.buffer)

		dst, ok := address.(*net.UDPAddr)
		if !ok {
			return 0, serrors.New("dst is not UDP", "addr", dst)
		}

		ip4 := dst.IP.To4()
		if ip4 == nil { //this should not happen, as we check it (at least in RunAppToNetDataplane())
			return 0, serrors.New("unsupported address type, must be UDP",
				"address", fmt.Sprintf("%#v", dst))
		}

		sa := &syscall.SockaddrInet4{Port: dst.Port}
		copy(sa.Addr[:], ip4)

		flags := 0
		var flagsCmsgData uint32
		flagsCmsgData = unix.SOF_TIMESTAMPING_TX_SOFTWARE
		if pkt.TsMode == int(addr.TxKernelHwRxKernelHw) {
			flagsCmsgData |= unix.SOF_TIMESTAMPING_TX_HARDWARE

		}
		oobBuffer := make([]byte, syscall.SizeofCmsghdr+4)

		//this will enable TS creation for this packet
		var cmsghdr *syscall.Cmsghdr
		cmsghdr = (*syscall.Cmsghdr)(unsafe.Pointer(&oobBuffer[0]))
		cmsghdr.Len = uint64(syscall.CmsgLen(int(unsafe.Sizeof(flagsCmsgData))))
		cmsghdr.Level = syscall.SOL_SOCKET
		cmsghdr.Type = syscall.SO_TIMESTAMPING
		cmsgData := (*uint32)(unsafe.Pointer(&oobBuffer[syscall.SizeofCmsghdr]))
		*cmsgData = flagsCmsgData

		//we could use something that is "cheaper"
		pkt.HashTsPkt = sha256.Sum256(toSend)

		//two Versions with similar performance
		//start := time.Now()
		//n, _, err := pkt.Udpv4Conn.WriteMsgUDP(toSend, oobBuffer, dst)
		err := syscall.Sendmsg(fd, toSend, oobBuffer, sa, flags)
		if err != nil {
			fmt.Printf("err=%v", err)
			return 0, err
		}
		n := len(toSend)
		//t := time.Now()
		//elapsed := t.Sub(start)
		//fmt.Printf("sendTime=%v\n", elapsed)

		return n, err
	}

	//special mode 2: We forward a packet on a reliable connection (i.e an applications unix socket)
	//The condition is fullfilled, if
	//	a) this is the "internal-ring to application buffer connection"
	//	b) the client asked for Rx-timestamps
	// Result: adding TS information to the packet
	switch conn.(type) {
	case *reliable.Conn: //this implies we forward data to the application's socket
		//there is no need to identify the specific TS modes (timestamps enabled => Rx-timestamps enabled)
		if conn.(*reliable.Conn).TsMode != 0 {
			//fmt.Printf("conn.(*reliable.Conn).TsMode=%v WE NEED TO ADD A TIMESTAMP\n", conn.(*reliable.Conn).TsMode)
			buffLen := pkt.buffer.Len()
			pkt.buffer = pkt.buffer[:buffLen+32]
			/*
				ASSUMPTION:
				Manipulation of pkt.buffer is enough, i.e. just add the data.
			*/
			/*
				Man könnte TS's auch durch Anpassung SerializeTo//framing protocol übermitteln
				Dies würde jedoch mehr Änderungen nötig machen.
			*/
			//TODO: Forward other informations and add failsafe buffLen+x <= cap(pkt.buffer)
			binary.LittleEndian.PutUint64(pkt.buffer[buffLen:], uint64(pkt.KernelTS.Sec))
			binary.LittleEndian.PutUint64(pkt.buffer[buffLen+8:], uint64(pkt.KernelTS.Nsec))
			binary.LittleEndian.PutUint64(pkt.buffer[buffLen+16:], uint64(pkt.HwTS.Sec))
			binary.LittleEndian.PutUint64(pkt.buffer[buffLen+24:], uint64(pkt.HwTS.Nsec))
		}
	}

	return conn.WriteTo(pkt.buffer, address)
}

func (pkt *Packet) reset() {
	pkt.buffer = pkt.buffer[:cap(pkt.buffer)]
	pkt.UnderlayRemote = nil
	pkt.L4 = 0

	pkt.KernelTS = syscall.Timespec{}
	pkt.HwTS = syscall.Timespec{}
	pkt.InterfaceId = 0
	pkt.PktLengthL2 = 0
	pkt.Ipi = syscall.Inet4Pktinfo{}
	pkt.TsMode = 0
	pkt.UseIpv4underlayFd = 0
	pkt.HashTsPkt = [32]byte{}

	pkt.Udpv4Conn = nil
}
