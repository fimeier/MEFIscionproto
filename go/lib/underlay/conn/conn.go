// Copyright 2017 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

// +build go1.9,linux

// Package conn implements underlay sockets with additional metadata on reads.
package conn

import (
	"flag"
	"fmt"
	"net"
	"reflect"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/sockctrl"
	"github.com/scionproto/scion/go/lib/topology/underlay"
)

// ReceiveBufferSize is the default size, in bytes, of receive buffers for
// opened sockets.
const ReceiveBufferSize = 1 << 20

const sizeOfRxqOvfl = 4 // Defined to be uint32
const sizeOfTimespec = int(unsafe.Sizeof(syscall.Timespec{}))

//Options are added to oobSize if they are in use (compare initConnUDP)
const sizeOfInet4Pktinfo = common.SizeOfInet4Pktinfo
const sizeOfScmTsPkginfo = common.SizeOfScmTsPkginfo
const sizeOfScmTimestamping = common.SizeOfScmTimestamping

var oobSize = syscall.CmsgSpace(sizeOfRxqOvfl) + syscall.CmsgSpace(sizeOfTimespec)
var sizeIgnore = flag.Bool("overlay.conn.sizeIgnore", true,
	"Ignore failing to set the receive buffer size on a socket.")

// Messages is a list of ipX.Messages. It is necessary to hide the type alias
// between ipv4.Message, ipv6.Message and socket.Message.
type Messages []ipv4.Message

// Conn describes the API for an underlay socket with additional metadata on
// reads.
type Conn interface {
	Read(common.RawBytes) (int, *ReadMeta, error)
	ReadBatch(Messages, []ReadMeta) (int, error)
	Write(common.RawBytes) (int, error)
	WriteTo(common.RawBytes, *net.UDPAddr) (int, error)
	WriteBatch(Messages) (int, error)
	LocalAddr() *net.UDPAddr
	RemoteAddr() *net.UDPAddr
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SetDeadline(time.Time) error
	Close() error
}

// Config customizes the behavior of an underlay socket.
type Config struct {
	// ReceiveBufferSize is the size of the operating system receive buffer, in
	// bytes. If 0, the package constant is used instead.
	ReceiveBufferSize int
	//Timestamping options of an underlay socket
	*common.TimestampOptions
}

func (c *Config) getReceiveBufferSize() int {
	if c.ReceiveBufferSize != 0 {
		return c.ReceiveBufferSize
	}
	return ReceiveBufferSize
}

// New opens a new underlay socket on the specified addresses.
//
// The config can be used to customize socket behavior. If config is nil,
// default values are used.
func New(listen, remote *net.UDPAddr, cfg *Config) (Conn, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.TimestampOptions == nil {
		cfg.TimestampOptions = &common.TimestampOptions{}
	}
	a := listen
	if remote != nil {
		a = remote
	}
	if listen == nil && remote == nil {
		panic("either listen or remote must be set")
	}
	if a.IP.To4() != nil {
		return newConnUDPIPv4(listen, remote, cfg)
	}
	return newConnUDPIPv6(listen, remote, cfg)
}

type connUDPIPv4 struct {
	connUDPBase
	pconn *ipv4.PacketConn
}

func newConnUDPIPv4(listen, remote *net.UDPAddr, cfg *Config) (*connUDPIPv4, error) {
	cc := &connUDPIPv4{}
	if err := cc.initConnUDP("udp4", listen, remote, cfg); err != nil {
		return nil, err
	}
	cc.pconn = ipv4.NewPacketConn(cc.conn)
	return cc, nil
}

// ReadBatch reads up to len(msgs) packets, and stores them in msgs, with their
// corresponding ReadMeta in metas. It returns the number of packets read, and an error if any.
func (c *connUDPIPv4) ReadBatch(msgs Messages, metas []ReadMeta) (int, error) {
	for i := range metas {
		metas[i].reset()
	}
	n, err := c.pconn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
	readTime := time.Now()
	for i := 0; i < n; i++ {
		msg := msgs[i]
		meta := &metas[i]
		if msg.NN > 0 {
			c.handleCmsg(msg.OOB[:msg.NN], meta, readTime)
		}
		meta.setSrc(c.Remote, msg.Addr.(*net.UDPAddr), underlay.UDPIPv4)
	}
	return n, err
}

func (c *connUDPIPv4) WriteBatch(msgs Messages) (int, error) {
	return c.pconn.WriteBatch(msgs, 0)
}

// SetReadDeadline sets the read deadline associated with the endpoint.
func (c *connUDPIPv4) SetReadDeadline(t time.Time) error {
	return c.pconn.SetReadDeadline(t)
}

func (c *connUDPIPv4) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

func (c *connUDPIPv4) SetDeadline(t time.Time) error {
	return c.pconn.SetDeadline(t)
}

type connUDPIPv6 struct {
	connUDPBase
	pconn *ipv6.PacketConn
}

func newConnUDPIPv6(listen, remote *net.UDPAddr, cfg *Config) (*connUDPIPv6, error) {
	cc := &connUDPIPv6{}
	if err := cc.initConnUDP("udp6", listen, remote, cfg); err != nil {
		return nil, err
	}
	cc.pconn = ipv6.NewPacketConn(cc.conn)
	return cc, nil
}

// ReadBatch reads up to len(msgs) packets, and stores them in msgs, with their
// corresponding ReadMeta in metas. It returns the number of packets read, and an error if any.
func (c *connUDPIPv6) ReadBatch(msgs Messages, metas []ReadMeta) (int, error) {
	for i := range metas {
		metas[i].reset()
	}
	n, err := c.pconn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
	readTime := time.Now()
	for i := 0; i < n; i++ {
		msg := msgs[i]
		meta := &metas[i]
		if msg.NN > 0 {
			c.handleCmsg(msg.OOB[:msg.NN], meta, readTime)
		}
		meta.setSrc(c.Remote, msg.Addr.(*net.UDPAddr), underlay.UDPIPv6)
	}
	return n, err
}

func (c *connUDPIPv6) WriteBatch(msgs Messages) (int, error) {
	return c.pconn.WriteBatch(msgs, 0)
}

// SetReadDeadline sets the read deadline associated with the endpoint.
func (c *connUDPIPv6) SetReadDeadline(t time.Time) error {
	return c.pconn.SetReadDeadline(t)
}

func (c *connUDPIPv6) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

func (c *connUDPIPv6) SetDeadline(t time.Time) error {
	return c.pconn.SetDeadline(t)
}

type connUDPBase struct {
	conn     *net.UDPConn
	Listen   *net.UDPAddr
	Remote   *net.UDPAddr
	oob      common.RawBytes
	closed   bool
	readMeta ReadMeta
}

func (cc *connUDPBase) initConnUDP(network string, laddr, raddr *net.UDPAddr, cfg *Config) error {
	var c *net.UDPConn
	var err error
	if laddr == nil {
		return serrors.New("listen address must be specified")
	}
	if raddr == nil {
		if c, err = net.ListenUDP(network, laddr); err != nil {
			return serrors.WrapStr("Error listening on socket", err,
				"network", network, "listen", laddr)
		}
	} else {
		if c, err = net.DialUDP(network, laddr, raddr); err != nil {
			return serrors.WrapStr("Error setting up connection", err,
				"network", network, "listen", laddr, "remote", raddr)
		}
	}
	if network == "udp4" && (cfg.EnableTimestampRX || cfg.EnableTimestampTX) {
		connUDPValue := reflect.ValueOf(c)
		conn := reflect.Indirect(reflect.Indirect(connUDPValue).FieldByName("conn"))
		netFD := reflect.Indirect(reflect.Indirect(conn).FieldByName("fd"))
		pfd := reflect.Indirect(netFD.FieldByName("pfd"))
		ipv4fd := int(pfd.FieldByName("Sysfd").Int())
		cfg.TimestampOptions.FdUDPv4 = ipv4fd
		cfg.Udpv4Conn = c
	}
	if network == "udp6" && cfg.EnableTimestampUdp6 && (cfg.EnableTimestampRX || cfg.EnableTimestampTX) {
		log.Error("udp6 timestamps not implemented")
	}
	// Set reporting socket options
	if err := sockctrl.SetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RXQ_OVFL, 1); err != nil {
		return serrors.WrapStr("Error setting SO_RXQ_OVFL socket option", err,
			"listen", laddr, "remote", raddr)
	}

	//TODO: HWTs-Flags entfernen falls nicht angefrag, device etc.... nicht alles kann hier geändert werden. binding nic müsste bereits früher stattfinden
	if network == "udp4" && (cfg.EnableTimestampRX || cfg.EnableTimestampTX) {
		//Used to map MSG_ERRQUEUE messages including Timestamps with NTP packets
		//For the "Dispatcher-Setting": Those addresses are meaningless, as we always have the "same destination, i.e. next hop"
		//but we still get the device back (relevant for hw timestamps, i.e. to identify the hw-clock in a multi-nic setting)
		if err := sockctrl.SetsockoptInt(c, syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1); err != nil {
			return serrors.WrapStr("Error setting IP_PKTINFO socket option", err,
				"listen", laddr, "remote", raddr)
		}
		flagsRX := unix.SOF_TIMESTAMPING_SOFTWARE | unix.SOF_TIMESTAMPING_RX_SOFTWARE | unix.SOF_TIMESTAMPING_RAW_HARDWARE | unix.SOF_TIMESTAMPING_RX_HARDWARE | unix.SOF_TIMESTAMPING_OPT_PKTINFO | unix.SOF_TIMESTAMPING_OPT_TX_SWHW | unix.SOF_TIMESTAMPING_OPT_CMSG
		//flagsTX := unix.SOF_TIMESTAMPING_TX_SOFTWARE | unix.SOF_TIMESTAMPING_TX_HARDWARE
		flags := flagsRX // we never activate the tx flags in the dispatcher setting | flagsTX
		//Here we activate the Timestamping options
		if err := sockctrl.SetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPING, flags); err != nil {
			//This are the "original flags": Those informations are parsed as a subset and remain accessible by all applications (logger,...)
			//compare handleCmsg() function for details.
			//if err := sockctrl.SetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
			return serrors.WrapStr("Error setting SO_TIMESTAMPNS socket option", err,
				"listen", laddr, "remote", raddr)
		}
		oobSize += sizeOfInet4Pktinfo + sizeOfScmTsPkginfo + sizeOfScmTimestamping
	} else {
		if err := sockctrl.SetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
			return serrors.WrapStr("Error setting SO_TIMESTAMPNS socket option", err,
				"listen", laddr, "remote", raddr)

		}
	}
	// Set and confirm receive buffer size
	before, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return serrors.WrapStr("Error getting SO_RCVBUF socket option (before)", err,
			"listen", laddr, "remote", raddr)
	}
	if err = c.SetReadBuffer(cfg.getReceiveBufferSize()); err != nil {
		return serrors.WrapStr("Error setting recv buffer size", err,
			"listen", laddr, "remote", raddr)
	}
	after, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return serrors.WrapStr("Error getting SO_RCVBUF socket option (after)", err,
			"listen", laddr, "remote", raddr)
	}
	if after/2 != ReceiveBufferSize {
		msg := "Receive buffer size smaller than requested"
		ctx := []interface{}{"expected", ReceiveBufferSize, "actual", after / 2,
			"before", before / 2}
		if !*sizeIgnore {
			return serrors.New(msg, ctx...)
		}
		log.Info(msg, ctx...)
	}

	oob := make(common.RawBytes, oobSize)
	cc.conn = c
	cc.Listen = laddr
	cc.Remote = raddr
	cc.oob = oob
	return nil
}

func (c *connUDPBase) Read(b common.RawBytes) (int, *ReadMeta, error) {
	c.readMeta.reset()
	n, oobn, flags, src, err := c.conn.ReadMsgUDP(b, c.oob)
	//This is missing in the current implementation
	//Decide what should be done with those informations
	if flags != 0 {
		var cause string
		switch flags {
		case syscall.MSG_CTRUNC:
			cause = "MSG_CTRUNC"
		case syscall.MSG_TRUNC:
			cause = "MSG_TRUNC"
		default:
			cause = "tbd"
		}
		log.Error("There was a problem with the recv-buffer: flags=%v cause=%s src.String()=%s", flags, cause, src.String()) //a breakpoint here for testing: should never be triggered
	}
	readTime := time.Now()
	if oobn > 0 {
		c.handleCmsg(c.oob[:oobn], &c.readMeta, readTime)
	}
	if c.Remote != nil {
		c.readMeta.Src = c.Remote
	} else if src != nil {
		c.readMeta.Src = &net.UDPAddr{
			IP:   src.IP,
			Port: src.Port,
			Zone: src.Zone,
		}
	}
	return n, &c.readMeta, err
}

// handleCmsg contains probably a bug with the alignment (compare the last line)
func (c *connUDPBase) handleCmsg(oob common.RawBytes, meta *ReadMeta, readTime time.Time) {
	// Based on https://github.com/golang/go/blob/release-branch.go1.8/src/syscall/sockcmsg_unix.go#L49
	// and modified to remove most allocations.
	sizeofCmsgHdr := syscall.CmsgLen(0)
	for sizeofCmsgHdr <= len(oob) {
		hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if hdr.Len < syscall.SizeofCmsghdr {
			log.Error("Cmsg from ReadMsgUDP has corrupted header length", "listen", c.Listen,
				"remote", c.Remote, "min", syscall.SizeofCmsghdr, "actual", hdr.Len)
			return
		}
		if uint64(hdr.Len) > uint64(len(oob)) {
			log.Error("Cmsg from ReadMsgUDP longer than remaining buffer",
				"listen", c.Listen, "remote", c.Remote, "max", len(oob), "actual", hdr.Len)
			return
		}
		switch {
		case hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SO_RXQ_OVFL:
			meta.RcvOvfl = *(*uint32)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
		case hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SO_TIMESTAMPNS:
			tv := *(*syscall.Timespec)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
			meta.Recvd = time.Unix(int64(tv.Sec), int64(tv.Nsec))
			meta.ReadDelay = readTime.Sub(meta.Recvd)
			// Guard against leap-seconds.
			if meta.ReadDelay < 0 {
				meta.ReadDelay = 0
			}
		case hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SCM_TIMESTAMPING:
			/* <linux/errqueue.h>
			struct scm_timestamping {
				struct timespec ts[3];
			};
			*/
			scmTimestamping := *(*[3]syscall.Timespec)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
			//fmt.Printf("Kernel: scmTimestamping[0].Sec=%v scmTimestamping[0].Nsec=%v\n", scmTimestamping[0].Sec, scmTimestamping[0].Nsec)
			//fmt.Printf("HW: scmTimestamping[2].Sec=%v scmTimestamping[2].Nsec=%v\n", scmTimestamping[2].Sec, scmTimestamping[2].Nsec)

			//compatibility, emulates: sockctrl.SetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1)
			meta.Recvd = time.Unix(int64(scmTimestamping[0].Sec), int64(scmTimestamping[0].Nsec))

			meta.KernelTS.Sec = scmTimestamping[0].Sec
			meta.KernelTS.Nsec = scmTimestamping[0].Nsec

			meta.HwTS.Sec = scmTimestamping[2].Sec
			meta.HwTS.Nsec = scmTimestamping[2].Nsec

			if scmTimestamping[2].Sec != 0 {
				fmt.Printf("Received a HW-Timestamp :-D: scmTimestamping[2]=%v scmTimestamping[2].Nsec=%v\n", scmTimestamping[2].Sec, scmTimestamping[2].Nsec)
			}
		case hdr.Level == syscall.SOL_SOCKET && hdr.Type == unix.SCM_TIMESTAMPING_PKTINFO:
			/* <linux/net_tstamp.h>

			SOF_TIMESTAMPING_OPT_PKTINFO:

			  Enable the SCM_TIMESTAMPING_PKTINFO control message for incoming
			  packets with hardware timestamps. The message contains struct
			  scm_ts_pktinfo, which supplies the index of the real interface which
			  received the packet and its length at layer 2. A valid (non-zero)
			  interface index will be returned only if CONFIG_NET_RX_BUSY_POLL is
			  enabled and the driver is using NAPI. The struct contains also two
			  other fields, but they are reserved and undefined.
						//SCM_TIMESTAMPING_PKTINFO control message
						struct scm_ts_pktinfo {
							__u32 if_index;
							__u32 pkt_length;
							__u32 reserved[2];
						};

			*/
			tsInfo := *(*[2]uint32)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
			meta.InterfaceId = tsInfo[0]
			meta.PktLengthL2 = tsInfo[1]
			//fmt.Printf("tsInfo[0]=%v tsInfo[1]=%v\n", tsInfo[0], tsInfo[1])
		case hdr.Level == syscall.IPPROTO_IP && hdr.Type == unix.IP_PKTINFO:
			meta.Ipi = *(*syscall.Inet4Pktinfo)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
			//fmt.Printf("ipi.Ifindex=%v ipi.Spec_dst=%v ipi.Addr=%v\n", meta.Ipi.Ifindex, meta.Ipi.Spec_dst, meta.Ipi.Addr)
		default:
			//fmt.Printf("handleCmsg: Unimplemented case:: hdr.Level=%v hdr.Type=%v", hdr.Level, hdr.Type)
		}
		// What we actually want is the padded length of the cmsg, but CmsgLen
		// adds a CmsgHdr length to the result, so we subtract that.
		//oob = oob[syscall.CmsgLen(int(hdr.Len))-sizeofCmsgHdr:] //mefi84 Das ist ziemlich sicher falsch, da Alignment nicht beachtet wird
		oob = oob[common.CmsgAlignOf(int(hdr.Len)):] //mefi84 Das ist ziemlich sicher falsch, da Alignment nicht beachtet wird

	}
}

func (c *connUDPBase) Write(b common.RawBytes) (int, error) {
	return c.conn.Write(b)
}

func (c *connUDPBase) WriteTo(b common.RawBytes, dst *net.UDPAddr) (int, error) {
	if c.Remote != nil {
		return c.conn.Write(b)
	}
	return c.conn.WriteTo(b, dst)
}

func (c *connUDPBase) LocalAddr() *net.UDPAddr {
	return c.Listen
}

func (c *connUDPBase) RemoteAddr() *net.UDPAddr {
	return c.Remote
}

func (c *connUDPBase) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// ReadMeta contains extra information about socket reads.
type ReadMeta struct {
	// Src is the remote address from which the datagram was received
	Src *net.UDPAddr
	// Local is the address on which the datagram was received
	Local *net.UDPAddr
	// RcvOvfl is the total number of packets that were dropped by the OS due
	// to the receive buffers being full.
	RcvOvfl uint32
	// Recvd is the timestamp when the kernel placed the packet in the socket's
	// receive buffer. N.B. this is in system time, it is _not_ monotonic.
	Recvd time.Time
	// ReadDelay is the time elapsed between the kernel adding a packet to the
	// socket's receive buffer, and the application reading it from the Go
	// network stack (i.e., kernel to application latency).
	ReadDelay time.Duration
	// ReadMetaTSExtension contains additional data to support timestamps
	common.ReadMetaTSExtension
}

func (m *ReadMeta) reset() {
	m.Src = nil
	m.RcvOvfl = 0
	m.Recvd = time.Unix(0, 0)
	m.ReadDelay = 0

	m.KernelTS = syscall.Timespec{Sec: 0, Nsec: 0}
	m.HwTS = syscall.Timespec{Sec: 0, Nsec: 0}
	m.InterfaceId = 0
	m.PktLengthL2 = 0
	m.Ipi = syscall.Inet4Pktinfo{
		Ifindex:  0,
		Spec_dst: [4]byte{0},
		Addr:     [4]byte{0},
	}

}

func (m *ReadMeta) setSrc(a *net.UDPAddr, raddr *net.UDPAddr, ot underlay.Type) {
	if a != nil {
		m.Src = a
	} else {
		m.Src = &net.UDPAddr{
			IP:   raddr.IP,
			Port: raddr.Port,
			Zone: raddr.Zone,
		}
	}
}

// NewReadMessages allocates memory for reading IPv4 Linux network stack
// messages.
func NewReadMessages(n int) Messages {
	m := make(Messages, n)
	for i := range m {
		// Allocate a single-element, to avoid allocations when setting the buffer.
		m[i].Buffers = make([][]byte, 1)
		m[i].OOB = make(common.RawBytes, oobSize)
	}
	return m
}

// NewWriteMessages allocates memory for writing IPv4 Linux network stack
// messages.
func NewWriteMessages(n int) Messages {
	m := make(Messages, n)
	for i := range m {
		// Allocate a single-element, to avoid allocations when setting the buffer.
		m[i].Buffers = make([][]byte, 1)
		m[i].Addr = &net.UDPAddr{}
	}
	return m
}
