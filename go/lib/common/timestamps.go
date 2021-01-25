// Copyright 2021 ETH Zurich
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

package common

import (
	"net"
	"syscall"
	"time"
	"unsafe"
)

// BufferSize is used to for buffers in rcvmsg-calls to return TS data
const BufferSize = 2 << 15
const MsgControlLenMax = 2 << 8 //TDB exactly, if relevant

const SizeOfInet4Pktinfo = syscall.SizeofInet4Pktinfo
const SizeOfScmTsPkginfo = 4 * 4 // Defined to be 4*uint32
const SizeOfScmTimestamping = int(unsafe.Sizeof([3]syscall.Timespec{}))

type TimestampOptions struct {
	EnableTimestampRX   bool //Could also be called EnableTimestamp, as we cannot have TX without RX. Is enforced and communicated to the user.
	EnableTimestampTX   bool
	HwTimestampDevice   string
	EnableTimestampUdp6 bool
	FdUDPv4             int
	FdUDPv6             int
	ErrQueueChanCap     int
	Udpv4Conn           *net.UDPConn
}

// ClientIdentifierTime contains infos about the data's origin (i.e. applicationsocket) and a timestamp
type ClientIdentifierTime struct {
	ClientIdentifier ClientIdentifier
	TimeAdded        time.Time //last time something added
	Count            uint      //there can be multiple messages with the same content
}
type ClientIdentifier net.PacketConn

type HashData [32]byte

// TsRequest is used to map messages read from the socket's error channel to client connections.
type TsRequest struct {
	HashPkt    HashData
	ClientConn ClientIdentifier
	TimeAdded  time.Time //used to delete old/wrong entries in map.ErrMsgs
}

//TODO change this after debugging
const TimeoutTxErrMsg = time.Second * 60

// TsRequestSet is used to map messages read from the socket's error channel to client connections.
//
// HashData is a hash of the outgoing packet (all SCION-Layers).
type TsRequestSet map[HashData]ClientIdentifierTime

const ErrQueueLen = 10000

type ErrQueueMsgs []SomeInfosTBD

func Enqueue(q ErrQueueMsgs, e SomeInfosTBD) ErrQueueMsgs { //why ism't this working
	if len(q) < ErrQueueLen {
		q = q[:len(q)+ErrQueueLen]
	}
	return append(q, e)
}

func (q ErrQueueMsgs) Dequeue() (e SomeInfosTBD) {
	e = q[0]
	q = q[1:]
	return e
}

type SomeInfosTBD struct {
	Used       bool
	HashPkt    HashData
	TimeAdded  time.Time
	DataBuffer RawBytes
	Addr       *net.UDPAddr
	//store timestamps etc...
	KernelTS syscall.Timespec
	// HwTS contains a hardware timestamp
	HwTS syscall.Timespec
	// InterfaceId is equal to struct scm_ts_pktinfo.if_index (if in use)
	InterfaceId uint32
	// PktLengthL2 is equal to struct scm_ts_pktinfo.pkt_length (if in use)
	PktLengthL2 uint32
	// Ipi is equal to Inet4Pktinfo struct
	Ipi syscall.Inet4Pktinfo
}

// PacketTSExtensionClient contains additional data to support timestamps
type PacketTSExtensionClient struct {
	// KernelTS contains a kernel timestamp
	KernelTS syscall.Timespec
	// HwTS contains a hardware timestamp
	HwTS syscall.Timespec
	// InterfaceID is equal to struct scm_ts_pktinfo.if_index (if in use)
	//
	// Rx timestamps will fill this in
	InterfaceID uint32
	// PktLengthL2 is equal to struct scm_ts_pktinfo.pkt_length (if in use)
	//
	// Rx timestamps will fill this in
	PktLengthL2 uint32
	// Ipi is equal to Inet4Pktinfo struct
	//
	// Hint: Using Ipi.Ifindex as this used by Rx AND Tx timestamps
	Ipi syscall.Inet4Pktinfo
}

// PacketTSExtension contains additional data to support timestamps
type PacketTSExtension struct {
	// KernelTS contains a kernel timestamp
	KernelTS syscall.Timespec
	// HwTS contains a hardware timestamp
	HwTS syscall.Timespec
	// InterfaceID is equal to struct scm_ts_pktinfo.if_index (if in use)
	//
	// Rx timestamps will fill this in
	InterfaceID uint32
	// PktLengthL2 is equal to struct scm_ts_pktinfo.pkt_length (if in use)
	//
	// Rx timestamps will fill this in
	PktLengthL2 uint32
	// Ipi is equal to Inet4Pktinfo struct
	//
	// Hint: Using Ipi.Ifindex as this used by Rx AND Tx timestamps
	Ipi syscall.Inet4Pktinfo
	// TsMode contains informations about activated socket options for timestamps (sciontime)
	TsMode            int //can be useful to know while sending out on underlay-connection
	UseIpv4underlayFd int
	UseIpv6underlayFd int
	HashTsPkt         HashData

	Udpv4Conn *net.UDPConn
}

// DispatcherTSExtension contains additional data to support timestamps
type DispatcherTSExtension struct {
	// TimestampRX specifies whether the dispatcher should enable rx-Timestamps
	// and provide them to applications who asked for them.
	TimestampRX bool `toml:"timestamp_rx,omitempty"`
	// TimestampTX specifies whether the dispatcher should enable tx-Timestamps
	// and provide them to applications who asked for them.
	TimestampTX bool `toml:"timestamp_tx,omitempty"`
	// HwTimestamp enables hardware timestamping from the specified network interface.
	HwTimestamp string `toml:"hwtimestamp,omitempty"`
	// HwTimestamp enables hardware timestamping from the specified network interface.
	EnableTimestampUdp6 bool `toml:"timestamp_udp6,default:false"`
	// ErrQueueChanCap is the cap of the channel used to match identifiers of outgoing msgs
	// and their tx-timestamp received from the kernel/hw as ERR_MSG
	ErrQueueChanCap int `toml:"err_queue_chan_cap,default:1000"`
}

// ServerTSExtension contains additional data to support timestamps
type ServerTSExtension struct {
	EnableTimestampRX   bool
	EnableTimestampTX   bool
	EnableTimestampUdp6 bool //disabled in dispatcher/main.go
	Ipv4UnderlayFd      int
	Ipv6UnderlayFd      int
	Ipv4ErrQueueChan    chan TsRequest
	Ipv6ErrQueueChan    chan TsRequest

	Udpv4Conn *net.UDPConn
}

// NetToRingDataplaneTSExtension contains additional data to support timestamps
type NetToRingDataplaneTSExtension struct {
	EnableTsRx    bool
	EnableTsTx    bool
	UnderlayFd    int
	TsRequestChan chan TsRequest
	NetworkType   string //probably not needed

	UDPConn *net.UDPConn
}

// AppConnHandler contains additional data to support timestamps
type AppConnHandlerTSExtension struct {
	// TsMode contains informations about activated socket options for timestamps (sciontime)
	//
	// Remark: The value is stored at different levels (Conn, DispConn,...).
	// Once it is clear where it is needed, it can be placed at the appropriate place, given that it
	// is also accessible by the given interface (not always the case)
	TsMode           int
	Ipv4UnderlayFd   int
	Ipv4ErrQueueChan chan TsRequest
	Ipv6UnderlayFd   int
	Ipv6ErrQueueChan chan TsRequest

	Udpv4Conn *net.UDPConn
}

// ReadMetaTSExtension contains additional data to support timestamps
type ReadMetaTSExtension struct {
	// KernelTS contains a hardware timestamp
	//
	// Contains garbage if not enabled by application
	KernelTS syscall.Timespec
	// HwTS contains a hardware timestamp
	//
	// Contains garbage if not enabled by application
	HwTS syscall.Timespec
	// InterfaceId is equal to struct scm_ts_pktinfo.if_index (if in use)
	InterfaceId uint32
	// PktLengthL2 is equal to struct scm_ts_pktinfo.pkt_length (if in use)
	PktLengthL2 uint32
	// Ipi is equal to Inet4Pktinfo struct
	Ipi syscall.Inet4Pktinfo
}

/* Low-Level System Stuff */

// cmsgAlignOf compare golangs implementation
//
// Hint: "Only" ubuntu x64, but I guess this are the limitations anyway
func CmsgAlignOf(salen int) int {
	salign := 0x8 //sizeofPtr
	return (salen + salign - 1) & ^(salign - 1)
}

type SockExtendedErr struct {
	Errno  uint32
	Origin uint8
	Type   uint8
	Code   uint8
	Pad    uint8
	Info   uint32
	Data   uint32
}

//blocks forever....
/*ready, err := syscall.Select(nfds, nil, nil, &exceptFds, nil)
if err != nil {
	fmt.Printf("%v\n", err)
}
fmt.Printf("ready=%v this should alwas be 1.... otherwise there was an error", ready)
*/

//Select Stuff der nicht gebraucht wird
/*

var exceptFds syscall.FdSet
ce := (*fdsetType)(unsafe.Pointer(&exceptFds))
fdPtr := uintptr(fd)
ce.Set(fdPtr)
nfds := fd + 1 //highest fd + 1



type fdsetType syscall.FdSet


// copyright https://golang.hotexamples.com/de/site/file?hash=0x5e82324c621245310a74ced33fa9cd3627abb2d8c84e55d16acb46c1de2ba57f&fullName=linuxdvb/filter.go&project=ziutek/dvb
func (s *fdsetType) Set(fd uintptr) {
	bits := 8 * unsafe.Sizeof(s.Bits[0])
	if fd >= bits*uintptr(len(s.Bits)) {
		panic("fdset: fd out of range")
	}
	n := fd / bits
	m := fd % bits
	s.Bits[n] |= 1 << m
}
*/

/*
func (s *fdsetType) Clr(fd uintptr) {
	bits := 8 * unsafe.Sizeof(s.Bits[0])
	if fd >= bits*uintptr(len(s.Bits)) {
		panic("fdset: fd out of range")
	}
	n := fd / bits
	m := fd % bits
	s.Bits[n] &^= 1 << m
}
func (s *fdsetType) IsSet(fd uintptr) bool {
	bits := 8 * unsafe.Sizeof(s.Bits[0])
	if fd >= bits*uintptr(len(s.Bits)) {
		panic("fdset: fd out of range")
	}
	n := fd / bits
	m := fd % bits
	return s.Bits[n]&(1<<m) != 0
}
*/
