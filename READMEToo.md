## Go stuff
* siehe hier für rcvmsg go Vorbereitungen der Datenstrukturen... allenfalls kann ich etwas bei mir optimieren /usr/local/go/src/syscall/syscall_linux.go
* https://golang.org/pkg/net/#InterfaceByIndex
* Syscall recvmsg polling teil interessant: https://github.com/jacksontj/traceroute/blob/master/traceroute.go
* noch was zu polling: https://blog.cloudflare.com/io_submit-the-epoll-alternative-youve-never-heard-about/

## Golang Stuff kommt eigentlich später in Debugging logik
* siehe /home/fimeier/go/pkg/mod/github.com/google/gopacket@v1.1.16-0.20190123011826-102d5ca2098c/layers/ports.go
```c
var udpPortLayerType = [65536]gopacket.LayerType{
	53:   LayerTypeDNS,
	123:  LayerTypeNTP,
	4789: LayerTypeVXLAN,
	67:   LayerTypeDHCPv4,
	68:   LayerTypeDHCPv4,
	546:  LayerTypeDHCPv6,
	547:  LayerTypeDHCPv6,
	5060: LayerTypeSIP,
	6343: LayerTypeSFlow,
	6081: LayerTypeGeneve,
	3784: LayerTypeBFD,
	2152: LayerTypeGTPv1U,
}
```

* siehe go/lib/slayers/layertypes.go für Layer Types!!!!
* /usr/local/go/src/net/udpsock.go vgl Metadaten stuff
```c
// ReadMsgUDP reads a message from c, copying the payload into b and
// the associated out-of-band data into oob. It returns the number of
// bytes copied into b, the number of bytes copied into oob, the flags
// that were set on the message and the source address of the message.
//
// The packages golang.org/x/net/ipv4 and golang.org/x/net/ipv6 can be
// used to manipulate IP-level socket options in oob.
func (c *UDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *UDPAddr, err error) {
	if !c.ok() {
		return 0, 0, 0, nil, syscall.EINVAL
	}
	n, oobn, flags, addr, err = c.readMsg(b, oob)
	if err != nil {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return
}
```

## Dispatcher/Golang Observations
* /usr/local/go/src/net/fd_unix.go:26 enthält auch unix fd (select()?)
* scionproto/go/lib/underlay/conn/conn.go es gibt metadaten im read (ts etc.. anpassen)
* /usr/local/go/src/net/ip_posix.go Siehe was die mit c-structs machen... betreffend ip to socket address etc.... (Hinweis,da syscalls allenfalls so "günstiger" sind als wenn ich eine funktion etc in der c-welt aufrufe) OER auch die copy function bytes(from string) => slice
* /usr/local/go/src/syscall/syscall_linux.go siehe z.B. Port to network order (so wie ich das gedacht habe macht man es wirklich :-D)
```c
func (sa *SockaddrInet4) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_INET
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	for i := 0; i < len(sa.Addr); i++ {
		sa.raw.Addr[i] = sa.Addr[i]
	}
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet4, nil
}

//oder auch für die Umkehrung:

case AF_INET:
		pp := (*RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
return sa, nil
```

* /usr/local/go/src/runtime/mfinal.go schaue mal den Finalizer/Garbage Collector an betreffend des "Leaks"

* im /usr/local/go/src/syscall/sockcmsg_unix.go hat es allenfalls auch interessantes zu den cmsg access Macros
```c
// CmsgLen returns the value to store in the Len field of the Cmsghdr
// structure, taking into account any necessary alignment.
func CmsgLen(datalen int) int {
	return cmsgAlignOf(SizeofCmsghdr) + datalen
}

// CmsgSpace returns the number of bytes an ancillary element with
// payload of the passed data length occupies.
func CmsgSpace(datalen int) int {
	return cmsgAlignOf(SizeofCmsghdr) + cmsgAlignOf(datalen)
}

func (h *Cmsghdr) data(offset uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(cmsgAlignOf(SizeofCmsghdr)) + offset)
}

// SocketControlMessage represents a socket control message.
type SocketControlMessage struct {
	Header Cmsghdr
	Data   []byte
}

//und so weiter.... habe das ja alles selebr gemacht
```

## How TO Debug Dispatcher
1. dispatcher must be started first (I guess because of the Control Service (CS) instance)2. start the rest....
3. Iff the dispatcher is restarted, the CS will give up at some point => no communication possible
   1. restart it
   2. or implement autorestart in supervisord


## How TO Build


```bash
git clone https://github.com/scionproto/scion.git
cd scion

./env/deps

rm -rf bin/*
rm -rf gen*

for service in "posix-router" "cs" "dispatcher" "scion-pki" "daemon" "scion";
do
  go build -o ./bin/ ./go/${service}/ && echo "Built ${service}";
done

export PYTHONPATH=python/:.git 
=> neu wohl export PYTHONPATH=.

printf '#!/bin/bash\necho "0.0.0.0"' > tools/docker-ip

python3 python/topology/generator.py -c ./topology/tiny4.topo

rm gen/jaeger-dc.yml

mkdir gen-cache

=> am besten killen, da sonst das ALTE Konfig File neu geladen wird (oder neustarten)
kill -HUD "ps -efa | grep supervisord nimmt den user process...."
supervisor/supervisor.sh reload
supervisor/supervisor.sh start all
supervisor/supervisor.sh stop all
```