// Copyright 2018 ETH Zurich
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

package network

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/scionproto/scion/go/dispatcher/dispatcher"
	"github.com/scionproto/scion/go/dispatcher/internal/metrics"
	"github.com/scionproto/scion/go/dispatcher/internal/respool"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// AppSocketServer accepts new connections coming from SCION apps, and
// hands them off to the registration + dataplane handler.
type AppSocketServer struct {
	Listener   *reliable.Listener
	DispServer *dispatcher.Server
}

func (s *AppSocketServer) Serve() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return err
		}
		pconn := conn.(net.PacketConn)
		s.Handle(pconn)
	}
}

// Handle passes conn off to a per-connection state handler.
func (h *AppSocketServer) Handle(conn net.PacketConn) {
	ch := &AppConnHandler{
		Conn:   conn,
		Logger: log.New("clientID", fmt.Sprintf("%p", conn)),
	}
	go func() {
		defer log.HandlePanic()
		ch.Handle(h.DispServer)
	}()
}

// AppConnHandler handles a single SCION application connection.
type AppConnHandler struct {
	// Conn is the local socket to which the application is connected.
	Conn     net.PacketConn
	DispConn *dispatcher.Conn
	Logger   log.Logger
	// AppConnHandler contains additional data to support timestamps
	common.AppConnHandlerTSExtension
}

//TODO: Hier muss ich vermutlich unterscheiden auf welchen wegen der Client rausssendne willl
//v4 vs vs4.... was dann aber erst beim weiterleiten klar ist...
func (h *AppConnHandler) Handle(appServer *dispatcher.Server) {
	h.Logger.Debug("Accepted new client")
	defer h.Logger.Debug("Closed client socket")
	defer h.Conn.Close()

	dispConn, err := h.doRegExchange(appServer)
	if err != nil {
		metrics.M.AppConnErrors().Inc()
		h.Logger.Info("Registration error", "err", err)
		return
	}
	h.DispConn = dispConn.(*dispatcher.Conn)
	defer h.DispConn.Close()
	svc := h.DispConn.SVCAddr().String()
	metrics.M.OpenSockets(metrics.SVC{Type: svc}).Inc()
	defer metrics.M.OpenSockets(metrics.SVC{Type: svc}).Dec()

	//packet.go::SendOnConn() will use this to add TS's to the incoming data buffer
	//before the packets get forwarded to the application's ingress socket
	//this "enables" Rx-Timestamps
	h.Conn.(*reliable.Conn).TsMode = h.TsMode

	if appServer.EnableTimestampTX {
		//here we are only interesstend in Tx-Timestamps, as we use those infos to decide how we should
		//send data from the application's socket to the (real) network
		if h.TsMode == int(addr.TxKernelRxKernel) || h.TsMode == int(addr.TxKernelHwRxKernelHw) {
			//AppConnHandler
			h.Ipv4UnderlayFd = appServer.Ipv4UnderlayFd
			h.Ipv6UnderlayFd = appServer.Ipv6UnderlayFd
			h.Ipv4ErrQueueChan = appServer.Ipv4ErrQueueChan
			h.Ipv6ErrQueueChan = appServer.Ipv6ErrQueueChan

			h.Udpv4Conn = appServer.Udpv4Conn
		}
	}

	go func() {
		defer log.HandlePanic()
		h.RunRingToAppDataplane()
	}()
	h.RunAppToNetDataplane()
}

// doRegExchange manages an application's registration request, and returns a
// reference to registered data that should be freed at the end of the
// registration, information about allocated ring buffers and whether an error occurred.
func (h *AppConnHandler) doRegExchange(appServer *dispatcher.Server) (net.PacketConn, error) {

	b := respool.GetBuffer()
	defer respool.PutBuffer(b)

	regInfo, err := h.recvRegistration(b)
	if err != nil {
		return nil, serrors.New("registration message error", "err", err)
	}

	//HINT: Code-Snippted here and below could also go into appServer.Register()<-the call below, the next one
	/* Get the TsMode out of the regInfo.SVCAddress field
	This is an ugly, but very usful hack to introduce timestamping socket options to the scion api, without
	changing a lot.
	Limitation: Activation of TsMode is only possible, if for the service "addr.SvcNone"

	could become a switch... depends on how the infos are use (activation of the options)
	*/
	if (regInfo.SVCAddress == addr.RxKernel) ||
		regInfo.SVCAddress == addr.RxKernelHw ||
		regInfo.SVCAddress == addr.TxKernelRxKernel ||
		regInfo.SVCAddress == addr.TxKernelHwRxKernelHw {

		//TODO Iff the client asks for something that is not supported decide what to do
		//At the moment we just ignore it
		//I guess we should let the client "crash", otherwise (a client like chrony) also needs to test the supported settings (could be done, but overkill)
		//Ignoring Hw Timestamps is "ok" <= Explanation: Nothing will crash, but chrony will wait a few ms.
		/*
			What a typicall application will do, as it is expected that HW-Tx(!) timestamps can have a delay of up to 200ms:
			Hint: File Input will be "ignored", just waiting for the missed HW-Tx-Ts coming in on ERR_Queue/File Exception

			2021-01-27T12:30:58Z sched.c:653:(fill_fd_sets) mefi::add fd=13 for SCH_FILE_INPUT
			2021-01-27T12:30:58Z sched.c:671:(fill_fd_sets) mefi::add fd=13 for SCH_FILE_EXCEPTION

			2021-01-27T12:30:58Z ntp_io.c:412:(read_from_socket) mefi:: fd=13 and event=file input
			2021-01-27T12:30:58Z ntp_io_linux.c:512:(suspend_socket) Suspended RX processing fd=13

			2021-01-27T12:30:58Z sched.c:671:(fill_fd_sets) mefi::add fd=13 for SCH_FILE_EXCEPTION

			2021-01-27T12:30:58Z ntp_io_linux.c:482:(resume_socket) Resumed RX processing on timeout fd=13

			=> conclusion: not returning expected timestamps will degrade the performance of an application!
		*/

		//no limitations
		if appServer.EnableTimestampRX && appServer.EnableTimestampTX {
			regInfo.TsMode = int(regInfo.SVCAddress)
			h.TsMode = int(regInfo.SVCAddress)
		} else
		//no TX Timestamps
		if appServer.EnableTimestampRX && !appServer.EnableTimestampTX {
			switch regInfo.SVCAddress {
			case addr.TxKernelRxKernel:
				regInfo.TsMode = int(addr.RxKernel)
				h.TsMode = int(addr.RxKernel)
				//we can remove the return => do not let the client "crash"
				return nil, serrors.New("Unsupported mode addr.TxKernelRxKernel")
			case addr.TxKernelHwRxKernelHw:
				regInfo.TsMode = int(addr.RxKernelHw)
				h.TsMode = int(addr.RxKernelHw)
				//we can remove the return => do not let the client "crash"
				return nil, serrors.New("Unsupported mode addr.TxKernelHwRxKernelHw")
			}
		}

		//remove HwTimestamp flags
		if appServer.HwTimestampDevice == "" {
			tsMode := regInfo.TsMode

			fmt.Printf("removing Hw flags. Old=%v ", addr.HostSVC(tsMode))

			switch tsMode {
			case int(addr.RxKernelHw):
				tsMode = int(addr.RxKernel)
				//we can remove the return => do not let the client "crash"
				return nil, serrors.New("Unsupported mode addr.RxKernelHw")
			case int(addr.TxKernelHwRxKernelHw):
				tsMode = int(addr.TxKernelRxKernel)
				//we can remove the return => do not let the client "crash"
				return nil, serrors.New("Unsupported mode addr.TxKernelHwRxKernelHw")
			}
			regInfo.TsMode = tsMode
			h.TsMode = tsMode

			fmt.Printf("New=%v ", addr.HostSVC(tsMode))
		}

		//Set SCVAddress Back to it's default
		//Hint: A client can only enable timestamps, if its service is equal to addr.SvcNone
		//Compare the clients interface. As we do not change it, the clients only way to tell the dispatcher
		//what kind of TS's should be activated, is by misiusing the SVCAddress
		regInfo.SVCAddress = addr.SvcNone
	}

	appConn, _, err := appServer.Register(nil,
		regInfo.IA, regInfo.PublicAddress, regInfo.SVCAddress)
	if err != nil {
		return nil, serrors.New("registration table error", "err", err)
	}

	udpAddr := appConn.(*dispatcher.Conn).LocalAddr().(*net.UDPAddr)
	port := uint16(udpAddr.Port)
	if err := h.sendConfirmation(b, &reliable.Confirmation{Port: port}); err != nil {
		appConn.Close()
		return nil, serrors.New("confirmation message error", "err", err)
	}
	h.logRegistration(regInfo.IA, udpAddr, getBindIP(regInfo.BindAddress),
		regInfo.SVCAddress)
	return appConn, nil
}

func (h *AppConnHandler) logRegistration(ia addr.IA, public *net.UDPAddr, bind net.IP,
	svc addr.HostSVC) {

	items := []interface{}{"ia", ia, "public", public}
	if bind != nil {
		items = append(items, "extra_bind", bind)
	}
	if svc != addr.SvcNone {
		items = append(items, "svc", svc)
	}
	h.Logger.Debug("Client registered address", items...)
}

func (h *AppConnHandler) recvRegistration(b common.RawBytes) (*reliable.Registration, error) {
	n, _, err := h.Conn.ReadFrom(b)
	if err != nil {
		return nil, err
	}
	b = b[:n]

	var rm reliable.Registration
	if err := rm.DecodeFromBytes(b); err != nil {
		return nil, err
	}
	return &rm, nil
}

func (h *AppConnHandler) sendConfirmation(b common.RawBytes, c *reliable.Confirmation) error {
	n, err := c.SerializeTo(b)
	if err != nil {
		return err
	}
	b = b[:n]

	if _, err := h.Conn.WriteTo(b, nil); err != nil {
		return err
	}
	return nil
}

// RunAppToNetDataplane moves packets from the application's socket to the
// underlay socket.
func (h *AppConnHandler) RunAppToNetDataplane() {

	for {
		pkt := respool.GetPacket()
		// XXX(scrye): we don't release the reference on error conditions, and
		// let the GC take care of this situation as they should be fairly
		// rare.

		if err := pkt.DecodeFromReliableConn(h.Conn); err != nil {
			if err == io.EOF {
				h.Logger.Debug("[app->network] EOF received from client")
			} else {
				h.Logger.Debug("[app->network] Client connection error", "err", err)
				metrics.M.AppReadErrors().Inc()
			}
			return
		}
		metrics.M.AppReadBytes().Add(float64(pkt.Len()))
		metrics.M.AppReadPkts().Inc()

		var sendErrMsg bool
		numErrMsg := 1
		//this condition implies, that we will be using a ipv4 connection
		if pkt.UnderlayRemote != nil && pkt.UnderlayRemote.IP.To4() != nil &&
			//we check for enabled Tx timestamp modes
			(h.TsMode == int(addr.TxKernelRxKernel) || h.TsMode == int(addr.TxKernelHwRxKernelHw)) &&
			(h.Ipv4UnderlayFd != 0) { //should always be okay, as we do not allow h.TsMode to be something unsupported
			pkt.UseIpv4underlayFd = h.Ipv4UnderlayFd //this implies we use an unconnected upd4 socket to send the data out
			pkt.TsMode = h.TsMode                    //vermutlich nicht mehr nötig
			sendErrMsg = true

			if h.TsMode == int(addr.TxKernelHwRxKernelHw) {
				numErrMsg = 2
			}

			pkt.Udpv4Conn = h.Udpv4Conn //test
		}

		n, err := h.DispConn.Write(pkt)
		if err != nil {
			metrics.M.NetWriteErrors().Inc()
			h.Logger.Error("[app->network] Underlay socket error", "err", err)
		} else {
			metrics.M.NetWriteBytes().Add(float64(n))
			metrics.M.NetWritePkts().Inc()
		}

		if sendErrMsg && err == nil {
			for i := 0; i < numErrMsg; i++ {
				h.Ipv4ErrQueueChan <- common.TsRequest{
					HashPkt:    pkt.HashTsPkt,
					ClientConn: h.Conn,
					TimeAdded:  time.Now(),
				}
			}
		}

		pkt.Free()
	}
}

// RunRingToAppDataplane moves packets from the application's ingress ring to
// the application's socket.
func (h *AppConnHandler) RunRingToAppDataplane() {
	for {
		pkt := h.DispConn.Read()
		if pkt == nil {
			// Ring was closed because app shut down its data socket
			return
		}
		n, err := pkt.SendOnConn(h.Conn, pkt.UnderlayRemote)
		if err != nil {
			metrics.M.AppWriteErrors().Inc()
			h.Logger.Error("[network->app] App connection error.", "err", err)
			h.Conn.Close()
			return
		}
		metrics.M.AppWritePkts().Inc()
		metrics.M.AppWriteBytes().Add(float64(n))
		pkt.Free()
	}
}

func getBindIP(address *net.UDPAddr) net.IP {
	if address == nil {
		return nil
	}
	return address.IP
}
