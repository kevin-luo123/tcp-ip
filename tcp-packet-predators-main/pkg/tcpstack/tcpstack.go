package tcpstack

import (
	"container/heap"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"tcp/pkg/ipstack"
	"tcp/pkg/orderedmap"
	"tcp/pkg/pqueue"
	"time"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
	"github.com/google/netstack/tcpip/header"
	"golang.org/x/exp/rand"
)

const (
	CLOSED               TCPState = 0
	LISTEN               TCPState = 1
	SYN_SENT             TCPState = 2
	SYN_RECEIVED         TCPState = 3
	ESTABLISHED          TCPState = 4
	FIN_WAIT_1           TCPState = 5
	FIN_WAIT_2           TCPState = 6
	CLOSING              TCPState = 7
	TIME_WAIT            TCPState = 8
	CLOSE_WAIT           TCPState = 9
	LAST_ACK             TCPState = 10
	BUFSIZE                       = 65535
	threshold                     = 4294967296 - BUFSIZE
	TcpHeaderLen                  = header.TCPMinimumSize
	TcpPseudoHeaderLen            = 12
	IpProtoTcp                    = header.TCPProtocolNumber
	MaxVirtualPacketSize          = 1360
	RTOMin                        = 100 * time.Millisecond
	RTOMax                        = 5 * time.Second
	Alpha                         = 0.9
	Beta                          = 2.0
	MaxRetransmits                = 10
)

type (
	TCPState  int
	TCPSocket struct {
		InitSeqNum        uint32
		LocIP             netip.Addr
		LocPort           uint16
		RemIP             netip.Addr
		RemPort           uint16
		State             int32
		AcceptQueue       Accept
		SendBuf           SendBuffer
		RecvBuf           RecvBuffer
		Retransmission    Retransmission
		applicationClosed int32
	}
	Accept struct {
		Queue []*TCPSocket
		Lock  sync.Mutex
		Cond  *sync.Cond
	}
	Retransmission struct {
		Sent            *orderedmap.OrderedMap
		RTOMin          time.Duration
		RTOMax          time.Duration
		RTT             time.Duration
		SRTT            time.Duration
		RTO             time.Duration
		RTTLock         sync.Mutex
		retransmittimer *time.Timer
		RTCount         uint16
	}
	TCPStack struct {
		Socks     map[string]*TCPSocket
		SocksLock sync.Mutex
		NumToKey  map[int]string
		ipStack   *ipstack.IPStack
		NextSock  int
	}
	SendBuffer struct {
		SendingATM bool
		Buf        []byte
		UNA        uint32
		NXT        uint32
		LBW        uint32
		Lock       sync.Mutex
		Cond       *sync.Cond
		SendWnd    uint32
	}
	RecvBuffer struct {
		Buf   []byte
		LBR   uint32
		NXT   uint32
		Lock  sync.Mutex
		Cond  *sync.Cond
		Early *pqueue.PriorityQueue
	}
)

func (socket *TCPSocket) VWrite(data []byte) (int, error) {
	if socket == nil {
		return 0, fmt.Errorf("nil socket")
	}
	if socket.GetState() != ESTABLISHED {
		return 0, fmt.Errorf("no connection established yet")
	}

	socket.SendBuf.Lock.Lock()
	defer socket.SendBuf.Lock.Unlock()

	written := 0

	for written < len(data) {
		avail := BUFSIZE - (socket.SendBuf.LBW - socket.SendBuf.UNA)

		if avail == 0 {
			socket.SendBuf.Cond.Wait()
			continue
		}

		needToWrite := len(data) - written

		if uint32(needToWrite) > avail {
			needToWrite = int(avail)
		}

		s := socket.seqNumToIndex(socket.SendBuf.LBW)
		e := (s + uint32(needToWrite)) % BUFSIZE

		if e > s {
			copy(socket.SendBuf.Buf[s:e], data[written:written+needToWrite])
		} else {
			firstPart := BUFSIZE - s
			copy(socket.SendBuf.Buf[s:], data[written:written+int(firstPart)])
			copy(socket.SendBuf.Buf[0:e], data[written+int(firstPart):written+needToWrite])
		}

		socket.SendBuf.LBW += uint32(needToWrite)
		written += needToWrite
		socket.SendBuf.Cond.Signal()
	}
	return written, nil
}
func (socket *TCPSocket) VRead(stack *TCPStack, message []byte) (int, error) {
	state := socket.GetState()
	if state == LISTEN {
		return 0, fmt.Errorf("can't read from listen socket")
	}
	socket.RecvBuf.Lock.Lock()
	defer socket.RecvBuf.Lock.Unlock()
	var avail uint32
	for {
		avail = socket.RecvBuf.NXT - socket.RecvBuf.LBR
		if avail > 0 {
			break
		} else if state == CLOSED || state == TIME_WAIT || state == CLOSE_WAIT {
			return 0, io.EOF
		}
		socket.RecvBuf.Cond.Wait()
		state = socket.GetState()
	}
	read := min(int(avail), len(message))
	s := socket.seqNumToIndex(socket.RecvBuf.LBR)
	e := (s + uint32(read)) % BUFSIZE
	if e > s {
		copy(message, socket.RecvBuf.Buf[s:e])
	} else {
		firstPart := BUFSIZE - s
		copy(message[:firstPart], socket.RecvBuf.Buf[s:])
		copy(message[firstPart:], socket.RecvBuf.Buf[:e])
	}
	socket.RecvBuf.LBR = socket.RecvBuf.LBR + uint32(read)
	sendTCPPacket(stack, socket, header.TCPFlagAck, nil, socket.SendBuf.NXT, false, false)

	return read, nil
}
func New(ipStack *ipstack.IPStack) *TCPStack {
	return &TCPStack{
		Socks:    make(map[string]*TCPSocket),
		NumToKey: make(map[int]string),
		ipStack:  ipStack,
		NextSock: 0,
	}
}
func (tcpStack *TCPStack) TCPHandler(data []byte, args []interface{}) {
	tcpHeader, err := ParseTCPHeader(data)
	if err != nil {
		fmt.Println("error parsing tcp header:", err)
		return
	}
	ipHeader := args[0].(*ipv4header.IPv4Header)
	key := fmt.Sprintf("%s:%d:%s:%d", ipHeader.Dst, tcpHeader.DstPort, ipHeader.Src, tcpHeader.SrcPort)
	tcpStack.SocksLock.Lock()
	socket, ok := tcpStack.Socks[key]
	tcpStack.SocksLock.Unlock()
	if ok {
		handleExistingConn(tcpStack, socket, tcpHeader, data[20:])
	} else {
		handleNewConn(tcpStack, ipHeader, tcpHeader)
	}
}
func handleNewConn(tcpStack *TCPStack, ipHeader *ipv4header.IPv4Header, tcpHeader *header.TCPFields) {
	tcpStack.SocksLock.Lock()
	listenKey := fmt.Sprintf("%s:%d", ipHeader.Dst, tcpHeader.DstPort)
	listenSocket, exists := tcpStack.Socks[listenKey]
	tcpStack.SocksLock.Unlock()
	if exists && listenSocket.GetState() == LISTEN {
		newSocket := &TCPSocket{
			InitSeqNum: rand.Uint32(),
			LocIP:      ipHeader.Dst,
			LocPort:    tcpHeader.DstPort,
			RemIP:      ipHeader.Src,
			RemPort:    tcpHeader.SrcPort,
			State:      int32(SYN_RECEIVED),
			Retransmission: Retransmission{
				Sent:            orderedmap.NewOrderedMap(),
				SRTT:            time.Second,
				RTO:             2 * time.Second,
				RTCount:         0,
				retransmittimer: time.NewTimer(2 * time.Second),
			},
		}
		newSocket.SendBuf = SendBuffer{
			Buf:     make([]byte, BUFSIZE),
			Cond:    sync.NewCond(&newSocket.SendBuf.Lock),
			SendWnd: BUFSIZE,
			UNA:     newSocket.InitSeqNum,
			NXT:     newSocket.InitSeqNum,
			LBW:     newSocket.InitSeqNum,
		}
		newSocket.RecvBuf = RecvBuffer{
			NXT:   tcpHeader.SeqNum + 1,
			LBR:   tcpHeader.SeqNum + 1,
			Buf:   make([]byte, BUFSIZE),
			Cond:  sync.NewCond(&newSocket.RecvBuf.Lock),
			Early: &pqueue.PriorityQueue{},
		}
		heap.Init(newSocket.RecvBuf.Early)
		connKey := fmt.Sprintf("%s:%d:%s:%d", newSocket.LocIP, newSocket.LocPort, newSocket.RemIP, newSocket.RemPort)
		tcpStack.SocksLock.Lock()
		tcpStack.Socks[connKey] = newSocket
		tcpStack.NumToKey[len(tcpStack.NumToKey)] = connKey
		tcpStack.SocksLock.Unlock()
		sendTCPPacket(tcpStack, newSocket, header.TCPFlagSyn|header.TCPFlagAck, nil, newSocket.SendBuf.NXT, false, false)
		go newSocket.rtoManager(tcpStack)
		newSocket.SendBuf.NXT += 1
		newSocket.SendBuf.LBW += 1
		listenSocket.AcceptQueue.Lock.Lock()
		listenSocket.AcceptQueue.Queue = append(listenSocket.AcceptQueue.Queue, newSocket)
		listenSocket.AcceptQueue.Cond.Signal()
		listenSocket.AcceptQueue.Lock.Unlock()
	}
}
func handleExistingConn(tcpStack *TCPStack, socket *TCPSocket, tcpHeader *header.TCPFields, data []byte) {
	socket.Retransmission.RTTLock.Lock()
	t, ok := socket.Retransmission.Sent.GetTime(tcpHeader.AckNum)
	if ok {
		measured := time.Since(t)
		socket.updateRTT(measured)
		socket.Retransmission.Sent.Delete(tcpHeader.AckNum)
	}
	if socket.Retransmission.Sent.Len() > 0 {
		socket.Retransmission.retransmittimer.Reset(socket.Retransmission.RTO)
	}
	socket.Retransmission.RTCount = 0
	socket.Retransmission.RTTLock.Unlock()
	switch socket.GetState() {
	case SYN_SENT:
		if tcpHeader.Flags&header.TCPFlagSyn != 0 && tcpHeader.Flags&header.TCPFlagAck != 0 {
			socket.RecvBuf.Lock.Lock()
			socket.RecvBuf.NXT = tcpHeader.SeqNum + 1
			socket.RecvBuf.LBR = tcpHeader.SeqNum + 1
			socket.RecvBuf.Lock.Unlock()
			socket.setState(ESTABLISHED)
			socket.SendBuf.Lock.Lock()
			socket.SendBuf.UNA += 1
			if !socket.SendBuf.SendingATM {
				socket.SendBuf.SendingATM = true
				go socket.sendingThread(tcpStack)
			}
			socket.SendBuf.Lock.Unlock()
			sendTCPPacket(tcpStack, socket, header.TCPFlagAck, nil, socket.SendBuf.NXT, false, false)
		}
	case SYN_RECEIVED:
		if tcpHeader.Flags&header.TCPFlagAck != 0 {
			socket.setState(ESTABLISHED)
			if !socket.SendBuf.SendingATM {
				socket.SendBuf.Lock.Lock()
				socket.SendBuf.UNA += 1
				socket.SendBuf.SendingATM = true
				socket.SendBuf.Lock.Unlock()
				go socket.sendingThread(tcpStack)
			}
			fmt.Println("Connection established")
		}
	case ESTABLISHED:
		if tcpHeader.Flags&header.TCPFlagAck != 0 {
			socket.SendBuf.Lock.Lock()
			socket.SendBuf.SendWnd = uint32(tcpHeader.WindowSize)
			if int32(socket.SendBuf.UNA-tcpHeader.AckNum) < 0 && int32(tcpHeader.AckNum-socket.SendBuf.NXT) <= 0 {
				socket.SendBuf.UNA = tcpHeader.AckNum
			}
			socket.SendBuf.Cond.Broadcast()
			socket.SendBuf.Lock.Unlock()
			socket.Retransmission.RTTLock.Lock()
			socket.Retransmission.Sent.DeleteUpTo(tcpHeader.AckNum)
			if socket.Retransmission.Sent.Len() > 0 {
				socket.Retransmission.retransmittimer.Reset(socket.Retransmission.RTO)
			} else {
				socket.Retransmission.retransmittimer.Stop()
			}
			socket.Retransmission.RTCount = 0
			socket.Retransmission.RTTLock.Unlock()
			if len(data) > 0 {
				processIncomingData(tcpStack, socket, tcpHeader, data)
			}
		}
	case FIN_WAIT_1:
		if tcpHeader.Flags&header.TCPFlagAck != 0 {
			socket.setState(FIN_WAIT_2)
		}
	case CLOSING:
		if tcpHeader.Flags&header.TCPFlagAck != 0 {
			socket.setState(TIME_WAIT)
			go socket.timeWait(tcpStack)
		}
	case LAST_ACK:
		if tcpHeader.Flags&header.TCPFlagAck != 0 {
			socket.setState(CLOSED)
			socket.removeFromTable(tcpStack)
		}
	}
	if tcpHeader.Flags&header.TCPFlagFin != 0 {
		socket.RecvBuf.Lock.Lock()
		if tcpHeader.SeqNum == socket.RecvBuf.NXT {
			socket.RecvBuf.NXT = tcpHeader.SeqNum + 1
		}
		socket.RecvBuf.Lock.Unlock()
		socket.RecvBuf.Cond.Signal()
		sendTCPPacket(tcpStack, socket, header.TCPFlagAck, nil, socket.SendBuf.NXT, false, false)
		switch socket.GetState() {
		case ESTABLISHED:
			socket.setState(CLOSE_WAIT)
			time.Sleep(2 * time.Second)
			socket.RecvBuf.Cond.Broadcast()
			socket.SendBuf.Cond.Broadcast()
		case FIN_WAIT_1:
			socket.setState(CLOSING)
		case FIN_WAIT_2:
			socket.setState(TIME_WAIT)
			go socket.timeWait(tcpStack)
		case CLOSING:
			socket.setState(TIME_WAIT)
			go socket.timeWait(tcpStack)
		}
	}
	if tcpHeader.Flags&header.TCPFlagRst != 0 {
		socket.removeFromTable(tcpStack)
	}
}
func processIncomingData(tcpStack *TCPStack, socket *TCPSocket, tcpHeader *header.TCPFields, data []byte) {
	socket.RecvBuf.Lock.Lock()
	defer socket.RecvBuf.Lock.Unlock()
	recvWnd := BUFSIZE - (socket.RecvBuf.NXT - socket.RecvBuf.LBR)
	rcvNxt := socket.RecvBuf.NXT
	segSeq := tcpHeader.SeqNum
	segLen := uint32(len(data))
	segEnd := segSeq + segLen - 1
	accept := false
	if recvWnd == 0 {
		if segLen == 0 && segSeq == rcvNxt {
			accept = true
		}
	} else {
		start := rcvNxt
		end := rcvNxt + recvWnd - 1
		if int32(start-end) <= 0 {
			if segLen == 0 {
				accept = int32(segSeq-start) >= 0 && int32(segSeq-end) <= 0
			} else {
				accept = (int32(segSeq-start) >= 0 && int32(segSeq-end) <= 0) ||
					(int32(segEnd-start) >= 0 && int32(segEnd-end) <= 0)
			}
		} else {
			if segLen == 0 {
				accept = int32(segSeq-start) >= 0 || int32(segSeq-end) <= 0
			} else {
				accept = (int32(segSeq-start) >= 0 || int32(segSeq-end) <= 0) ||
					(int32(segEnd-start) >= 0 || int32(segEnd-end) <= 0)
			}
		}
	}
	if !accept {
		return
	}
	startSeq := segSeq
	endSeq := segSeq + segLen
	if int32(startSeq-socket.RecvBuf.LBR) < 0 {
		diff := socket.RecvBuf.LBR - startSeq
		if diff >= segLen {
			return
		}
		data = data[diff:]
		startSeq = socket.RecvBuf.LBR
	}
	if int32(endSeq-(socket.RecvBuf.LBR+BUFSIZE)) > 0 {
		diff := endSeq - (socket.RecvBuf.LBR + BUFSIZE)
		if diff >= segLen {
			return
		}
		data = data[:len(data)-int(diff)]
		endSeq = socket.RecvBuf.LBR + BUFSIZE
	}
	s := socket.seqNumToIndex(startSeq)
	e := socket.seqNumToIndex(endSeq)
	if e > s {
		copy(socket.RecvBuf.Buf[s:e], data)
	} else {
		firstPart := BUFSIZE - s
		copy(socket.RecvBuf.Buf[s:], data[:firstPart])
		copy(socket.RecvBuf.Buf[:e], data[firstPart:])
	}
	if startSeq == socket.RecvBuf.NXT {
		socket.RecvBuf.NXT = endSeq
		for socket.RecvBuf.Early.Len() > 0 {
			pkt := heap.Pop(socket.RecvBuf.Early).(*pqueue.Packet)
			if pkt.Start == socket.RecvBuf.NXT {
				socket.RecvBuf.NXT = pkt.End
			} else {
				heap.Push(socket.RecvBuf.Early, pkt)
				break
			}
		}
		socket.RecvBuf.Cond.Signal()
	} else {
		heap.Push(socket.RecvBuf.Early, &pqueue.Packet{Start: startSeq, End: endSeq})
	}
	sendTCPPacket(tcpStack, socket, header.TCPFlagAck, nil, socket.SendBuf.NXT, false, false)
}
func sendTCPPacket(tcpStack *TCPStack, socket *TCPSocket, flags uint8, payload []byte, seqNum uint32, RT bool, locked bool) {
	recvWnd := BUFSIZE - (socket.RecvBuf.NXT - socket.RecvBuf.LBR)
	if recvWnd > BUFSIZE {
		recvWnd = 0
	}
	tcpHdr := &header.TCPFields{
		SrcPort:       socket.LocPort,
		DstPort:       socket.RemPort,
		SeqNum:        seqNum,
		AckNum:        socket.RecvBuf.NXT,
		DataOffset:    20,
		Flags:         flags,
		WindowSize:    uint16(recvWnd),
		Checksum:      0,
		UrgentPointer: 0,
	}
	tcpHdr.Checksum = ComputeTCPChecksum(tcpHdr, socket.LocIP, socket.RemIP, payload)
	hBytes := make(header.TCP, tcpHdr.DataOffset)
	hBytes.Encode(tcpHdr)
	if len(payload) > MaxVirtualPacketSize {
		fmt.Println("Packet exceeded MTU")
		return
	}
	packet := append(hBytes, payload...)
	err := tcpStack.ipStack.SendIP(socket.RemIP, 6, packet)
	if err != nil {
		fmt.Println("Error sending TCP packet:", err)
		socket.removeFromTable(tcpStack)
		return
	}
	if RT {
		if !locked {
			socket.Retransmission.RTTLock.Lock()
		}
		var ackNum uint32
		if tcpHdr.Flags&header.TCPFlagFin != 0 {
			ackNum = seqNum + 1
		} else {
			ackNum = seqNum + uint32(len(payload))
		}
		socket.Retransmission.Sent.Set(ackNum, payload, time.Now())
		if socket.Retransmission.Sent.Len() == 1 {
			socket.Retransmission.retransmittimer.Reset(socket.Retransmission.RTO)
		}
		if !locked {
			socket.Retransmission.RTTLock.Unlock()
		}
	}
}

func (socket *TCPSocket) VClose(stack *TCPStack) {
	switch socket.GetState() {
	case CLOSED, TIME_WAIT:
		return
	case LISTEN:
		socket.removeFromTable(stack)
	case SYN_SENT, SYN_RECEIVED:
		sendTCPPacket(stack, socket, header.TCPFlagRst, nil, socket.SendBuf.NXT, false, false)
		socket.removeFromTable(stack)
	case ESTABLISHED:
		socket.setApplicationClosed(true)
		socket.SendBuf.Lock.Lock()
		socket.SendBuf.Cond.Broadcast()
		socket.SendBuf.Lock.Unlock()
	case CLOSE_WAIT:
		sendTCPPacket(stack, socket, header.TCPFlagFin, nil, socket.SendBuf.NXT, true, false)
		socket.setState(LAST_ACK)
	case FIN_WAIT_1, FIN_WAIT_2, CLOSING, LAST_ACK:
		return
	default:
		socket.removeFromTable(stack)
	}
}

func (socket *TCPSocket) removeFromTable(stack *TCPStack) {
	var k string
	stack.SocksLock.Lock()
	if socket.GetState() == LISTEN {
		k = fmt.Sprintf("%s:%d", socket.LocIP, socket.LocPort)
	} else {
		k = fmt.Sprintf("%s:%d:%s:%d", socket.LocIP, socket.LocPort, socket.RemIP, socket.RemPort)
	}
	socket.setState(CLOSED)
	delete(stack.Socks, k)
	for id, key := range stack.NumToKey {
		if key == k {
			delete(stack.NumToKey, id)
			break
		}
	}
	stack.SocksLock.Unlock()
}
func (tcpStack *TCPStack) VConnect(remoteIP netip.Addr, remotePort uint16) error {
	localIP := getLocalIP(tcpStack.ipStack)
	localPort := uint16(rand.Intn(1 << 16))
	if localIP == nil {
		return fmt.Errorf("no local IP available")
	}
	socket := &TCPSocket{
		InitSeqNum: rand.Uint32(),
		LocIP:      *localIP,
		LocPort:    localPort,
		RemIP:      remoteIP,
		RemPort:    remotePort,
		State:      int32(SYN_SENT),
		Retransmission: Retransmission{
			Sent:            orderedmap.NewOrderedMap(),
			SRTT:            time.Second,
			RTO:             2 * time.Second,
			RTCount:         0,
			retransmittimer: time.NewTimer(2 * time.Second),
		},
	}
	socket.SendBuf = SendBuffer{
		Buf:     make([]byte, BUFSIZE),
		Cond:    sync.NewCond(&socket.SendBuf.Lock),
		SendWnd: BUFSIZE,
		UNA:     socket.InitSeqNum,
		NXT:     socket.InitSeqNum,
		LBW:     socket.InitSeqNum,
	}
	socket.RecvBuf = RecvBuffer{
		NXT:   0,
		LBR:   0,
		Buf:   make([]byte, BUFSIZE),
		Cond:  sync.NewCond(&socket.RecvBuf.Lock),
		Early: &pqueue.PriorityQueue{},
	}
	heap.Init(socket.RecvBuf.Early)
	connKey := fmt.Sprintf("%s:%d:%s:%d", socket.LocIP, socket.LocPort, socket.RemIP, socket.RemPort)
	tcpStack.SocksLock.Lock()
	ID := tcpStack.NextSock
	tcpStack.Socks[connKey] = socket
	tcpStack.NumToKey[ID] = connKey
	tcpStack.NextSock += 1
	tcpStack.SocksLock.Unlock()
	sendTCPPacket(tcpStack, socket, header.TCPFlagSyn, nil, socket.SendBuf.NXT, false, false)
	go socket.rtoManager(tcpStack)
	socket.SendBuf.NXT += 1
	socket.SendBuf.LBW += 1
	fmt.Printf("Connecting to %s:%d from port %d\n", remoteIP.String(), remotePort, localPort)
	return nil
}

func (socket *TCPSocket) sendingThread(stack *TCPStack) {
	var probeTimer *time.Timer
	socket.SendBuf.Lock.Lock()
	for {
		state := socket.GetState()
		if state == CLOSED {
			socket.SendBuf.Lock.Unlock()
			return
		}

		needToSend := socket.SendBuf.LBW - socket.SendBuf.NXT
		if needToSend <= 0 {
			if socket.isApplicationClosed() && (state == ESTABLISHED || state == SYN_RECEIVED) {
				sendTCPPacket(stack, socket, header.TCPFlagFin, nil, socket.SendBuf.NXT, true, false)
				socket.setState(FIN_WAIT_1)
				socket.SendBuf.Lock.Unlock()
				return
			}
			socket.SendBuf.Cond.Wait()
			continue
		}
		dataCanSend := socket.SendBuf.SendWnd - (socket.SendBuf.NXT - socket.SendBuf.UNA)
		if dataCanSend <= 0 {
			if probeTimer == nil {
				probeTimer = time.NewTimer(socket.Retransmission.RTO)
			}
			socket.SendBuf.Lock.Unlock()
			<-probeTimer.C
			socket.SendBuf.Lock.Lock()
			if socket.SendBuf.SendWnd > 0 {
				probeTimer.Stop()
				probeTimer = nil
				continue
			}
			seqNum := socket.SendBuf.UNA
			socket.SendBuf.Lock.Unlock()
			sendTCPPacket(stack, socket, header.TCPFlagAck, []byte{0}, seqNum, false, false)
			socket.SendBuf.Lock.Lock()
			probeTimer.Reset(socket.Retransmission.RTO)
			continue
		} else {
			if probeTimer != nil {
				probeTimer.Stop()
				probeTimer = nil
			}
		}
		toSend := min(needToSend, dataCanSend, uint32(MaxVirtualPacketSize))
		s := socket.seqNumToIndex(socket.SendBuf.NXT)
		e := (s + toSend) % BUFSIZE
		var data []byte
		if e > s {
			data = socket.SendBuf.Buf[s:e]
		} else {
			data = append(socket.SendBuf.Buf[s:], socket.SendBuf.Buf[:e]...)
		}
		seqNum := socket.SendBuf.NXT
		socket.SendBuf.NXT = (socket.SendBuf.NXT + toSend)
		socket.SendBuf.Lock.Unlock()
		time.Sleep(10 * time.Millisecond)
		sendTCPPacket(stack, socket, header.TCPFlagAck, data, seqNum, true, false)
		socket.SendBuf.Lock.Lock()
	}
}

func (socket *TCPSocket) retransmit(stack *TCPStack) {
	socket.Retransmission.RTTLock.Lock()
	defer socket.Retransmission.RTTLock.Unlock()
	seq, data, err := socket.Retransmission.Sent.Pop()
	if err != nil {
		fmt.Println(err)
		return
	}

	socket.SendBuf.Lock.Lock()
	if int32(seq-socket.SendBuf.UNA) < 0 {
		socket.SendBuf.Lock.Unlock()
		return
	}
	socket.SendBuf.Lock.Unlock()
	sendTCPPacket(stack, socket, header.TCPFlagAck, data, seq, true, true)
	socket.Retransmission.RTO *= 2
	if socket.Retransmission.RTO > RTOMax {
		socket.Retransmission.RTO = RTOMax
	}
	socket.Retransmission.RTCount += 1
}

func (socket *TCPSocket) rtoManager(stack *TCPStack) {
	for {
		if socket.GetState() == CLOSED {
			return
		}
		<-socket.Retransmission.retransmittimer.C
		if socket.Retransmission.Sent.Len() > 0 {
			socket.retransmit(stack)
			socket.Retransmission.retransmittimer.Reset(socket.Retransmission.RTO)
		}
		if socket.Retransmission.RTCount >= MaxRetransmits {
			socket.VClose(stack)
			return
		}
	}
}

func ComputeTCPChecksum(tcpHdr *header.TCPFields, sourceIP netip.Addr, destIP netip.Addr, payload []byte) uint16 {
	// Fill in the pseudo header
	pseudoHeaderBytes := make([]byte, TcpPseudoHeaderLen)

	// First are the source and dest IPs.  This function only supports
	// IPv4, so make sure the IPs are IPv4 addresses
	copy(pseudoHeaderBytes[0:4], sourceIP.AsSlice())
	copy(pseudoHeaderBytes[4:8], destIP.AsSlice())

	// Next, add the protocol number and header length
	pseudoHeaderBytes[8] = uint8(0)
	pseudoHeaderBytes[9] = uint8(IpProtoTcp)

	totalLength := TcpHeaderLen + len(payload)
	binary.BigEndian.PutUint16(pseudoHeaderBytes[10:12], uint16(totalLength))

	// Turn the TcpFields struct into a byte array
	headerBytes := header.TCP(make([]byte, TcpHeaderLen))
	headerBytes.Encode(tcpHdr)

	// Compute the checksum for each individual part and combine To combine the
	// checksums, we leverage the "initial value" argument of the netstack's
	// checksum package to carry over the value from the previous part
	pseudoHeaderChecksum := header.Checksum(pseudoHeaderBytes, 0)
	headerChecksum := header.Checksum(headerBytes, pseudoHeaderChecksum)
	fullChecksum := header.Checksum(payload, headerChecksum)

	// Return the inverse of the computed value,
	// which seems to be the convention of the checksum algorithm
	// in the netstack package's implementation
	return fullChecksum ^ 0xffff
}
func ParseTCPHeader(b []byte) (*header.TCPFields, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("header too short")
	}
	td := header.TCP(b)
	tcpFields := header.TCPFields{
		SrcPort:    td.SourcePort(),
		DstPort:    td.DestinationPort(),
		SeqNum:     td.SequenceNumber(),
		AckNum:     td.AckNumber(),
		DataOffset: td.DataOffset(),
		Flags:      td.Flags(),
		WindowSize: td.WindowSize(),
		Checksum:   td.Checksum(),
	}
	return &tcpFields, nil
}

func getLocalIP(ipStack *ipstack.IPStack) *netip.Addr {
	for _, iface := range ipStack.Interfaces {
		return &iface.VirtualIP
	}
	return nil
}

func (tcpStack *TCPStack) Listen(localPort uint16) error {
	localIP := getLocalIP(tcpStack.ipStack)
	if localIP == nil {
		return fmt.Errorf("no local IP available")
	}
	listenKey := fmt.Sprintf("%s:%d", localIP, localPort)
	tcpStack.SocksLock.Lock()
	defer tcpStack.SocksLock.Unlock()
	if _, exists := tcpStack.Socks[listenKey]; exists {
		return fmt.Errorf("already listening on port %d", localPort)
	}
	listenSock := &TCPSocket{
		LocIP:   *localIP,
		LocPort: localPort,
		State:   int32(LISTEN),
		AcceptQueue: Accept{
			Queue: make([]*TCPSocket, 0),
		},
	}
	listenSock.AcceptQueue.Cond = sync.NewCond(&listenSock.AcceptQueue.Lock)
	tcpStack.Socks[listenKey] = listenSock
	ID := tcpStack.NextSock
	tcpStack.NumToKey[ID] = listenKey
	tcpStack.NextSock += 1
	fmt.Printf("Listening on port %d\n", localPort)
	return nil
}

func (listenSocket *TCPSocket) VAccept() (*TCPSocket, error) {
	if listenSocket.GetState() != LISTEN {
		return nil, fmt.Errorf("socket not in LISTEN state")
	}
	listenSocket.AcceptQueue.Lock.Lock()
	defer listenSocket.AcceptQueue.Lock.Unlock()
	for len(listenSocket.AcceptQueue.Queue) == 0 {
		listenSocket.AcceptQueue.Cond.Wait()
	}
	newSocket := listenSocket.AcceptQueue.Queue[0]
	listenSocket.AcceptQueue.Queue = listenSocket.AcceptQueue.Queue[1:]
	return newSocket, nil
}

func (socket *TCPSocket) updateRTT(measured time.Duration) {
	socket.Retransmission.SRTT = time.Duration(Alpha*float64(socket.Retransmission.SRTT) + (1-Alpha)*float64(measured))
	socket.Retransmission.RTO = time.Duration(max(float64(RTOMin), min(Beta*float64(socket.Retransmission.SRTT), float64(RTOMax))))
	if socket.Retransmission.RTO < RTOMin {
		socket.Retransmission.RTO = RTOMin
	} else if socket.Retransmission.RTO > RTOMax {
		socket.Retransmission.RTO = RTOMax
	}
}

func (socket *TCPSocket) GetState() TCPState {
	return TCPState(atomic.LoadInt32(&socket.State))
}

func (socket *TCPSocket) setState(state TCPState) {
	atomic.StoreInt32(&socket.State, int32(state))
}

func (socket *TCPSocket) timeWait(stack *TCPStack) {
	time.Sleep(2 * time.Second)
	socket.setState(CLOSED)
	socket.removeFromTable(stack)
}

func (socket *TCPSocket) setApplicationClosed(closed bool) {
	var val int32 = 0
	if closed {
		val = 1
	}
	atomic.StoreInt32(&socket.applicationClosed, val)
}

func (socket *TCPSocket) isApplicationClosed() bool {
	return atomic.LoadInt32(&socket.applicationClosed) == 1
}

func (socket *TCPSocket) seqNumToIndex(seqNum uint32) uint32 {
	diff := seqNum - socket.InitSeqNum
	return diff % BUFSIZE
}
