// IP stack implementation
// Initializes interfaces, handles packet forwarding, and manages protocol handlers.
package ipstack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"tcp/pkg/lnxconfig"
	"time"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
	"github.com/google/netstack/tcpip/header"
)

type ForwardingEntry struct {
	NextHopIP    netip.Addr //fill with rip
	OutInterface string
	Cost         int
	Type         string
	Timestamp    time.Time
}

type IPStack struct {
	Config          lnxconfig.IPConfig
	ForwardingTable map[netip.Prefix]*ForwardingEntry
	Interfaces      map[string]*Interface
	Handlers        map[uint8]HandlerFunc
	NeighborToIF    map[netip.Addr]string
	TableMutex      *sync.Mutex
}

type Interface struct {
	Name      string
	VirtualIP netip.Addr
	Network   netip.Prefix
	UDP       netip.AddrPort
	Neighbors map[netip.Addr]netip.AddrPort
	Conn      *net.UDPConn
	Enabled   bool // added to track interface state as outlined in specification
}

type ripEntry struct {
	Cost    uint32
	Address uint32
	Mask    uint32
}
type RIPPacket struct {
	Command    uint16
	NumEntries uint16
	Entries    []ripEntry
}

func Initialize(configinfo lnxconfig.IPConfig) (*IPStack, error) {
	stack := &IPStack{}
	stack.Config = configinfo
	stack.ForwardingTable = make(map[netip.Prefix]*ForwardingEntry)
	stack.Interfaces = make(map[string]*Interface)
	stack.Handlers = make(map[uint8]HandlerFunc)
	stack.NeighborToIF = make(map[netip.Addr]string)
	stack.TableMutex = new(sync.Mutex)
	for _, i := range configinfo.Interfaces {
		iface := &Interface{}
		iface.Name = i.Name
		iface.VirtualIP = i.AssignedIP
		iface.Network = i.AssignedPrefix
		iface.UDP = i.UDPAddr
		iface.Neighbors = make(map[netip.Addr]netip.AddrPort)
		iface.Enabled = true
		udpAddress := net.UDPAddrFromAddrPort(iface.UDP)
		conn, err := net.ListenUDP("udp", udpAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to bind UDP socket on %s: %v", iface.UDP.String(), err)
		}
		iface.Conn = conn

		stack.Interfaces[i.Name] = iface

		go stack.listen(iface) //start listening on interface

		//only add to forwarding table after listening starts
		stack.ForwardingTable[iface.Network] = &ForwardingEntry{
			NextHopIP:    netip.Addr{}, // Directly connected network
			OutInterface: iface.Name,
			Cost:         0,
			Type:         "L",
		}
	}

	for _, n := range configinfo.Neighbors {
		iface, ok := stack.Interfaces[n.InterfaceName]
		stack.NeighborToIF[n.DestAddr] = n.InterfaceName
		if !ok {
			return nil, fmt.Errorf("Interface \"%s\" not found", n.InterfaceName)
		}
		iface.Neighbors[n.DestAddr] = n.UDPAddr
	}

	for prefix, nextHopIP := range configinfo.StaticRoutes {
		var outInterfaceName string
		var found bool
		for _, iface := range stack.Interfaces {
			if _, ok := iface.Neighbors[nextHopIP]; ok {
				outInterfaceName = iface.Name
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("can't locate interface to reach next hop IP %s for static route %s", nextHopIP, prefix)
		}
		stack.ForwardingTable[prefix] = &ForwardingEntry{
			NextHopIP:    nextHopIP,
			OutInterface: outInterfaceName,
			Cost:         1,
			Type:         "S",
		}
	}
	if len(configinfo.RipNeighbors) > 0 {
		go stack.RIPUpdates()
		go stack.periodicExpirationCheck()
	}
	return stack, nil
}

// use to send new messages from cli
func (ips *IPStack) SendIP(dst netip.Addr, protoNum uint8, data []byte) error {
	iface, nextHop, err := ips.searchTable(dst)
	if err != nil {
		return fmt.Errorf("could not find a route to host %s", dst)
	}
	hBytes, err := ips.constructIPHeader(iface.VirtualIP, dst, protoNum, data)
	if err != nil {
		return fmt.Errorf("error constructing IP header: %v", err)
	}
	err = ips.send(iface, nextHop, hBytes, data)
	if err != nil {
		return fmt.Errorf("error sending packet: %v", err)
	}
	return nil
}

func (ips *IPStack) RIPRequest() {
	for _, neighborIP := range ips.Config.RipNeighbors {
		iface := ips.Interfaces[ips.NeighborToIF[neighborIP]]
		packet := RIPPacket{Command: 1, NumEntries: 0}
		pBytes, err := serializeRIPPacket(packet)
		if err != nil {
			log.Printf("failed to serialize packet to %s", neighborIP)
			continue
		}
		hBytes, err := ips.constructIPHeader(iface.VirtualIP, neighborIP, 200, pBytes)
		if err != nil {
			log.Printf("failed to create RIP header from %s to %s", iface.Name, neighborIP.String())
			continue
		}
		err = ips.send(iface, iface.Neighbors[neighborIP], hBytes, pBytes)
		if err != nil {
			log.Printf("failed to send RIP request from %s to %s", iface.Name, neighborIP.String())
			continue
		}
	}
}

func serializeRIPPacket(packet RIPPacket) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, packet.Command)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, packet.NumEntries)
	if err != nil {
		return nil, err
	}
	if packet.NumEntries > 0 {
		for _, entry := range packet.Entries {
			err = binary.Write(buf, binary.BigEndian, entry)
			if err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

func deSerializeRIPPacket(data []byte) (RIPPacket, error) {
	packet := RIPPacket{}
	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.BigEndian, &packet.Command)
	if err != nil {
		return packet, err
	}
	err = binary.Read(buf, binary.BigEndian, &packet.NumEntries)
	if err != nil {
		return packet, err
	}
	packet.Entries = make([]ripEntry, packet.NumEntries)
	for i := 0; i < int(packet.NumEntries); i++ {
		err = binary.Read(buf, binary.BigEndian, &packet.Entries[i])
		if err != nil {
			return packet, err
		}
	}
	return packet, nil
}

// searches forwarding table for dest addr, returns interface to write from and port to write to
func (ips *IPStack) searchTable(dst netip.Addr) (*Interface, netip.AddrPort, error) {
	var matchedEntry *ForwardingEntry
	longestPrefixLen := -1
	ips.TableMutex.Lock()
	defer ips.TableMutex.Unlock()
	for prefix, entry := range ips.ForwardingTable {
		if prefix.Contains(dst) && prefix.Bits() > longestPrefixLen {
			longestPrefixLen = prefix.Bits()
			matchedEntry = entry
		}
	}
	if matchedEntry == nil {
		return nil, netip.AddrPort{}, fmt.Errorf("no route to host %s", dst)
	}
	iface, ok := ips.Interfaces[matchedEntry.OutInterface]
	if !ok {
		return nil, netip.AddrPort{}, fmt.Errorf("interface %s not found", matchedEntry.OutInterface)
	}
	if !iface.Enabled {
		return nil, netip.AddrPort{}, fmt.Errorf("interface %s is down", iface.Name)
	}

	var nextHopUDPAddr netip.AddrPort

	if matchedEntry.Type != "L" { //forward to other network
		nextHopUDPAddr, ok = iface.Neighbors[matchedEntry.NextHopIP]
		if !ok {
			return nil, netip.AddrPort{}, fmt.Errorf("no neighbor info for next hop %s", matchedEntry.NextHopIP)
		}
	} else { //local network
		nextHopUDPAddr, ok = iface.Neighbors[dst]
		if !ok {
			return nil, netip.AddrPort{}, fmt.Errorf("no neighbor info for destination %s", dst)
		}
	}
	return iface, nextHopUDPAddr, nil
}

// helper for sendIP, actually sends to the udp port
func (ips *IPStack) send(iface *Interface, nextHop netip.AddrPort, hBytes, data []byte) error {
	if !iface.Enabled {
		return fmt.Errorf("interface %s is down", iface.Name)
	}
	p := append(hBytes, data...)
	destAddr := net.UDPAddrFromAddrPort(nextHop)

	_, err := iface.Conn.WriteToUDP(p, destAddr)
	if err != nil {
		return fmt.Errorf("error sending packet: %v", err)
	}
	return nil
}

// handle a rip message, As
// a response to a RIP request,
// A periodic update, which is sent by the router every 5 seconds
// A triggered update, which is sent whenever the router’s routing table changes
func HandleRIP(data []byte, shit []interface{}) { // shit has header, ipstack, str iface on this node, address to send to
	packet, err := deSerializeRIPPacket(data)
	if err != nil {
		log.Println("error parsing RIP packet")
		return
	}
	var header *ipv4header.IPv4Header
	var stack *IPStack
	var iface string
	var addr netip.AddrPort
	var ok bool
	if header, ok = shit[0].(*ipv4header.IPv4Header); !ok {
		fmt.Println("shit[0] is not of type ipv4header")
		return
	}
	if stack, ok = shit[1].(*IPStack); !ok {
		fmt.Println("shit[1] is not of type *IPStack")
		return
	}
	if iface, ok = shit[2].(string); !ok {
		fmt.Println("shit[2] is not of type string")
		return
	}
	if addr, ok = shit[3].(netip.AddrPort); !ok {
		fmt.Println("shit[3] is not of type netip.AddrPort")
		return
	}
	if packet.Command == 1 { //handle rip request -> respond       need to do split horizon/poison reverse later
		stack.updateNeighborRIP(iface, addr, header)
	} else if packet.Command == 2 { // Handle RIP response
		stack.updateRoutingTable(packet, header.Src, iface)
	}
}

func (ips *IPStack) updateNeighborRIP(iface string, addr netip.AddrPort, header *ipv4header.IPv4Header) {
	ips.TableMutex.Lock()
	defer ips.TableMutex.Unlock()
	response := RIPPacket{
		Command: 2,
		Entries: make([]ripEntry, 0),
	}
	for prefix, entry := range ips.ForwardingTable {
		// split horizon w/ poison
		cost := entry.Cost
		if entry.NextHopIP == header.Src { //checking if learned from neighbor
			cost = 16
		}

		compressedAddr, err := compressIP(prefix.Addr())
		if err != nil {
			log.Println("could not shrink prefix address")
			continue
		}

		response.Entries = append(response.Entries, ripEntry{
			Cost:    uint32(cost),
			Address: compressedAddr,
			Mask:    ^uint32(0) << (32 - prefix.Bits()),
		})
	}
	response.NumEntries = uint16(len(response.Entries))
	pBytes, err := serializeRIPPacket(response)
	if err != nil {
		log.Println("could not construct RIP response packet")
		return
	}
	hBytes, err := ips.constructIPHeader(header.Dst, header.Src, 200, pBytes)
	if err != nil {
		log.Println("could not construct header for RIP response")
		return
	}
	err = ips.send(ips.Interfaces[iface], addr, hBytes, pBytes)
	if err != nil {
		log.Printf("failed to send RIP response from %s to %s", iface, header.Src)
	}
}

func bitmaskToPrefixLength(mask uint32) int {
	count := 0
	for i := 31; i >= 0; i-- {
		if (mask>>i)&1 == 1 {
			count++
		} else {
			break
		}
	}
	return count
}

func (ips *IPStack) updateRoutingTable(packet RIPPacket, srcIP netip.Addr, ifaceName string) {
	ips.TableMutex.Lock()
	defer ips.TableMutex.Unlock()
	for _, entry := range packet.Entries {
		prefixAddr, err := restoreIP(entry.Address)
		if err != nil {
			log.Println("Error restoring IP address from RIP entry:", err)
			continue
		}
		prefix := netip.PrefixFrom(prefixAddr, bitmaskToPrefixLength(entry.Mask))

		//calculate new cost
		newCost := int(entry.Cost) + 1
		if newCost > 16 {
			newCost = 16
		}

		existingEntry, exists := ips.ForwardingTable[prefix]
		if !exists || newCost < existingEntry.Cost {
			ips.ForwardingTable[prefix] = &ForwardingEntry{
				NextHopIP:    srcIP,
				OutInterface: ifaceName,
				Cost:         newCost,
				Type:         "R",
				Timestamp:    time.Now(),
			}
		} else if existingEntry.NextHopIP == srcIP {
			if newCost >= 16 {
				delete(ips.ForwardingTable, prefix) // delete unreachable routes
			} else {
				existingEntry.Cost = newCost
				existingEntry.Timestamp = time.Now()
				ips.ForwardingTable[prefix] = existingEntry
			}
		}
	}
}

func compressIP(ip netip.Addr) (uint32, error) {
	if !ip.IsValid() || !ip.Is4() {
		return 0, errors.New("invalid ip")
	}
	ipv4 := ip.As4()
	compressed := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
	return compressed, nil
}

func restoreIP(compressed uint32) (netip.Addr, error) {
	ipv4 := [4]byte{
		byte(compressed >> 24),
		byte(compressed >> 16),
		byte(compressed >> 8),
		byte(compressed),
	}
	return netip.AddrFrom4(ipv4), nil
}

func (ips *IPStack) RIPUpdates() { //periodically sending ripresponses
	ticker := time.NewTicker(ips.Config.RipPeriodicUpdateRate)
	defer ticker.Stop()
	for {
		<-ticker.C
		ips.TableMutex.Lock()
		ips.updateNeighbors()
		ips.TableMutex.Unlock()
	}
}

func (ips *IPStack) updateNeighbors() {
	for _, neighborIP := range ips.Config.RipNeighbors {
		ifaceName := ips.NeighborToIF[neighborIP]
		iface := ips.Interfaces[ifaceName]
		if !iface.Enabled {
			continue
		}
		response := RIPPacket{
			Command: 2,
			Entries: make([]ripEntry, 0),
		}
		for prefix, entry := range ips.ForwardingTable {
			// split horizon & poison
			cost := entry.Cost
			if entry.NextHopIP == neighborIP {
				cost = 16
			}
			compressedAddr, err := compressIP(prefix.Addr())
			if err != nil {
				log.Println("could not shrink prefix address")
				continue
			}
			response.Entries = append(response.Entries, ripEntry{
				Cost:    uint32(cost),
				Address: compressedAddr,
				Mask:    ^uint32(0) << (32 - prefix.Bits()),
			})
		}
		response.NumEntries = uint16(len(response.Entries))
		pBytes, err := serializeRIPPacket(response)
		if err != nil {
			log.Println("could not serialize RIP packet")
			continue
		}
		hBytes, err := ips.constructIPHeader(iface.VirtualIP, neighborIP, 200, pBytes)
		if err != nil {
			log.Println("could not construct IP header for RIP update")
			continue
		}
		err = ips.send(iface, iface.Neighbors[neighborIP], hBytes, pBytes)
		if err != nil {
			log.Printf("failed to send RIP update from %s to %s", iface.Name, neighborIP.String())
		}
	}
}

type HandlerFunc = func([]byte, []interface{})

// registers a handler function for different packet types
func (ips *IPStack) RegisterRecvHandler(protocolNum uint8, callbackFunc HandlerFunc) {
	ips.Handlers[protocolNum] = callbackFunc
}

func (ips *IPStack) listen(iface *Interface) error { //we will need a goroutine to listen on each interface with this function
	for {
		buf := make([]byte, 1500)
		n, addr, err := iface.Conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			log.Printf("error reading from interface %s: %v", iface.Name, err)
			continue
		}
		if !iface.Enabled {
			continue
		}
		packetData := buf[:n]
		go ips.processPacket(iface, packetData, addr)
	}
}

// need to implement
func (ips *IPStack) processPacket(iface *Interface, packetData []byte, addr netip.AddrPort) {
	hdr, err := ipv4header.ParseHeader(packetData)
	if err != nil {
		fmt.Println("Error parsing header", err)
		return
	}

	headerBytes := packetData[:hdr.Len]
	if !validateChecksum(headerBytes) {
		log.Println("dropping packet, invalid checksum")
		return
	}

	hdr.TTL -= 1
	if hdr.TTL < 1 {
		log.Println("dropping packet, TTL ran out")
		return
	}

	hdr.Checksum = 0
	hBytes, err := hdr.Marshal()
	if err != nil {
		log.Println("error marshalling header after TTL decrement:", err)
		return
	}
	hdr.Checksum = int(ComputeChecksum(hBytes))
	hBytes, err = hdr.Marshal()
	if err != nil {
		log.Println("Error serializing header after checksum recomputation:", err)
		return
	}

	message := packetData[hdr.Len:]

	//check if local to network
	isLocal := false
	for _, iface := range ips.Interfaces {
		if iface.VirtualIP == hdr.Dst {
			isLocal = true
			break
		}
	}

	// local vs forwarding logic
	if isLocal {
		handler, ok := ips.Handlers[uint8(hdr.Protocol)]
		if ok {
			handler(message, []interface{}{hdr, ips, iface.Name, addr})
		} else {
			log.Printf("No handler registered for protocol %d", hdr.Protocol)
		}
	} else {
		nextIface, nextHop, err := ips.searchTable(hdr.Dst)
		if err != nil {
			log.Printf("No route to host %s", hdr.Dst)
			return
		}
		err = ips.send(nextIface, nextHop, hBytes, message)
		if err != nil {
			log.Println("Error forwarding packet:", err)
		}
	}
}

func (ips *IPStack) EnableInterface(name string) error {
	iface, ok := ips.Interfaces[name]
	if !ok {
		return fmt.Errorf("interface %s not found", name)
	}
	iface.Enabled = true
	return nil
}

func (ips *IPStack) DisableInterface(name string) error {
	iface, ok := ips.Interfaces[name]
	if !ok {
		return fmt.Errorf("interface %s not found", name)
	}
	iface.Enabled = false
	return nil
}

func (ips *IPStack) constructIPHeader(src netip.Addr, dst netip.Addr, protoNum uint8, payload []byte) ([]byte, error) {
	hdr := ipv4header.IPv4Header{
		Version:  4,
		Len:      20, // Header length is always 20 when no IP options
		TOS:      0,
		TotalLen: ipv4header.HeaderLen + len(payload),
		ID:       0,
		Flags:    0,
		FragOff:  0,
		TTL:      32,
		Protocol: int(protoNum),
		Checksum: 0, // Should be 0 until checksum is computed
		Src:      src,
		Dst:      dst,
		Options:  []byte{},
	}

	hBytes, err := hdr.Marshal()
	if err != nil {
		return nil, err
	}

	hdr.Checksum = int(ComputeChecksum(hBytes))

	hBytes, err = hdr.Marshal()
	if err != nil {
		return nil, err
	}

	return hBytes, nil
}

func ComputeChecksum(b []byte) uint16 {
	checksum := header.Checksum(b, 0)
	checksumInv := checksum ^ 0xffff
	return checksumInv
}

func validateChecksum(b []byte) bool {
	return header.Checksum(b, 0) == 0xffff
}

func (ips *IPStack) periodicExpirationCheck() {
	ticker := time.NewTicker(ips.Config.RipTimeoutThreshold)
	defer ticker.Stop()
	for {
		<-ticker.C
		now := time.Now()
		ips.TableMutex.Lock()
		for prefix, entry := range ips.ForwardingTable {
			if entry.Type == "R" {
				if now.Sub(entry.Timestamp) > ips.Config.RipTimeoutThreshold {
					ips.ForwardingTable[prefix].Cost = 16
					ips.updateNeighbors()
					delete(ips.ForwardingTable, prefix)
				}
			}
		}
		ips.TableMutex.Unlock()
	}
}
