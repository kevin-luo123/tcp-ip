package cli

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"tcp/pkg/ipstack"
	"tcp/pkg/tcpstack"
	"time"

	ipv4header "github.com/brown-csci1680/iptcp-headers"
)

func MonitorCL(stack *ipstack.IPStack, tcpStack *tcpstack.TCPStack) {
	reader := bufio.NewReader(os.Stdin)
	for {
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("error reading input")
			continue
		}
		input = strings.TrimSpace(input)
		if input == "li" { //print list of interfaces
			interfaces := "\nName  Addr/Prefix State\n"
			for name, iface := range stack.Interfaces {
				var status string
				if iface.Enabled {
					status = "up"
				} else {
					status = "down"
				}
				interfaces += fmt.Sprintf("%s  %s %s \n", name, iface.Network.String(), status)
			}
			fmt.Println(interfaces)
		} else if input == "ln" { //print list of reachable neighbors
			neighbors := "\nIface          VIP          UDPAddr\n"
			for name, iface := range stack.Interfaces {
				if iface.Enabled {
					for vip, udpAddr := range iface.Neighbors {
						neighbors += fmt.Sprintf("%s     %s   %s\n", name, vip.String(), udpAddr.String())
					}
				}
			}
			fmt.Println(neighbors)
		} else if input == "lr" {
			routes := "\nT       Prefix   Next hop   Cost\n"
			stack.TableMutex.Lock()
			for prefix, forwardingEntry := range stack.ForwardingTable {
				var nextHop string
				if forwardingEntry.Type == "L" {
					nextHop = fmt.Sprintf("local:%s", forwardingEntry.OutInterface)
				} else {
					nextHop = forwardingEntry.NextHopIP.String()
				}
				routes += fmt.Sprintf("%s  %s   %s      %d\n", forwardingEntry.Type, prefix.String(), nextHop, forwardingEntry.Cost)
			}
			stack.TableMutex.Unlock()
			fmt.Println(routes)
		} else if strings.HasPrefix(input, "down") {
			toDisable := input[5:]
			if _, exists := stack.Interfaces[toDisable]; exists {
				stack.DisableInterface(toDisable)
			}
		} else if strings.HasPrefix(input, "up") {
			toEnable := input[3:]
			if _, exists := stack.Interfaces[toEnable]; exists {
				stack.EnableInterface(toEnable)
			}
		} else if strings.HasPrefix(input, "send") {
			parts := strings.SplitN(input, " ", 3)
			fmt.Println(parts)
			if len(parts) == 3 {
				if addr, err := netip.ParseAddr(parts[1]); err == nil {
					stack.SendIP(addr, 0, []byte(parts[2]))
				} else {
					fmt.Println("invalid destination")
				}
			} else {
				fmt.Println("follow format: send <addr> <message ...>")
			}
		} else if strings.HasPrefix(input, "a ") {
			if tcpStack == nil {
				fmt.Println("Routers do not support TCP commands")
			} else {
				parts := strings.Fields(input)
				if len(parts) != 2 {
					fmt.Println("Usage: a <local_port>")
					continue
				}
				port, err := strconv.Atoi(parts[1])
				if err != nil {
					fmt.Println("Invalid port number")
					continue
				}
				localPort := uint16(port)
				err = tcpStack.Listen(localPort)
				if err != nil {
					fmt.Println(err)
				}
			}
		} else if strings.HasPrefix(input, "c ") {
			if tcpStack == nil {
				fmt.Println("Routers do not support TCP commands")
			} else {
				parts := strings.Fields(input)
				if len(parts) != 3 {
					fmt.Println("Usage: c <remote_ip> <remote_port>")
					continue
				}
				remIPStr := parts[1]
				remIP, err := netip.ParseAddr(remIPStr)
				if err != nil {
					fmt.Println("Invalid remote IP address")
					continue
				}
				remPort, err := strconv.Atoi(parts[2])
				if err != nil {
					fmt.Println("Invalid remote port number")
					continue
				}

				err = tcpStack.VConnect(remIP, uint16(remPort))
				if err != nil {
					fmt.Println(err)
				}
			}
		} else if input == "ls" {
			if tcpStack == nil {
				fmt.Println("Routers do not support TCP commands")
			} else {
				sockets := "\nSID      LAddr LPort      RAddr    RPort    Status\n"
				tcpStack.SocksLock.Lock()
				for i, k := range tcpStack.NumToKey {
					sock := tcpStack.Socks[k]
					var state string
					switch sock.GetState() {
					case tcpstack.CLOSED:
						state = "CLOSED"
					case tcpstack.LISTEN:
						state = "LISTEN"
					case tcpstack.SYN_SENT:
						state = "SYN_SENT"
					case tcpstack.SYN_RECEIVED:
						state = "SYN_RECEIVED"
					case tcpstack.ESTABLISHED:
						state = "ESTABLISHED"
					case tcpstack.CLOSING:
						state = "CLOSING"
					case tcpstack.FIN_WAIT_1:
						state = "FIN_WAIT_1"
					case tcpstack.FIN_WAIT_2:
						state = "FIN_WAIT_2"
					case tcpstack.TIME_WAIT:
						state = "TIME_WAIT"
					case tcpstack.CLOSE_WAIT:
						state = "CLOSE_WAIT"
					case tcpstack.LAST_ACK:
						state = "LAST_ACK"
					default:
						state = fmt.Sprintf("UNKNOWN(%d)", sock.State)
					}
					if !sock.RemIP.IsValid() {
						sockets += fmt.Sprintf("%d    %s  %d      0.0.0.0    0       %s\n", i, sock.LocIP.String(), sock.LocPort, state)
					} else {
						sockets += fmt.Sprintf("%d    %s  %d      %s   %d   %s\n", i, sock.LocIP.String(), sock.LocPort, sock.RemIP.String(), sock.RemPort, state)
					}
				}
				tcpStack.SocksLock.Unlock()
				fmt.Println(sockets)
			}
		} else if strings.HasPrefix(input, "s ") {
			if tcpStack == nil {
				fmt.Println("Routers do not support TCP commands")
			} else {
				parts := strings.SplitN(input, " ", 3)
				if len(parts) != 3 {
					fmt.Println("Usage: s <socket ID> <bytes>")
					continue
				}
				socketIDStr := parts[1]
				message := parts[2]
				socketID, err := strconv.Atoi(socketIDStr)
				if err != nil {
					fmt.Println("Invalid socket number")
					continue
				}
				tcpStack.SocksLock.Lock()
				k, ok := tcpStack.NumToKey[socketID]
				if !ok {
					tcpStack.SocksLock.Unlock()
					fmt.Println("socket doesn't exist")
					continue
				}
				socket := tcpStack.Socks[k]
				tcpStack.SocksLock.Unlock()
				if socket == nil {
					fmt.Println("nil socket")
					continue
				}
				bytes, err := socket.VWrite([]byte(message))
				if err != nil {
					fmt.Println("failed to send message")
				} else {
					fmt.Printf("%d bytes sent\n", bytes)
				}
			}
		} else if strings.HasPrefix(input, "r ") {
			if tcpStack == nil {
				fmt.Println("Routers do not support TCP commands")
			} else {
				parts := strings.SplitN(input, " ", 3)
				if len(parts) != 3 {
					fmt.Println("Usage: s <socket ID> <numbytes>")
					continue
				}
				socketIDStr := parts[1]
				numBytesStr := parts[2]
				numBytes, err := strconv.Atoi(numBytesStr)
				if err != nil {
					fmt.Println("Invalid number of bytes")
					continue
				}
				socketID, err := strconv.Atoi(socketIDStr)
				if err != nil {
					fmt.Println("Invalid socket number")
					continue
				}
				tcpStack.SocksLock.Lock()
				k, ok := tcpStack.NumToKey[socketID]
				if !ok {
					tcpStack.SocksLock.Unlock()
					fmt.Println("socket doesn't exist")
					continue
				}
				socket := tcpStack.Socks[k]
				tcpStack.SocksLock.Unlock()
				message := make([]byte, numBytes)
				bytesRead, err := socket.VRead(tcpStack, message)
				if err != nil {
					fmt.Println("error reading socket")
				} else {
					fmt.Printf("Read %d bytes: %s \n", bytesRead, message)
				}
			}
		} else if strings.HasPrefix(input, "rf ") {
			if tcpStack == nil {
				fmt.Println("Routers do not support TCP commands")
			} else {
				parts := strings.SplitN(input, " ", 3)
				if len(parts) != 3 {
					fmt.Println("Usage: rf <dest_file> <port>")
					continue
				}
				port, err := strconv.Atoi(parts[2])
				if err != nil || port < 1 || port > 65535 {
					fmt.Println("Invalid port number")
					continue
				}
				go func(destFile string, port uint16) {
					err := tcpStack.Listen(port)
					if err != nil {
						fmt.Printf("recvfile error: %v\n", err)
						return
					}
					id := tcpStack.NextSock - 1
					tcpStack.SocksLock.Lock()
					k, exists := tcpStack.NumToKey[id]
					if !exists {
						fmt.Printf("error socket %d for sending file no longer exists\n", id)
						return
					}
					listenSock, exists := tcpStack.Socks[k]
					if !exists {
						fmt.Printf("error socket %d for sending file no longer exists\n", id)
						return
					}
					tcpStack.SocksLock.Unlock()
					sock, err := listenSock.VAccept()
					if err != nil {
						fmt.Printf("error with vaccept\n")
						return
					}
					fmt.Printf("recvfile: client connected!\n")
					f, err := os.Create(destFile)
					if err != nil {
						fmt.Printf("recvfile: failed to create destination file ): %v\n", err)
						sock.VClose(tcpStack)
						return
					}
					defer f.Close()
					total := 0
					buffer := make([]byte, 1024)
					for sock.GetState() != tcpstack.ESTABLISHED {
						time.Sleep(100 * time.Millisecond)
					}
					for {
						// fmt.Printf("Calling vread")
						bytesRead, err1 := sock.VRead(tcpStack, buffer)
						if bytesRead > 0 {
							_, err := f.Write(buffer[:bytesRead])
							if err != nil {
								break
							}
							total += bytesRead
						}
						if err1 != nil {
							break
						}
					}
					listenSock.VClose(tcpStack)
					sock.VClose(tcpStack)
					fmt.Printf("recvfile done: read %d bytes total\n", total)
				}(parts[1], uint16(port))
			}
		} else if strings.HasPrefix(input, "sf ") {
			if tcpStack == nil {
				fmt.Println("Routers do not support TCP commands")
			} else {
				parts := strings.SplitN(input, " ", 4)
				if len(parts) != 4 {
					fmt.Println("Usage: sf <file_path> <addr> <port>")
					continue
				}
				dest, err := netip.ParseAddr(parts[2])
				if err != nil {
					fmt.Println("invalid destination ip")
					continue
				}
				port, err := strconv.Atoi(parts[3])
				if err != nil || port < 1 || port > 65535 {
					fmt.Println("invalid destination port")
					continue
				}
				go func(path string, addr netip.Addr, port uint16) {
					f, err := os.Open(path)
					if err != nil {
						fmt.Printf("failed to open file: %v\n", err)
						return
					}
					defer f.Close()
					err = tcpStack.VConnect(addr, port)
					if err != nil {
						fmt.Printf("failed to connect to %s:%d: %v\n", addr.String(), port, err)
						return
					}
					fmt.Printf("connected to %s:%d\n", addr.String(), port)
					id := tcpStack.NextSock - 1
					tcpStack.SocksLock.Lock()
					k, exists := tcpStack.NumToKey[id]
					if !exists {
						fmt.Printf("error socket %d for sending file no longer exists\n", id)
						return
					}
					socket, exists := tcpStack.Socks[k]
					tcpStack.SocksLock.Unlock()
					if !exists || socket == nil {
						fmt.Printf("error socket %d for sending file no longer exists\n", id)
						return
					}
					for socket.GetState() != tcpstack.ESTABLISHED {
						time.Sleep(100 * time.Millisecond)
					}
					total := 0
					buffer := make([]byte, 1024)
					for {
						bytesRead, err := f.Read(buffer)
						if err != nil {
							if err == io.EOF {
								break
							}
							fmt.Printf("error sending file: %v\n", err)
							break
						}
						if bytesRead > 0 {
							bytesSent, err := socket.VWrite(buffer[:bytesRead])
							if err != nil {
								fmt.Printf("failed to send data: %v\n", err)
								break
							}
							total += bytesSent
						}
					}
					for socket.Retransmission.Sent.Len() > 0 {
						time.Sleep(100 * time.Millisecond)
					}
					socket.VClose(tcpStack)
					fmt.Printf("Sent %d total bytes\n", total)
				}(parts[1], dest, uint16(port))
			}
		} else if strings.HasPrefix(input, "cl ") {
			if tcpStack == nil {
				fmt.Println("Routers do not support TCP commands")
			} else {
				parts := strings.SplitN(input, " ", 2)
				if len(parts) != 2 {
					fmt.Println("Usage: cl <socket ID>")
					continue
				}
				socketID, err := strconv.Atoi(parts[1])
				if err != nil {
					fmt.Println("Invalid socket number")
					continue
				}
				tcpStack.SocksLock.Lock()
				k, ok := tcpStack.NumToKey[socketID]
				if !ok {
					tcpStack.SocksLock.Unlock()
					fmt.Println("socket doesn't exist")
					continue
				}
				sock := tcpStack.Socks[k]
				tcpStack.SocksLock.Unlock()
				sock.VClose(tcpStack)
			}
		} else {
			fmt.Println("invalid command")
		}
	}
}

func HandleTestPacket(data []byte, shit []interface{}) {
	if iface, ok := shit[2].(*ipstack.Interface); ok && !iface.Enabled {
		fmt.Println("message received on disabled interface")
	}
	if header, ok := shit[0].(*ipv4header.IPv4Header); ok {
		fmt.Printf("Received test packet: Src: %s, Dst: %s, TTL: %d, Data: %s\n",
			header.Src.String(), header.Dst.String(), header.TTL, string(data))
	}
}
