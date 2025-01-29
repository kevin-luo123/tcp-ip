// Entry point for vhost
// Initializes IP stack and sends + receives packets.

package main

import (
	"log"
	"os"
	"tcp/pkg/cli"
	"tcp/pkg/ipstack"
	"tcp/pkg/lnxconfig"
	"tcp/pkg/tcpstack"
)

func main() {
	node := os.Args[1]
	lnxconfig, err := lnxconfig.ParseConfig(os.Args[2])
	if err != nil {
		log.Fatalf("Failed to parse node %s: %s", node, err)
	}
	stack, err := ipstack.Initialize(*lnxconfig)
	if err != nil {
		log.Fatalf("Failed to initialize node %s: %s", node, err)
	}

	tcpStack := tcpstack.New(stack)

	stack.RegisterRecvHandler(0, cli.HandleTestPacket)
	stack.RegisterRecvHandler(200, ipstack.HandleRIP)
	stack.RegisterRecvHandler(6, tcpStack.TCPHandler)
	cli.MonitorCL(stack, tcpStack)
}
