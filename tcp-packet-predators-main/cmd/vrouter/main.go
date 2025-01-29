// Entry point for vrouter
// Initializes IP stack, routing and manages RIP

package main

import (
	"tcp/pkg/cli"
	"tcp/pkg/ipstack"
	"tcp/pkg/lnxconfig"
	"log"
	"os"
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
	stack.RegisterRecvHandler(0, cli.HandleTestPacket)
	stack.RegisterRecvHandler(200, ipstack.HandleRIP)
	stack.RIPRequest()
	cli.MonitorCL(stack, nil)
}
