all: vhost vrouter

vhost: ./cmd/vhost
	go build -o vhost ./cmd/vhost

vrouter: ./cmd/vrouter
	go build -o vrouter ./cmd/vrouter

clean:
	rm -fv vhost vrouter