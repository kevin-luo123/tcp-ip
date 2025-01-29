## Design Decisions
## General 
We used a priority queue to keep track of out of order packets in the receive buffer and an ordered map to keep track of transmitted packets. The former was chosen for efficient integration of packets as the prior packets were received. The ordered map allowed for efficient retrieval of packets for RTT updates, while maintaining order for retransmission. 

### What are the key data structures that represent a connection?
A connection is represented by 2 tcp sockets, both of which contain a send and receive buffer. information is continuously sent when available from one socket's send buffer to the other's receive buffer by a thread. Another thread keeps track of transmitted packets that have not yet been acknowledged, and retransmits as needed. We use an ordered map for efficient dynamic storage of packets. 

### At a high level, how does your TCP logic (sending, receiving, retransmissions, etc.) use threads, and how do they interact with each other (and your data structures)?
Our tcp logic uses threads in 3 cases: the continuous transmission of information between sockets, monitoring the status of retransmissions, and when closing a connection. The general sending thread waits when the sendbuf contains no data to be sent, and reawakens when data is added. It probes the receive buffer when no room is available, and begins sending proper data when the receiving socket has room. The retransmission thread waits for a timer that is continuously managed as packets are acked, sent, etc. When the timer runs out and the ordered map contains packets that need to be retransmitted, we call a retransmit function. Finally, the thread for closing connections makes a socket wait before closing and removing from the socket table

### If you could do this assignment again, what would you change? Any ideas for how you might improve performance?
We would be more organized when building the code to improve readability and extensibility. We could improve performance by figuring out the duplicate ack/unnecessary retransmission issue, which slows down the program a bit. We looked into this problem extensively; monitoring pointer updates, order of packet reception, points at which pointers changed, etc., but were unable to narrow it down by the deadline. We also would clean up the teardown, which is a bit buggy. 

## Measuring Performance
Reference: ~0.044 seconds on ~1mb file
Ours: ~7.6 seconds on same file

## Packet Capture
Done on smaller file because the 1mb file with dropout broke my computer
handshake syn, syn/ack, acks are frames 1, 2, and 3

frame 4 sends the data at seq 1-1001. it is acked on frame 22
 
frame 170 is a retransmission of the data that was sent in frame 17

In order, the frames involved in teardown are 444-447

## Bugs
Duplicate acks and spurious retransmissions, teardown does not respond to last ack ? so gets stuck
## 1. How you build your abstractions for the IP layer and interfaces (What data structures do you have? How do your vhost and vrouter programs interact with your shared IP stack code?)

Our entire design for building IP layer abstractions is centered around the IPStack struct, encapsulating all of the foundational functionalities of the IP protocol, including managing interfaces, forwarding tables, processing packets, and handling routing protocols.

**Data structures:**
- **`IPStack`**: Central struct for the IP layer
    - **`Config`**: Contains parsed lnx config
    - **`Interfaces`** Map of interface names to their structs
    - **`ForwardingTable`** Map of prefixes to ForwardingEntry structs
    - **`Handlers`**: Map of protocol nums to their respective handler functions
    - **`NeighborToIF`**: Map linking neighbor IPs to interface names
    - **`TableMutex`**: The mutex that ensures safe concurrent operations on shared resources like the forwarding table
- **`Interface`**: Struct for a network interface
    - **`Name`**: Interface's identifier
    - **`VirtualIP`**: Interface's IP address
    - **`Network`**: Interface's prefix
    - **`UDP`**: UDP address & port for communication
    - **`Neighbors`**: Map of neighbor IPs to UDP addresses
    - **`Conn`**: UDP conn for sending/receiving packets
    - **`Enabled`**: For interface activation/deactivation
- **`ForwardingEntry`**: Struct for an entry in the forwarding table
    - **`NextHopIP`**: IP for next hop
    - **`OutInterface`**: The name of  the outgoing interface
    - **`Cost`**: Cost of route
    - **`Type`**: Local/Static/RIP ('L'/'S'/'R')
    - **`Timestamp`**: Last time the route was updated, used for expiration
- **`RIPPacket`** & **`ripEntry`**: Both structs used for RIP, and containing routing information that is exchanged between routers.

Our vhost and vrouter programs initialize an instance  of IPStack with the parsed config, and then register protocolm handlers for test packets and RIP packets. The functionality is almost exactly the same but vrouter also sends a rip request after initialization so that it can start exchanging  information with other routers.

## 2. How you use threads/goroutines?

We use goroutines in a lot of places for concurrent operations and to make sure network operations don't block the flow of  the main execution.

- **Interface Listening**:  For each interface, we start a goroutine so that  the interface can constantly listen for packets. This is done through the listen method in IPStack.
- **Packet Processing**: Every time an interface gets a packet, we start another go routine to process it. This is done through the processPacket method in IPStack.
- **RIP Updates**: The RIPUpdates method in IPStack is used to regularly send routing updates.
- **Route Expiration**: In order to consistently check for expired routes and remove them, we run the method periodicExpirationCheck in a  goroutine.

## 3. The steps you will need to process IP packets

- **Receiving Packets**: The listen goroutine receives a UDP packet and reads the data as well as the source address.
- **Parsing Headers**: We parse the header from the packet data uusing the provided ParseHeader function in the brown-csci1680/iptcp-headers package, which parses necessary information into a struct.
- **Validating Checksum**: We use the validateChecksum method which returns a boolean for whether the checksum is valid. If the checksum is  invalid, then the packet is discarded within the processPacket method.
- **Handling TTL**: The TTL field in the IP header is continuously decremented, and the packet is discarded when it hits zero. (checksum is also recalculated before forwarding again)
- **Determining Destination**: Just check if the destination IP matches any local interfaces.
- **Handling Packets**:
    - **Delivery**: For us --> Invoke appropriate protocol handler by checking protocol field in the IP header
    - **Forwarding**: Not for  us --> check forwarding table and send to  next hop using appropriate  interface
- **Thread Safety**: We have  the table mutex ensuring thread safe access to shared resources.