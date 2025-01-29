High Level Design Plan

There will be two main components, the virtual host and  the virtual router. They share an
underlying IPStack, which initializes the interfaces, maintains forwarding tables, and
routes/processes packets w/ registered protocl handlers. The host and router will communicate
via UDP sockets, and will hold IP packets within UDP packets to simulate the network link
layer. We will use .lnx files to define the network interfaces, neighbors, and routing
information for each node.

The IPStack will be designed to allow us to register protocol-specific handlers which process
incoming packets. This includes the RIP protocol that enables routers to exchange routing 
information efficiently.  Vhost will send/receive basic IP packets while vrouter will
periodically update its forwarding table using RIP. Our design will ensure that the IP layer
will be extensible with higher level protocols like TCP. We will also ensure scalability and
reliability through implementing reusable interfaces and leveraging Go's networking 
libraries for dealing  with socket communication and managing IP packets.