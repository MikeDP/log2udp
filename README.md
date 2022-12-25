# **log2udp**
<p align="center">
    <img src="assets/UDPglyph.png">
</p>

### _`log2d` with added UDP handler_

[`log2d`](https://github.com/PFython/log2d) is a wrapper around Python `logging` that makes it trivially simple, sane and logical to implement Python `logging` without needing to understand it's complexity.

`log2udp` adds a simple UDP datagram handler to `log2d` that allows log messages to be sent to a remote logger to provide a simple centralised logging system.

The UDP handler produces a log message as a `logging.logRecord` dict, uses JSON rather than pickle to encode the dict into a UDP packet and then transmits it to the remote listener. The listener can be anywhere on your network and can be setup as a _broadcast_ reciever.

### **UDP - Universal Datagram Protocol**
Unlike TCP, UDP is not connection-based - it's _“connectionless”_ - no connection is established before communication occurs. It is commonly referred to as the “fire-and-forget” protocol because it is not concerned about whether or not anyone actually receives the data transmitted. It is lightweight and faster than TCP and is commonly used for streaming.



