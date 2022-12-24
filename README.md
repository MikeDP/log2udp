# **log2udp**
[UDPglyph](assets/UDPglyph.png)
_`log2d` with added UDP handler_

[`log2d`](https://github.com/PFython/log2d) is a wrapper around Python `logging` that makes it trivially simple, sane and logical to implement Python `logging` without needing to understand it's complexity.

`log2udp` adds a simple UDP datagram handler to `log2d` that allows log messages to be sent to a remote logger to provide a simple centralised logging system.

The UDP handler produces a log message as a `logging.logRecord` dict, uses JSON rather than pickle to encode the dict into a UDP packet and then transmits it to the remote listener. The listener can be anywhere and can be setup as a _broadcast_ reciever
