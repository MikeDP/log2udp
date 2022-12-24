# **log2udp**
_`log2d` with added UDP handler_

`log2d` is a wrapper around Python `logging` that makes it sane, simple and logical to use.

`log2udp` adds a simple UDP datagram handler to `log2d` that allows log messages to be sent 
to a remote logger to provide a simple centralised logging system.

The UDP handler produces a log message as a `logging.logRecord` dict and uses JSON rather than pickle
to encode the UDP packet.
