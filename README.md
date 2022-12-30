# **log2udp**
<p align="center">
    <img src="assets/UDPglyph.png">
</p>

### _`log2d` with added UDP handler_

[`log2d`](https://github.com/PFython/log2d) is a wrapper around Python `logging` that makes it trivially simple, sane and logical to implement Python `logging` without needing to understand it's complexity.

`log2udp` adds a simple UDP datagram handler to `log2d` that allows log messages to be sent to a remote logger to provide a simple centralised logging system.

The UDP handler produces a log message as a `logging.logRecord` dict, uses JSON rather than pickle to encode the dict into a UDP packet and then transmits it to the remote listener. The listener can be anywhere on your network and can be setup as a _broadcast_ receiver.

### **UDP - User Datagram Protocol**
Unlike TCP, UDP is not connection-based - it's _“connectionless”_ - no connection is established before communication occurs. It is commonly referred to as the “fire-and-forget” protocol because it is not concerned about whether or not anyone actually receives the data transmitted. It is lightweight and faster than TCP and is commonly used for streaming.

### **Example UDP Listener**
I've provided an example UDP listener framework suitable for modest logging rates in a small network environment. Most conveniently, if you use a \<broadcast\> UDP address, you can run this anywhere on your local network and log messages will find it from any other machine, without providing an explicit IP address . However, there are a number of things you'll want to consider before *scaling up*.
* Speed: UDP is a fast, lightweight network protocaol.  This simple code sample is single threaded and - whilst fast - can only cope with one message at once.  If you expect usage to be significant, you should look at using a multi-threading approach to receiving UPD packets.
* Security: I have used `json.dumps()` rather than `pickle` as is used by the normal `logging.handlers.DatagramHandler` as `pickle` has some security concerns.  However, as written, the code will accept UDP packets from *any* source on your network - there is no provision for preventing malicious packets being received - though only `dict`s are accepted.  If required, additional security can be added using normal methods of authentification/encryption/hashing etc. by overriding the `makePickle` class method and the UDP listener as appropriate.
* Reliabilty: UDP is connectionless: this means `LogUDP` send it's log requests out *but has no way of knowing if the log message has been received and acted upon*.  It's quite possible to return a *message receipt* via UDP but then `LogUDP` would need to wait and check for a response - so you might as well use the standard `logging.handlers.SocketHandler` which uses TCP.
    
### **Usage Examples**
For general LogUPD usage, see the examples provided for [log2d](https://github.com/PFython/log2d#cookbook)
```
# Instantiate a remote log on a specific machine with local stdout echo and send a log message
remote_log = LogUDP("myRemoteLog", udp=("192.168.1.250", 6666), to_stdout=True)
remote_log.myRemoteLog.info("Info message 1")  # Goes to remote log and stdout
remote_log("Info message 2", "info")           # Also goes to remote log and stdout
``` 
```
# Instantiate a local and remote log and send a message
two_logs = LogUDP("mirrorLog", path="~/.logs", udp=("<broadcast>", 5005), to_stdout=False)
two_logs.mirrorlog.warning("Warning message 1")   # Goes to local and remote logs
two_logs("Warning message 2", "warning")          # Also goes to both logs
```
```
# Send log message with class function
LogUDP("remotelog", udp=("<broadcast>", 6666))("Critical message!", "critical")
```
