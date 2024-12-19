# **log2udp**
<p align="center">
    <img src="assets/UDPglyph.png">
</p>

### _`log2d` with centralised logging for your lan via udp_

[`log2d`](https://github.com/PFython/log2d) is a wrapper around Python `logging` that makes it trivially simple, sane and logical to implement Python `logging` without needing to understand it's complexity.

`log2udp` extends this by adding a simple UDP datagram handler to `log2d` that allows log messages to be sent to a remote logger thus providing a simple centralised logging system. It also simplifies adding *'extra'* static and dynamic attributes to log messages and dispatching the messages themselves.

The UDP handler produces a log message as a `logging.logRecord` dict, using JSON rather than pickle, to encode the dict into a UDP packet. The raw JSON UDP packet is converted to an authenticated and encrypted string using the lightwieght [ASCON 1.2](https://github.com/meichlseder/pyascon) protocol and transmitted to the remote listener.

`logRecord` attributes can be modified from the initialisation kwargs. One (fixed) attribute is *hostapp* which defaults to "your_machine_name:your_app_name" if not explicitly specified.  It's possible to add *extra* attributes to the `logRecord` in a simple way via the "extras=_dict_" keyword argument, where _dict_ is a normal Python dictionary of key:value pairs.  See examples below.

### **UDP - User Datagram Protocol**
Unlike TCP, UDP is not connection-based - it's _“connectionless”_ - no connection is established before communication occurs. It is commonly referred to as the “fire-and-forget” protocol because it is not concerned about whether or not anyone actually receives the data transmitted. It is lightweight and faster than TCP and is commonly used for streaming.

### **Example UDP Listener**
Once the UDP packet is created and transmitted, it's up to the user to receive and handle it as they see fit.  I've provided an example UDP listener framework suitable for use in a small LAN environment. Most conveniently, if you use a \<broadcast\> UDP address, you can run this anywhere on your local network and log messages will find it from any other machine, without providing an explicit IP address . However, there are a number of things you'll want to consider before *scaling up*.
* Speed: UDP is a fast, lightweight network protocol.  This example uses multi-threading and queues.  
  - A *listener thread* receives incoming messages and puts them onto a *receive queue*. 
  - A *message handler* thread dispatches each message from the receive queue to it's own thread for handling.  
  - Any handled message that generates a response (eg. a *find* command) puts the response onto a *response queue* which ...
  - again starts a separate thread to encode the response and transmit it back to the client.
* Security: I have used `json.dumps()` rather than `pickle` as is used by the normal `logging.handlers.DatagramHandler` as `pickle` has some security concerns.  ASCON provides a simple, fast and secure means of both authenticating and encrypting the JSON packet before transmission over the LAN.
* Reliabilty: UDP is connectionless: this means `LogUDP` sends it's log requests out *but has no way of knowing if the log message has been received and acted upon*.  It's quite possible to return a *message receipt* via UDP but then `LogUDP` would need to wait and check for a response - so you might as well use the standard `logging.handlers.SocketHandler` which uses TCP.
    
### **Usage Examples**
For general LogUPD usage, see the examples provided for [log2d](https://github.com/PFython/log2d#cookbook)
```
# Instantiate a remote log on a specific machine with local stdout echo and send a log message
remote_log = LogUDP("myRemoteLog", udp=("192.168.1.250", 6666), to_stdout=True, salt="MySecret")
remote_log.myRemoteLog.info("Info message 1")  # Goes to remote log and stdout - as per log2d
remote_log.info("Info message 2")              # Also goes to same logs - simplified
remote_log("Info message 3", level="info")     # Also goes to remote log and stdout
``` 
```
# Instantiate a local and remote log and send a message and search it
two_logs = LogUDP("mirrorLog", path="~/.logs", udp=("<broadcast>", 5005), to_stdout=False, salt="MySecret")
two_logs.mirrorlog.warning("Warning message 1")   # Goes to local and remote logs - as per log2d
two_logs.warning("Warning message 2")             # again, same logs - simplified
two_logs("Warning message 3", level="warning")    # Also goes to both logs
```
```
# Send log message with class function
LogUDP("remotelog", udp=("<broadcast>", 6666), salt="MySecret")("Critical message!", level="critical")
```
```
# Add new attibutes to log record
new_attrs = {"IP": 192.168.1.20", "User": "Alice"}
fmt = "%(hostapp)s|%(asctime)s|%(levelname)-8s|%(message)s|%(IP)s|%(User)s"
remote_log = LogUDP("myRemoteLog", udp=("192.168.1.250", 6666), fmt=fmt, salt="MySecret", hostapp="Server1", extras=new_attrs)
remote_log("Message to remote log", level="INFO")
...
remote_log.info("Message 2 to remote log", User="Mikey")  # Dynamically change 'User'
...
remote_log.find("info", remote=True)   #  Case insensitive search of remote log for "info" in last 7 days

# Results in:  
  `Server1|2023-02-28T14:07:22|INFO    |Message to remote log|192.168.1.20|Alice`
  `Server1|2023-02-28T14:07:23|INFO    |Message 2 to remote log|192.168.1.20|Mikey`
```
