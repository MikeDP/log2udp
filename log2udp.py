#!/usr/bin/env python3
"""
log2udp.py

This is a log2d clone that adds logging to a UPD port.  The UDP packet
is the 'logging.logRecord' dict sent as JSON, preceeded by a 4 byte length.
Also overrides __call__ to allow e.g. mylog("Test INFO message", "Info") to
post direct to INFO etc.

V0.1  MDP  25/12/22  Merry Christmas
v0.2  MDP  09/01/23  Happy Birthday

"""

from functools import wraps
import json
import socket
import struct
import hashlib
from logging.handlers import DatagramHandler, SocketHandler
import threading

from log2d import Log, logging

# ################################# GLOBALS #####################
__VER__ = "v0.2 alpha"

# ################################# FUNCTIONS ###################

def json_encode(data: str, salt: str) -> bytes:
    """Encode the 'data' into a bytes string prepending the length and salted SHA256 digest"""
    hash = hashlib.sha256()
    try:
        # encode as JSON and convert to bytes
        json_text = json.dumps(data, default=str).encode('UTF-8')
        # Salt the hash with the secret
        hash.update(salt.encode('UTF-8'))
        hash.update(json_text)
        digest = hash.digest()
        # Add the length of the data and the digest to the beginning of the bytes
        json_bytes = struct.pack('!i', len(json_text+digest)) + digest + json_text
    except Exception as excep:
        print(f"Exception during makePickle: {excep}")
        return None
    return json_bytes

def json_decode(data, salt:str):
    """Unpack the data packet"""
    # Extract the length and the digest from the beginning of the packet
    length = struct.unpack('!i', data[:4])[0] + 4
    #Check the length of the data
    if len(data) != length:
        raise ValueError("Data length check failed")
    # Get the digest
    digest = data[4:4+hashlib.sha256().digest_size]
    # Extract the json data from the packet
    json_bytes = data[4+hashlib.sha256().digest_size:]

    # Calculate the digest of the json data
    calculated_digest = hashlib.sha256(salt.encode('utf-8')+json_bytes).digest()

    # Compare the calculated digest with the one received in the packet
    if calculated_digest != digest:
        raise ValueError("Data integrity check failed")

    # Convert the json bytes to a dictionary
    json_data = json_bytes.decode()
    log_dict = json.loads(json_data)

    return log_dict

def make_socket():
    """ Make a UDP socket that can use broadcasts"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(5)
    return sock


# ################################# CLASSES #####################

class ClassOrMethod(object):
    """Make method work for class or instance"""
    def __init__(self, func):
        self.func = func
    def __get__(self, obj, cls):
        context = obj if obj is not None else cls
        @wraps(self.func)
        def hybrid(*args, **kw):
            return self.func(context, *args, **kw)
        return hybrid

class LogUDP(Log):
    """ 'log2d.Log' clone incorporating a UDP data handler. """
    to_udp = False
    udp = ("localhost", 50005)
    remote_result = []

    def __init__(self, name, **kwargs):
        """ Initialise and add UDP handler if requested in kwargs
            as 'udp=("Name",port)' e.g. udp=("<broadcast>", 6666)
            and secret for SHA256 salt as salt="secret_salt"
        """
        # Set up for any UDP use first
        if "udp" in kwargs:
            self.to_udp = True
            self.udp = kwargs["udp"]
            if "salt" in kwargs:
                self.secret = kwargs["salt"]
            else:
                self.secret = ""
        # Now initialise. This also calls get_handlers
        super().__init__(name, **kwargs)

    def get_handlers(self):
        """Add UDP handler if reqested"""
        # get normal handlers
        handlers = super().get_handlers()
        # add UDP handler
        if self.to_udp:
            log_udp_formatter = logging.Formatter(fmt=self.fmt, datefmt=self.datefmt)
            handler = UDPHandler(*self.udp, self.secret)
            handler.setFormatter(log_udp_formatter)
            handler.setLevel(level=self.level_int)
            handlers += [handler]
        return handlers

    def version(self):
        """ Version string"""
        return __VER__

    def __call__(self, *args, **kwargs):
        """
        Shortcut to log at effective logging level using easy syntax e.g.
        mylog = Log("mylog")
        mylog("This text gets added to the logger output - no fuss!") # default 'debug'
        mylog("But this text goes to ERROR", level="ErRor")  # case insensitive, Goes to 'error'
        """
        level = logging.getLevelName(self.logger.getEffectiveLevel())
        if "level" in kwargs:
            lvl = kwargs['level'].upper()
            if lvl in logging._nameToLevel:
                level = lvl.lower()
        getattr(self.logger, level)(*args)

    def remote_find(self, find_command: dict):
        """Find via UDP.  Runs as a thread. Result in global 'remote_result' """
        global remote_result
        try:
            find_sock = make_socket()
            find_sock.sendto(find_command, self.udp)
            # now wait for reply
            data, addr = find_sock.recvfrom(4096)
            remote_result = json_decode(data, self.secret)
        except: # timeout?
            remote_result = ["Timeout"]

    @ClassOrMethod
    def find(self, text: str="", path=None, date=None, deltadays: int=-7, level: str='NOTSET',
                ignorecase: bool=True, remote=True):
        """ Search log for:
               text:        Text to seach for. Default '' means return everything
               path:        FULL 'path/to/another/log.log' to search. Default=None, search this log
               date:        Date(time) object/str anchor for search. Default None = NOW
               deltadays:   Number of days prior to (-ve) or after date. Default 1 week prior
               level:       Log level below which results are ignored. Default 'NOTSET'
               ignorecase:  Set case insensitivity. Default True
               remote:      Perform remote search over UDP. Default True
            Returns [r/l find] where r/l find is [MSG,[...]], [error msg.] or []
        """
        global remote_result
        remote_thread = None
        if self.to_udp and remote:
            # Construct command dict
            command = {"command": "FIND"}
            command['deflog'] = self.name
            command["text"] = text
            command["name"] = path
            command["date"] = date
            command["deltadays"] = deltadays
            command["level"] = level
            command["ignorecase"] = ignorecase
            command_json = json_encode(command, self.secret)
            # self.remote_find(command_json)
            remote_thread = threading.Thread(target=self.remote_find, args=(command_json,))
            remote_thread.start()
            # Now wait for thread, remote_result will be assigned globally
            remote_thread.join()
            return remote_result
            
        else: # local find
            if path or self.to_file:
                return super().find(text, path, date, deltadays, level, ignorecase)
            else:
                return []
            
class UDPHandler(DatagramHandler):  # Inherit from logging.Handler.DatagramHandler
    """
    Handler class which writes logging records, in json format, to
    a UDP socket.  The logRecord's dictionary (__dict__), is used
    which makes simple to decode at the recieving end - just use json.dumps().
    The json packet is preceeded by a 4 byte length int and a salted SHA256 digest.
    """

    def __init__(self, host, port, secret):
        """
        Initializes the handler with a specific host address and port.
        Host can be ip or name - 'localhost', '<broadcast>' etc.
        port is 1024 < port < 65536
        secret is salt for SHA256 digest of data packet
        """
        SocketHandler.__init__(self, host, port)
        self.hash = hashlib.sha256()
        self.closeOnError = False
        self.secret = secret

    def makeSocket(self):
        """
        The factory method of SocketHandler is here overridden to create
        a UDP socket (SOCK_DGRAM).
        """
        return make_socket()

    def send(self, pkt: bytes):
        """
        Send the json string to the socket.
        """
        if self.sock is None:
            self.createSocket()
        if pkt:
            self.sock.sendto(pkt, self.address)

    def makePickle(self, record) -> str:
        """
        Convert the message data to json dump, prefixed with length and digest
        """
        exinf = record.exc_info
        if exinf:
            # TODO: sort any traceback text
            _ = self.format(record)
        # Will only work when record only contains json serialisable objects
        msg = dict(record.__dict__)
        # Hardwire just to LOG stuff at this stage - find etc later
        msg['command'] = 'LOG'
        # Add two formatting strings
        msg['datefmt'] = self.formatter.datefmt
        msg['fmt'] = self.formatter._fmt
        msg['msg'] = msg.get("msg", record.getMessage())
        # Now return preceed by 4 byte length
        return json_encode(msg, self.secret)

# For simplified dev testing
if __name__ == "__main__":
    mylog = LogUDP('mylog', to_stdout=True, to_file=True,  udp=('<broadcast>', 6666), salt="M15ecret")
    #mylog.mylog.info("Test info message")
    mylog("Send to CRITICAL now", level="critical")
    #print(mylog.version())
    #LogUDP("mylog", udp=("<broadcast>", 6666), salt="M15ecret")("Class sensible error!", "error" )
    A = mylog.find()
    #A = LogUDP('').find(path='mylog')
    print(A)
