#!/usr/bin/env python3
"""
log2udp.py

This is a log2d clone that adds logging to a UPD port.  The UDP packet
is the 'logging.logRecord' dict sent as JSON, preceeded by a 4 byte length.
Also overrides __call__ to allow e.g. mylog("Test INFO message", "Info") to
post direct to INFO etc.

V0.1  MDP  25/12/22  Merry Christmas
v0.2  MDP  09/01/23  Happy Birthday
v0.3  MDP  28/02/23  ASCON authenticated encryption
v0.4  MDP  04/03/23  Simplified/enhanced 'extra' attributes
v0.41 MDP  16/03/23  UDP receive now chunked
v0.42 MDP  21/04/24  Latest version of ascon
"""

import hashlib
import os
import json
import socket
import struct
import threading
from datetime import datetime, timedelta
from functools import wraps
from logging.handlers import DatagramHandler, SocketHandler
from pathlib import Path

import ascon  # ASCON Encryption V>=0.0.9

from log2d import Log, logging    # MUST BE log2d v>=0.0.18 including 'find'

# ################################# GLOBALS #####################
__VER__ = "v0.42 beta"
VER_CMD = {"command": "VER", "name": 'apps'}
BUFSIZE = 4096

# ################################# FUNCTIONS ###################

def get_hostapp():
    """Return the present 'HOST:APP' string"""
    # Get hostapp details
    _hostname = socket.gethostname()
    _hostapp = Path(__file__).stem
    return f"{_hostname.upper()}:{_hostapp.upper()}"

def make_socket(timeout: int=2):
    """ Make a UDP socket that can use broadcasts"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    return sock

def json_encode(data: any, key: str) -> bytes:
    """Encode the 'data' into a bytes string using ASCON"""
    # encode as JSON
    json_data = json.dumps(data, default=str)
    # encrypt with ASCON
    encrypted_bytes = asc_encrypt(json_data, key).encode('utf-8')
    return encrypted_bytes

def json_decode(data:bytes, key:str) -> any:
    """Unpack the data packet"""
    # Decrypt with ASCON
    json_data = asc_decrypt(data.decode('utf-8'), key)
    # and decode from jason
    decrypt = json.loads(json_data)
    return decrypt

def asc_encrypt(plaintext:str, key:str) -> str:
    """ASCON1.2 encryption.
       Plaintext: str plaintext input
       key: str encryp[tion key. Will be hashed to 16 bytes.
       Returns: encrypted string of hex characters
    """
    # Fix key and convert to bytes
    _key = hashlib.md5(key.encode('utf-8')).digest()
    #Convert plaintext to byte
    plaintext_bytes = plaintext.encode('utf-8')
    # Generate a random 16 byte nonce
    nonce = bytes(os.urandom(16))
    # Encrypt plaintext with key and nonce
    ciphertext = ascon.encrypt(_key, nonce, b"", plaintext_bytes)
    # Append the nonce to the ciphertext
    encrypted_message = nonce + ciphertext
    # Convert encrypted message bytes to string of hex
    return encrypted_message.hex()  # string of hex characters

def asc_decrypt(encrypted_message_hex:str, key:str) -> str:
    """ASCON1.2 decryption.
        encrypted_message_hex: str encrypted text input
        key: str encryption key. Will be hashed to 16 bytes.
        Returns: str - decrypted plaintext
    """
    # Fix key to 16 bytes
    _key = hashlib.md5(key.encode('utf-8')).digest()
    # Convert encrypted message from hex to bytes
    encrypted_message = bytes.fromhex(encrypted_message_hex)
    # Extract the nonce and ciphertext from the encrypted message
    nonce = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    # Decrypt ciphertext with key and nonce
    try:
        plaintext_bytes = ascon.decrypt(_key, nonce, b"", ciphertext)
    except ValueError:
        raise ValueError("Decryption failed - message has been tampered with")
    # Convert plaintext bytes to string
    return plaintext_bytes.decode()  # String

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
    to_udp = False # required for local class find

    def __init__(self, name='', **kwargs):
        """ Initialise - additional (to log2d) kwargs recognised:
              'udp=("Name", port)' e.g. udp=("<broadcast>", 6666), add UDP handler
              'timeout=x' [0..x..5, def:2] for UDP receive timeout
              'salt="MySecret"' for UDP encryption key
              'hostapp="source of msg"' [def: auto] for hostapp attribute
              'extras={dict: of_new_attributes}' to add more record attributes as key:value dict
        """
        # Generic instance stuff
        self.to_udp = False
        self.udp = ("localhost", 50005)
        self.remote_result = []
        # Set up the hostapp
        self.hostapp = kwargs.get('hostapp', get_hostapp())
        # Set up for any UDP use first
        if "udp" in kwargs:
            self.to_udp = True
            self.udp = kwargs["udp"]
            self.secret = kwargs.get('salt', '')
            self.timeout = kwargs.get('timeout', 2)
            self.timeout = min(5, max(self.timeout, 0)) # timeout in range 0..5
        # Get any additional log attributes
        self.extras = kwargs.get('extras', {})
        if not isinstance(self.extras, dict):
            self.extras = {}
        # Now initialise. This also calls get_handlers
        super().__init__(name, **kwargs)
        self.logger.addFilter(self.extras_filter)

    def extras_filter(self, record):
        """Add hostapp and any other extras to logrecord for all handlers"""
        record.hostapp = self.hostapp
        if self.extras:
            for key in self.extras:
                setattr(record, key, self.extras[key])
        return True

    def get_handlers(self):
        """Add UDP handler if reqested"""
        # get normal handlers
        handlers = super().get_handlers()
        # add UDP handler
        if self.to_udp:
            log_udp_formatter = logging.Formatter(fmt=self.fmt, datefmt=self.datefmt)
            handler = UDPHandler(*self.udp, self.secret, self.timeout)
            handler.setFormatter(log_udp_formatter)
            handler.setLevel(level=self.level_int)
            handlers += [handler]
        return handlers

    def version(self):
        """ Version string from local and remote"""
        try:
            ver_sock = make_socket(self.timeout)
            ver_sock.sendto(json_encode(VER_CMD, self.secret), self.udp)
            # now wait for reply
            length_bytes, addr = ver_sock.recvfrom(4)  # length int
            total_length = struct.unpack('>L', length_bytes)[0]
            # receive the data in chunks
            data, addr = ver_sock.recvfrom(min(BUFSIZE, total_length))
            remote_ver = json_decode(data, self.secret) 
        except Exception as xcpt: # timeout?
            if isinstance(xcpt, socket.timeout):
                remote_ver = ["Timeout"]
            else:
                remote_ver = [f'Exception: {xcpt}']
        finally:
            ver_sock.close()
        return remote_ver

    def __getattr__(self, name, *args, **kwargs):
        """Modified to trap LogUPD.'level'() type calls which
        are re-directed to __call__"""
        if name.upper() in logging._nameToLevel:
            self.savelevel = name
            return self.__redirect__
        raise AttributeError(f": '{self.name}' object has no attribute '{name}'")

    def __redirect__(self, *args, **kwargs):
        """Redirect unknown method calls to __call__
        adding the correct 'level' """
        # Add level to kwargs
        kwargs['level'] = self.savelevel
        # and call dipatcher
        self.__call__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        """
        Shortcut to log at any logging level using easy syntax e.g.
          mylog = LogUDP("mylog", ...)
          mylog("This text gets added to the logger output - no fuss!") # default 'debug'
          mylog("But this text goes to ERROR", level="ErRor")  # case insensitive, Goes to 'error'
          mylog("Dynamic record attribute possible.", level="info", User="Bob") # User is first passed #
                                                                                  as element in extras dict at init.
        """
        level = logging.getLevelName(self.logger.getEffectiveLevel())
        lvl = kwargs.pop('level', level).upper()
        if lvl in logging._nameToLevel:
            level = lvl
        # Now sort any 'extras' attribute values
        def_extras = self.extras.copy()
        for attr in self.extras:
            new_value = kwargs.pop(attr, None)
            if new_value:
                self.extras[attr] = new_value
        getattr(self.logger, level.lower())(*args)
        # Reset old 'extras' value
        self.extras = def_extras.copy()

    def remote_find(self, find_command: dict):
        """Find via UDP.  Runs as a thread. Result in global 'remote_result' """
        global remote_result  # This returns the result when the thread ends
        try:
            find_sock = make_socket(self.timeout)
            find_sock.sendto(find_command, self.udp)
            # receive the total length of the data as a 4-byte unsigned integer
            length_bytes, addr = find_sock.recvfrom(4)
            total_length = struct.unpack('>L', length_bytes)[0]
            # receive the data in chunks
            chunks = []
            while total_length > 0:
                chunk, addr = find_sock.recvfrom(min(BUFSIZE, total_length))
                chunks.append(chunk)
                total_length -= len(chunk)
            # combine the chunks into a single data string
            data = b''.join(chunks)
            # decrypt
            remote_result = json_decode(data, self.secret)
        except Exception as xcpt: # timeout?
            if isinstance(xcpt, socket.timeout):
                remote_result = ["Timeout"]
            else:
                remote_result = [f'Exception: {xcpt}']
        finally:
            find_sock.close()

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
        global remote_result # This holds the result when remote_find thread ends
        remote_thread = None
        if self.to_udp and remote:
            # Construct command dict
            command = {"command": "FIND"}
            command['name'] = self.name
            command["text"] = text
            command["path"] = path
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
            return []  # No search so return nothing

class UDPHandler(DatagramHandler):  # Inherit from logging.Handler.DatagramHandler
    """
    Handler that writes logging records, in json format, to
    a UDP socket.  The logRecord's dictionary (__dict__), is sent
    as an authenticated/encrypted (ASCON) hex json string which
    makes it simple to decode at the recieving end.
    """

    def __init__(self, host, port, secret, timeout=2):
        """
        Initializes the handler with a specific host address and port.
        Host can be ip or name - 'localhost', '<broadcast>' etc.
        port is 1024 < port < 65536
        secret is key for encryption of data packet
        timeout is for any reply
        """
        SocketHandler.__init__(self, host, port)
        self.hash = hashlib.sha256()
        self.closeOnError = False
        self.secret = secret
        self.timeout = timeout
        #self.hostapp = hostapp

    def makeSocket(self):
        """
        The factory method of SocketHandler is here overridden to create
        a UDP socket (SOCK_DGRAM).
        """
        return make_socket(self.timeout)

    def send(self, pkt: bytes):
        """
        Send the jason string to the socket.
        """
        if self.sock is None:
            self.createSocket()
        if pkt:
            self.sock.sendto(pkt, self.address)

    def makePickle(self, record:logging.LogRecord) -> bytes:
        """
        Convert the message data to json dump, prefixed with length
        """
        exinf = record.exc_info
        if exinf:
            # TODO: sort any traceback text
            _ = self.format(record)
        # Will only work when record only contains json serialisable objects
        msg = dict(record.__dict__)
        # Add command to LOG
        msg['command'] = 'LOG'
        # Add two formatting strings
        msg['datefmt'] = self.formatter.datefmt
        msg['fmt'] = self.formatter._fmt
        # Now return encoded message
        return json_encode(msg, self.secret)

# For simplified dev testing
if __name__ == "__main__":
    now = datetime.now() - timedelta(seconds=1)
    msg_fmt = "%(hostapp)s|%(asctime)s|%(levelname)-8s|%(message)s|%(WTF)s"
    date_fmt = "%Y-%m-%dT%H:%M:%S"
    extras={"IP":"192.168.1.50", "WTF":42}
    mylog = LogUDP('mylog', datefmt=date_fmt, fmt=msg_fmt, udp=("<broadcast>", 6666),
                   salt="M15ecret", hostapp="TestHOST", extras=extras)
    #mylog.add_level("success", 35)

    #mylog.info("Critical Info message",  WTF=55)

    #mylog.logger.warning("More realistic log message")
    #mylog("Error message", level="error", WTF=50)
    #res = mylog.find(remote=True, date=now, deltadays=-1, level='error')
    #res = mylog.find(remote=True, date=now, deltadays=+1, level="Error")
    #print(f"\n###############\n{res}")
    #mylog.add_level("success", 25)
    #mylog("CRITICAL Success message, maybe in HTML?", level='critical')
    #mylog.logger.success("More fun!")


    #LogUDP("", udp=("<broadcast>", 6666), salt="M15ecret")("Class sensible error!", "error" )
    #mylog.add_level('success', above="INFO")

    print(f"Version: {mylog.version()}")
    pass
    
    """
    mylog = LogUDP('wtf', to_file=True, udp=('<broadcast>', 6666), salt="M15ecret")
    mylog("Simple send to default DEBUG")
    #mylog.mylog.info("Test info message")
    mylog("Send to CRITICAL now", level="critical")
    #print(mylog.version())
    #LogUDP("mylog", udp=("<broadcast>", 6666), salt="M15ecret")("Class sensible error!", "error" )
    A = mylog.find()
    #A = LogUDP('').find(path='mylog')
    #A = LogUDP('mylog', udp=('<broadcast>', 6666), salt="M15ecret").find()
    print(A)
    """
