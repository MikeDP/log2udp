#!/usr/bin/env python3
"""
log2udp.py

This is a log2d clone that adds logging to a UPD port.  The UDP packet
is the 'logging.logRecord' dict sent as JSON, preceeded by a 4 byte length.
Also overrides __call__ to allow e.g. mylog("Test INFO message", "Info") to
post direct to INFO etc.

V0.1  MDP  25/12/22  Merry Christmas

"""

import json
import socket
import struct
from logging.handlers import DatagramHandler, SocketHandler

from log2d import Log, logging

# ################################# GLOBALS #####################
__VER__ = "v0.1 alpha"

# ################################# CLASSES #####################

class LogUDP(Log):
    """ 'log2d.Log' clone incorporating a UDP data handler. """
    to_udp = False
    udp = ("localhost", 50005)

    def __init__(self, name, **kwargs):
        """ Initialise and add UDP handler if requested in kwargs
            as 'udp=("Name",port)' e.g. udp=("<broadcast>", 6666)
        """
        # Set up for any UDP use first
        if "udp" in kwargs:
            self.to_udp = True
            self.udp = kwargs["udp"]
        #else:
        #    self.to_udp = False
        # Now initialise. This also calls get_handlers
        super().__init__(name, **kwargs)

    def get_handlers(self):
        """Add UDP handler if reqested"""
        handlers = super().get_handlers()
        if self.to_udp:
            log_udp_formatter = logging.Formatter(fmt=self.fmt, datefmt=self.datefmt)
            handler = UDPHandler(*self.udp)
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
        mylog("But this text goes to ERROR", "ErRor")  # case insensitive, Goes to 'error'
        """
        level = logging.getLevelName(self.logger.getEffectiveLevel())
        if len(args) > 1:
            lvl = args[1].upper()
            if lvl in logging._nameToLevel:
                level = lvl
        getattr(self.logger, level.lower())(args[0])


class UDPHandler(DatagramHandler):  # Inherit from logging.Handler.DatagramHandler
    """
    Handler class which writes logging records, in json format, to
    a UDP socket.  The logRecord's dictionary (__dict__), is used
    which makes simple to decode at the recieving end - just use json.dumps().
    The json packet is preceeded by a 4 byte length int.
    """

    def __init__(self, host, port):
        """
        Initializes the handler with a specific host address and port.
        Host can be ip or name - 'localhost', '<broadcast>' etc.
        """
        SocketHandler.__init__(self, host, port)
        self.closeOnError = False

    def makeSocket(self):
        """
        The factory method of SocketHandler is here overridden to create
        a UDP socket (SOCK_DGRAM).
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(5)
        return sock

    def send(self, pkt: bytes):
        """
        Send the jason string to the socket.
        """
        if self.sock is None:
            self.createSocket()
        if pkt:
            self.sock.sendto(pkt, self.address)

    def makePickle(self, record) -> str:
        """
        Convert the message data to json dump, prefixed with length
        """
        exInf = record.exc_info
        if exInf:
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
        """
        # pop other crap we don't need
        for item in _ignoreList:
            msg.pop(item, None)
        """
        # Now return preceed by 4 byte length
        try:
            json_text = json.dumps(msg, default=str).encode('UTF-8')
            json_text_length = struct.pack(">L", len(json_text))
        except Exception as excep:
            print(f"Exception during makePickle: {excep}")
            return None
        return json_text_length + json_text

# For simplified testing
if __name__ == "__main__":
    mylog = LogUDP('mylog', to_file=True, to_stdout=True, udp=('<broadcast>', 6666))
    mylog.mylog.info("Test info message")
    mylog("Send to ERROR", "eRrOR")
    pass
