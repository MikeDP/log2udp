#! /usr/bin/env python3

"""
This applet is a bare minimum framework example of a UDP listener.

UPDATE PENDING FOR USE OF SHA256 DIGEST ETC.
FOR USE WITH V0.2 OF LOG2UDP

"""
import json
import logging
import socket
import struct
from pathlib import Path

from log2udp import LogUDP

# ################################# GLOBALS ######################
__VER__ = "v0.1 alpha"
UDP_SRC = ('<broadcast>', 6666)   # Socket listner address
LOGBASE = Path(Path.home(), '.logs')  # MAKE SURE THIS EXISTS
log_path = lambda fn: Path(LOGBASE, fn +'.log')
# ################################# FUNCTIONS ####################

def unpack(packet: bytes) -> str:
        """Unpack and length check UDP packet. Return data or '' """
        pkt_len, *_ = struct.unpack('>L', packet[:4])
        pkt_data = packet[4:]
        if len(pkt_data) == pkt_len:
            #print(f'length OK: {pkt_len}')
            return packet[4:].decode(encoding='UTF-8')
        print(f"Unpack Error: Print length should be {pkt_len} but found {len(pkt_data)}")
        return ''

def email_alert(critical_message: str):
    """ Send email e.g. if there is a CRITICAL error"""
    ...

def udp_send_data(data, addr):
    """Sends data (str, list, tuple, number, dict) to addr through sock via UDP in chunks"""
    def chunks(lump, size):
        "Yield successive n-sized chunks from lst"
        for i in range(0, len(lump), size):
            yield lump[i:i+size]

    _data = json.dumps(data).encode('utf-8')   # data as a bytes string
    _data_length = json.dumps(len(_data), default=str).encode('utf-8') # length in bytes as string
    udp_sock.sendto(_data_length, addr)
    # now send the data in 200 byte chunks
    for chunk in chunks(_data, 200):
        #print("Send: ", chunk, addr)
        udp_sock.sendto(chunk, addr)

def udp_logit(record: dict, address: tuple):
    """ Parse record received from 'address' and write to log as required """
    """  Typical command 'record' dict is:
    {"name": "testlogname", "record": "My log message", "levelname": "DEBUG", "levelno": 10, "filename": "__init__.py",
    "module": "__init__", "created": 1670063920.662804, "command": "LOG", "datefmt": "%Y-%m-%dT%H:%M:%S%z",
    "fmt": "%(name)s|%(levelname)-8s|%(asctime)s|%(message)s", ...}
    """
    global logger
    if not isinstance(record, dict):
        print(f"Log record is not a dict: {record}")
        return
    # Get the command. Log2udp inserts a "command" = "LOG" item in record dict
    _command = record['command'].upper()
    if _command == "LOG":
        # Create a custom logger
        if not logger:
            logger = logging.getLogger(__name__)
        # Dispose any current handlers if wrong name and make a new one
        if len(logger.handlers) == 0 or logger.handlers[0].name != record['name']:
            logger.handlers.clear()
            # Create file handler
            f_handler = logging.FileHandler(log_path(record['name']))
            f_handler.set_name(record['name'])
            logger.addHandler(f_handler)
        # set up handler
        logger.handlers[0].setLevel(logging.DEBUG)
        # Create formatters and add it to handlers
        f_format = logging.Formatter(record['fmt'], record['datefmt'])
        logger.handlers[0].setFormatter(f_format)
        # make the log record
        log_record = logging.makeLogRecord(record)
        # and send to log
        logger.handle(log_record)
        if record['levelno'] >= 50:   # This is critical or above
            alert_record = f"{record['hostapp']} - {log_record}" if 'hostapp' in record.keys() else log_record
            print(alert_record)
            email_alert(alert_record)
        ...
    elif _command == "FIND":
        """ Remote 'find' request.
        Typical command record dict is 
        {'command': 'FIND', 'text': '', 'logname': None, 'date': None, 'deltadays': -7,
          'level': 'NOTSET', 'ignorecase': True}
        """
        log_name = record['logname']
        if log_name:
            text = record['text']
            date = record['date']
            deltadays = record['deltadays']
            level = record['level']
            ignoreCase = record['ignorecase']
            # and search
            result = LogUDP.find(text=text, logname=log_name, date=date, deltadays=deltadays,
                        level=level, ignorecase=ignoreCase)
        else:
            result = ['Error: No logname provided.']
        if address is None:
            return result # testing
            #print('ADDR: {}'.format(Addr))
        udp_send_data(result, address)

    elif _command == "VER":
        """ Respond with listener version.  This can be used to show its working
            command dict is {"command": "VER"}
        """
        udp_send_data(__VER__, address)

    else:
        #Unknown command
        udp_send_data(f"Error: Unknown command received: '{_command}'", Addr)
        ...
    

# ################################# MAIN #########################
if __name__ == "__main__":
    # set up the UDP sockets

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as udp_sock:
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_sock.bind(UDP_SRC)
        # Create MT logger
        logger = None
        while True:
            _data, address = udp_sock.recvfrom(1024)
            #print(f"received message from {address}: {_data}")
            data = unpack(_data)
            _data = None
            if data:
                logpacket = json.loads(data)
                udp_logit(logpacket, address)
                data = None
