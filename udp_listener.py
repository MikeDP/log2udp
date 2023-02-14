#! /usr/bin/env python3

"""
This applet is a minimal framework example of a UDP listener.
It uses separate threads and queues to 
  * receive and decode udp packet and write to receeve_Q
  * pull packets from receive_Q and handle them
  * place any respnse on response_Q
  * pull responses from response_Q, encode and transmit back to client

"""

import hashlib
import json
import os
import socket
import struct
import threading
from datetime import datetime
from pathlib import Path
from queue import Queue

from dateutil import parser

from log2d import Log, logging
# NOTE: YOU NEED A VERSION OF LOG2D THAT INCLUDES 'find'
# and this ~may~ not be the PIP package yet!  
# See https://github.com/PFython/log2d

__VER__ = 'udp_listner v0.2' # Version string

# ############################ CONSTANTS ########################
LOGBASE = Path(os.environ['HOME'], '.logs')   # Base folder for logs
UDP_SRC = ('<broadcast>', 6666)   # UDP listener address:port
SECRET = "Your5ecret"   # SALT for haslib
LOGSIZE = 1024 * 1024  # 1MB before log rotate
LOGGERS = {}   # Dict of active loggers

# ############################# GLOBAL FUNCTIONS ################

full_path = lambda fn: Path(LOGBASE, fn +'.log')

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
    # Extract the length from the beginning of the packet
    length = struct.unpack('!i', data[:4])[0] + 4
    # Check the length of the data
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

def udp_listener(queue, secret):
    """Thread to continually listen for UDP messages.  These are 'unpacked'
    then put on the receive queue for future processing.
    """
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(UDP_SRC)

    while True:
        # Receive data from the socket
        data, address = sock.recvfrom(4096)
        # Unpack it
        message_data = json_decode(data, secret)
        if message_data:
            # Put the received data and address into the queue as tuple
            queue.put((message_data, address))

def message_handler(queue, response_queue):
    """Handle messages.  Read message from the receive queue passes it to
       a new thread for processing.
    """
    while True:
        # Get data from the queue
        data, address = queue.get()

        # Start message handler thread
        message_thread = threading.Thread(target=handle_message, args=(data, address, response_queue,))
        message_thread.start()

def get_logger(log_name):
    """Returns a logger for this file. If a logger for this file doesn't exist, generates one."""
    # check if the logger for this log name has already been created
    if log_name not in LOGGERS:
        logger = logging.getLogger(log_name)
        logger.setLevel(logging.DEBUG)
        # create a rotating file handler
        handler = logging.handlers.RotatingFileHandler(f"{log_name}.log", maxBytes=LOGSIZE, backupCount=5)
        handler.setLevel(logging.DEBUG)
        # add the handlers to the logger
        logger.addHandler(handler)
        # store the logger for reuse
        LOGGERS[log_name] = logger
    return LOGGERS[log_name]  # retrieve the logger from the loggers dict

def handle_message(msg, address, response_queue):
    """Handle the decoded message:  Log any log messages and respond
       to any other handlable requests
    """
    if not isinstance(msg, dict):
        print(f"msg is not a dict: {msg}")
        return
    # Get the command
    _cmd = msg['command'].upper()

    if _cmd == "LOG":   # Just log the data
        # Get custom logger
        logger = get_logger(msg['name'])
        # Create formatters and add it to handlers
        f_format = logging.Formatter(msg['fmt'], msg['datefmt'])
        logger.handlers[0].setFormatter(f_format)
        # make the log record
        log_record = logging.makeLogRecord(msg)
        # Check level we need exists and add if needed
        if not msg["levelname"] in logging._nameToLevel:
            logging.addLevelName(msg['levelname'], msg['levelno'])
        # and send to log
        logger.handle(log_record)
        if msg['levelno'] >= 50:   # This is critical or above
            ... # send suitable email alert
            # or alternatively add SMTPHandler

    elif _cmd == "FIND":   # Search a log
        # get params
        log_name = msg['name']
        if log_name:
            _lname = full_path(log_name)
        else:
            _lname = msg['path']
        if _lname:
            _txt = msg['text']
            _date = msg['date']
            if not _date:
                _date = datetime.now()
            if isinstance(_date, str):
                _date = parser.parse(_date)
            _deltadays = msg['deltadays']
            _level = msg['level']
            _ignorecase = msg['ignorecase']
            # and search
            try:
                result = Log('').find(text=_txt, path=_lname, date=_date, deltadays=_deltadays,
                            level=_level, ignorecase=_ignorecase)
            except Exception as excpt:
                result = [f'Error: {excpt}']
        else:
            result = ['Error: No logname provided.']
        response_queue.put((result, address))

    elif _cmd == "VER":
        # Respond with UDPLogger version.  This can be used to show its working
        response_queue.put((__VER__, address))


def response_sender(response_queuelogger):
    """Sends data (str, list, tuple, number) to addr through sock via UDP"""
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        # Get the response from the queue
        response, address = response_queue.get()
        response_bytes = json_encode(response, SECRET)
        sock.sendto(response_bytes, address)

# ################################# MAIN #########################

if __name__ == '__main__':
    # Create a queue for received messages
    received_queue = Queue()

    # Create a queue for responses
    response_queue = Queue()

    # Start the listener thread
    listener_thread = threading.Thread(target=udp_listener, args=(received_queue, SECRET))
    listener_thread.start()

    # Start the message handler thread
    handler_thread = threading.Thread(target=message_handler, args=(received_queue, response_queue))
    handler_thread.start()

    # Start the response sender thread
    sender_thread = threading.Thread(target=response_sender, args=(response_queue,))
    sender_thread.start()

    """
    Probably should add watchdog to detect thread dying
    and fix or warn user.
    while True:
        sleep(1)
        if not listener_thread.is_alive():
            ??? etc.
    """