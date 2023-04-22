#! /usr/bin/env python3
"""
This applet is a minimal framework example of a UDP listener.
It uses separate threads and queues to
  * receive and decode udp packet and write to receive_Q
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

from ascon import ascon
from dateutil import parser

from MDPLibrary.log2d.log2d import Log, logging
#from log2d import Log, logging
# NOTE: YOU NEED A VERSION OF LOG2D THAT INCLUDES 'find'
# and this ~may~ not be the PIP package yet!
# See https://github.com/PFython/log2d

__VER__ = 'udp_listener v0.4' # Version string

# ############################ CONSTANTS ########################
BUFSIZE = 4096  # Socket buffer size
LOGBASE = Path(os.environ['HOME'], '.logs')   # Base folder for logs
UDP_SRC = ('<broadcast>', 6666)   # UDP listener address:port
SECRET = "M15ecret"   # key for encryption
LOGSIZE = 1024 * 1024  # 1MB before log rotate
LOGGERS = {}   # Dict of active loggers

# ############################# GLOBAL FUNCTIONS ################

full_path = lambda fn: Path(LOGBASE, fn +'.log')

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
    """ASCON1.2 encryption.  Plaintext: str, key: str will hashed to 16 bytes.
        Returns: string of hex characters
    """
    # Fix key and convert to bytes
    _key = hashlib.md5(key.encode('utf-8')).digest()
    #Convert plaintext to byte
    plaintext_bytes = plaintext.encode('utf-8')
    # Generate a random 16 byte nonce
    nonce = ascon.get_random_bytes(16)
    # Encrypt plaintext with key and nonce
    ciphertext = ascon.ascon_encrypt(_key, nonce, b"", plaintext_bytes)
    # Append the nonce to the ciphertext
    encrypted_message = nonce + ciphertext
    # Convert encrypted message bytes to string of hex
    return encrypted_message.hex()  # string of hex characters

def asc_decrypt(encrypted_message_hex:str, key:str) -> str:
    """ASCON1.2 decryption. encrypted_message_hex: str, key: str will hashed to 16 bytes.
        Returns: str
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
        plaintext_bytes = ascon.ascon_decrypt(_key, nonce, b"", ciphertext)
    except ValueError:
        raise ValueError("Decryption failed - message has been tampered with")
    # Convert plaintext bytes to string
    return plaintext_bytes.decode()  # String

def udp_listener(queue, secret):
    """Thread to continually listen for UDP messages.  These are 'unpacked'
    then put on the receive queue for future processing.
    """
    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(UDP_SRC)

        while True:
            # Receive data from the socket
            data, address = sock.recvfrom(BUFSIZE)
            queue.put((data, address))   # put raw message on Q

def message_handler(queue, response_queue):
    """Handle messages.  Read message from the receive queue passes it to
       a new thread for processing.
    """
    while True:
        # Get data from the queue
        encrypted_msg, address = queue.get()

        # Start message handler thread
        message_thread = threading.Thread(target=handle_message,
                                args=(encrypted_msg, address, response_queue))
        message_thread.start()

def get_logger(log_name):
    """Returns a logger for this file. If a logger for this file doesn't exist, generates one."""
    # check if the logger for this log name has already been created
    if log_name not in LOGGERS:
        logger = logging.getLogger(log_name)
        logger.setLevel(logging.DEBUG)
        # create a rotating file handler
        handler = logging.handlers.RotatingFileHandler(f"{log_name}.log",
                                                        maxBytes=LOGSIZE, backupCount=5)
        handler.setLevel(logging.DEBUG)
        # add the handlers to the logger
        logger.addHandler(handler)
        # store the logger for reuse
        LOGGERS[log_name] = logger
    return LOGGERS[log_name]  # retrieve the logger from the loggers dict

def handle_message(encrypted_msg, address, response_queue):
    """Handle the message:  Log any log messages and respond
       to any other handlable requests
    """
    # decrypt message here
    msg = json_decode(encrypted_msg, SECRET)
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
            logging.addLevelName(msg['levelno'], msg['levelname'] )
        # and send to log
        logger.handle(log_record)
        if msg['levelno'] >= 50:   # This is critical or above
            ... # send suitable email alert
            # or add SMTPHandler also

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

def response_sender(response_queue):
    """Sends data (str, list, tuple, number) to addr through sock via UDP"""
    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        while True:
            # Get the response from the queue
            response, address = response_queue.get()
            response_bytes = json_encode(response, SECRET)
            # break the data into chunks
            chunks = [response_bytes[i:i+BUFSIZE] for i in range(0, len(response_bytes), BUFSIZE)]
            # send the total length of the data as a 4-byte unsigned integer
            total_length = len(response_bytes)
            sock.sendto(struct.pack('>L', total_length), address)

            # send each chunk separately
            for chunk in chunks:
                sock.sendto(chunk, address)

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
    sender_thread = threading.Thread(target=response_sender, args=(response_queue))
    sender_thread.start()

    """
    Probably should add watchdog to detect thread dying
    and fix or warn user.
    while True:
        sleep(1)
        if not listener_thread.is_alive():
            ??? etc.
    """
