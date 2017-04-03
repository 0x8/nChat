#!/usr/bin/env python3

'''
    Ian Guibas
    
    nChat seeks to provide a CLI-based encrypted Instant Messaging platform
    between two peers.

    Each chat "client" will also be its own server. The only requirement that
    two clients should have in order to talk to eachother is that they be able
    to connect to eachother. This naturally requires either public IP or
    a presence on the same virtual network.
'''
from Crypto.Util import number # pycrypto
from Crypto.PublicKey import RSA
import socketserver
import textwrap
import hashlib
import socket
import random
import base64
import math
import sys
import os

# Global INTENTS set
'''
Intents signify what the client wants the server to do and allow the server to
respond or act accordingly.

Intents
--------

INIT_CONV:
    Sent at conversation start, this signifies the beginning of a conversation.
    Additional metadata may be sent to signify that the two have chatted before
    and an attempt should be made to authenticate the connecting client

MSG_SEND:
    The basic intent signifying that a message is about to be sent. This is sent
    along with the length of the message so that the recieving end knows not to
    kill the connection to early and/or can respond with an error after a set
    timeout.

DHS:
    This signifies that the server should start the Diffie-Hellman key exchange
    to generate a shared secret to be used with the session. In this program, an
    8 byte key is used.

DHV:
    This is sent after the key exchange to verify that the key has been
    successfully shared between the two parties. For security purposes, the
    public key of the other party is used to encrypt the message then decrypted
    and encrypted again with the senders key. If both send back DH_OK, the
    generation was successful.

PKC:
    This signifies that a public key change is needed. This is to manually
    retire old public keys and allow the use of fresh ones. Requires
    authentication.

NSS:
    This tells the server to restart the Diffi-Hellman process to create a new
    shared secret. If the old secret is too old or believed compromised, this
    allows the quick generation of a new one.

UAUTH:
    This is for basic user authentication. Password is hashed with
    bcrypt-sha256 and stored along with user's desired username.
'''
intents = {'INIT_CONV','MSG_SEND','DHS','PKC','PKR','NSS','UAUTH'}



#=============================== RSA Encryption ===============================#
'''
This section deals with the creation of the RSA object responsible for
encryption and decryption on this end. This allows the distribution of this
"client's" public key to the other party as well as decrypt the messages from
the other party.
'''
def gen_rsa(n):
    '''
    This function generates an n-bit rsa object. Note that this object comes from
    the PublicKey.RSA class of pycrypto and is generated containing e,d,p,q, and
    u. It does NOT generate n, you must be explicitly generate and check it.
    '''
    rsa = RSA.generate(n)
    return rsa

#============================= Message Encryption =============================#

#=============================== Server Portion ===============================#
'''
Using a threaded server allows the program to both send and recieve
asynchronously. This asynchronous nature allows it to act as an IM client.
'''

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    '''
    This class is called whenever the threaded server recieves a connection and
    needs to handle the data. In my scheme, each send will be comprised,
    generally, of two messages: an intent, and content. The method in which the
    connection is handled depends on the intent.
    '''
    def handle(self):
        '''
        This does the bulk of the handling
        '''
        # Attempt to get intent
        c_intent = str(self.request.recv(32),'utf8')
        
        # Determine what to do based on intent:
        if 
    

        # Respond
        

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

#================================ Client Part =================================#
class Client:
    def __init__(self, host, port, rsa, p_c=None):
        self.host = host
        self.port = port
        self.rsa  = rsa
        self.3des = 
        # If not previously connected run the handshake
        if not p_c:
            # Initial RSA handshake
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    def msgSend(self, msg, serv):
        
        # Create a socket to use
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            s.connect((self.host,self.port))

            # Calculate message length and send intent
            m_len = len(msg)
            s.sendall(r'MSG_SEND {0}'.forat(m_len))
    
            # Send the message
            s.send(msg)


#==================================== Main ====================================#
if __name__ == '__main__':
        
    # Initalize local server thread and dispatch it
    PORT = 31333
    server = ThreadedTCPServer(('0.0.0.0',PORT))
    with server:
        ip, port = server.server_address

        # Start the server thread
        server_thread = theading.Thread(target=server.serve_forever)
        server_thread.daemon = True # Exit server when main thread exits
        server_thread.start()
        print('Started server in thread:', server_thread.name)
        print('Listening on port:',port)


    n = int(input('Number of bits to use: '))
    rsa = RSA.generate(n)
    m = message('This is a test message', rsa)
    
    print(textwrap.dedent('''
          [nChat]
          This is an encrypted peer-to-peer IM service. To connect to a peer,
          please do '/connect <host> <port> [<auth_token>]. For more information
          type '/help' or '/?'.
          '''))
    
    choice = input(textwrap.dedent('''
                To use an existing key, please specify the path to it. To use a 
                new one, leave blank: '''))

    
    rserver = None # Initially the remote server is set to None
                   # Gets set on a connection command

    while True:
        # Get command or message
        msg = input('>> ')

        # Determine if message is a command
        if msg.startswith('/'):
            cmd = msg.split(' ')[0].split('/')[1]
            # If we got connect command, create a new object to use
            # for this connection
            if cmd == 'connect':
                try:
                    # Attempt to parse the data
                    host = msg.split(' ')[1]
                    port = int(msg.split(' ')[2])
                    rserver = Client(host,port,rsa)
                    print('Connecting to: {0}:{1}'.format(host,port))
                except IndexError as e:
                    print('You must supply a port') # For now no default port
                    
        else:
            # process and send the message
            pass
