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
    generally, of two messages: an intent, and content.

    The method in which the connection is handled depends on the intent. During
    initial connection, the INIT_CONVERSATION intent will be sent. Upon
    recieving this, the client will do two things: first check for the existance
    of a known_hosts file and see if it contains the IP of the remote client in
    which case, that clients public key would be loaded from the file for
    encrypting all further communication. The server then responds with either
    KEY_FOUND or KEY_NEEDED

    I'll break the response up based on intent:
        INIT_CONV:
            This is sent at the beginning of transmission and prompts the user
            for their public key. This is done by sending the KEY_REQ intent
            back to the other user.
        KEY_REQ:
            The remote server is requesting an rsa public_key to use for the
            remainder of this session. Forcing a new key per session eliminates
            key reuse though for practicality's sake I would like to eventually
            have keys cached dependent upon some sort of secret that is agreed
            upon on initial connection
    '''
    def handle(self):
        '''
        This does the bulk of the handling
        '''
        # Attempt to get intent
        c_intent = str(self.request.recv(32),'utf8')
        
        # Determine what to do based on intent:
            
    

        # Respond
        

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


#================================ Remote Server ===============================#
class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def msgSend(self, msg, serv):
        # Create a socket to use
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host,self.port))

        # Calculate message length and send intent
        m_len = len(msg)
        s.send('MSG_SEND {0}'.forat(m_len))
    
        # Send the message
        s.send(msg)


#================================ Client Part =================================#
class client:

    def __init__(self, rsa):
        self.rsa = rsa

class message:

    def __init__(self, content, rsa):
        self.content = content
        self.rsa = rsa

    def encrypt(self):
        m = base64.b64encode(bytes(self.content,'utf8'))
        self.content = self.rsa.encrypt(m,1)

    def decrypt(self):
        m = bytes.decode(base64.b64decode(self.rsa.decrypt(self.content)),'utf8')
        self.content = m

#==================================== Main ====================================#
if __name__ == '__main__':

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
                    rserver = Server(host,port)
                    print('Connecting to: {0}:{1}'.format(host,port))
                except IndexError as e:
                    print('You must supply a port') # For now no default port
                    
        else:
            # process and send the message
            pass
