#!/usr/bin/env python3

'''
Ian Guibas

This module defines the behavior of the threaded server. Splitting the modules
makes them easier to maintain. This also helps maintain readability.
'''

from passlib.hash import bcrypt_sha256
from remoteInfo import remoteInfo
import socketserver
import ServerInfo
import getpass
import socket
import client
import Config

BUFSIZE = 2048
localInfo = None
connections = dict()

#============================================================[ Request Handler ]
class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    # Primary Handling Class
    def handle(self):
        '''Handle incoming requests
        This method is called on each remote connection made. The use of global
        is required to reference variables outside of its own scope. This allows
        for keeping track of the client between requests.
        '''
        
        msg = str(self.request.recv(BUFSIZE),'utf8')
        intent  = msg.split(':')[0]
        ip,port = msg.split(':')[1],int(msg.split(':')[2])
        
        # Add connection to dict and set up information
        if ip not in connections.keys():
            connections[ip] = remoteInfo()
            connections[ip].HOST = ip
            connections[ip].PORT = port


        # ---- HAND SHAKE INTENTS ---- #
        # Determine if this is an init:
        if intent == 'INIT_CONV':
            init_conv(ip,port)
            
        # Respond to INIT, connection establishment
        elif intent == 'INIT_ACK':
            init_ack(msg,ip,port)

        # Got a public key (Remote sent first)
        elif intent == 'PK_SEND':
            pk_send(msg,ip,port)

        # Got a public key (Server sent first)
        elif intent == 'PK_ACK':
            pk_ack(msg,ip,port)

        # Remote's proposed secret
        elif intent == 'SS_SET':
            ss_set(msg,ip,port)

        # Local acknowledging remote's secret
        elif intent == 'SS_ACK':
            ss_ack(msg,ip,port)
    
        
        # ---- CONVERSATIONAL INTENTS ---- #
        elif intent == 'MSG':
            pass

    def init_conn(self, ip, port):
        '''Handle the initial connection to client
        Sends INIT_ACK back to the connecting clients server to initiale key
        exhange and setup.
        '''
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock = socket.settimeout(0.0) # Non-blocking
        sock.connect((ip,port))

        intent = 'INIT_ACK:{0}:{1}:{2}'.format(localInfo.HOST,
                                               localInfo.PORT,
                                               len(localInfo.pubKey))
        sock.sendall(intent)

    def do_iack(msg,ip,port):
        klen = int(msg.split(':')[1])
        remoteInfo.pubkey = msg.split(':')[2]
        

#===============================================================[ Server Class ]
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

def start_server(serverInfo):
    # Grab and set the HOST and port from config
    global localInfo = serverInfo # saves to global
    PORT = serverInfo.PORT
    HOST = serverInfo.HOST

    # Create the server object and start the thread
    server = ThreadedTCPServer((HOST,PORT),ThreadedTCPRequestHandler)
    with server:
        ip,port = server.server_address

        # Start server thread
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True # Exit on main thread exit
        server_thread.start()
        print('Server started in thread:', serve_thread.name)
        print('Listening on port:', port)
        
        return server, server_thread
