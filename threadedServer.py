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
import knownUsers
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
    
        
        # ---- AUTHENTICATION INTENTS ---- # 

        elif intent == 'REQ_PASS':
            username = msg.split(':')[3]

        # ---- CONVERSATIONAL INTENTS ---- #
        elif intent == 'MSG':
            decrypt(msg,ip,port)

    def init_conv(self, ip, port):
        '''Handle the initial connection to client
        Sends INIT_ACK back to the connecting clients server to initiale key
        exhange and setup.
        '''
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(0.0) # Non-blocking
        sock.connect((ip,port))

        intent = 'INIT_ACK:{0}:{1}:{2}'.format(localInfo.HOST,
                                               localInfo.PORT,
                                               len(localInfo.pubKey))
        sock.sendall(intent)


    def init_ack(msg,ip,port):
        '''Handle receiving the init acknowledgement. Reply PK_SEND'''
        username = msg.split(':')[3]
        
        # Short cirtuit the handshake if this user is known
        if knownUsers.check(username):
            intent = 'REQ_PASS:{0}:{1}:{2}'.format(localInfo.HOST,
                                                   localInfo.PORT,
                                                   username)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.0)
            sock.sendall(intent)

        else:
            # Set user in information
            connections[ip].username = username
            intent = 'PK_SEND:{0}:{1}:{2}'.format(localInfo.HOST,
                                                  localInfo.PORT,
                                                  localInfo.pubKey)
            
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(0.0)
            sock.connect((ip,port))
            sock.sendall(intent)

    
    def pk_send(msg,ip,port):
        '''After receiving pk_send, do a pk_ack and supply own public key'''
        # Set remote public key
        pubkey = msg.split(':')[2]
        connections[ip].publicKey = pubkey
        
        # Socket setup
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(0.0)
        sock.connect((ip,port))
        
        # Craft intent
        intent = 'PK_ACK:{0}:{1}:{2}'.format(localInfo.HOST,
                                             localInfo.PORT,
                                             localInfo.pubKey)
        sock.sendall(intent)


    def pk_ack(msg,ip,port):
        '''Acknowledge pubkeys have been swapped, set up shared secret
           using the stored public key'''
    
        # Set remote pubkey
        pubkey = msg.split(':')[2]
        connections[ip].publicKey = pubkey

        # Set up socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.0)
        sock.connect((ip,port))
        
        # Generate the IV and KEY as random 16 bytes
        Key = os.urandom(16)
        IV  = os.urandom(16)
        
        # Store values locally for this connection
        connections[ip].IV = IV
        connections[ip].Key = Key

        # Encrypt the IV and Key with remote party's public key
        eKey = connections[ip].publicKey.encrypt(Key)
        eIV  = connections[ip].publicKey.encrypt(IV)

        # Send off intent
        intent 'SS_SET:{0}:{1}:{2}:{3}'.format(localInfo.HOST,
                                               localInfo.PORT,
                                               eIV,
                                               eKey)
        sock.sendall(intent)


    def ss_set(msg,ip,port):

        # Socket Creation
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(0.0)
        sock.connect((ip,port))
        
        # Get IV and Key
        cIV = msg.split(':')[2]
        cKey = msg.split(':')[3]
        pIV = localInfo.privKey.decrypt(cIV)
        pKey = localInfo.privKey.decrypt(cKey)

        # Store for remote connection
        connections[ip].IV  = pIV
        connections[ip].Key = pKey

        # Encrypt with remote pubkey and send for verification
        sKey = connections[ip].publicKey.encrypt(pKey)
        sIV  = connections[ip].publicKey.encrypt(pIV)

        intent = 'SS_ACK:{0}:{1}:{2}:{3}'.format(localInfo.HOST

    def req_pass(username,ip,port):
        print('Password requested by {0}:{1} for user: {3}'.format(ip,
                                                            port,
                                                            username)
        pw = bcrypt_sha256(getpass.getpass('Password: '))
        intent = 'PASS_ACK:{0}:{1}:{2}:{3}'.format(username,pw)

        # Socket creation
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(0.0)
        sock.connect((ip,port))
        sock.sendall(intent)
    

    def pass_ack(msg,ip,port):
        
        # Parse uname and password hash
        username = msg.split(':')[2]
        passhash = msg.split(':')[3]
        
        # Check if user exists:
        if knownUsers.check(username):
            '''user exists, check pass and set values'''
            
            if passhash == user.getPass(username):
                '''password matches record, set vals'''
                
                connections[ip].username = username
                connections[ip].password = passhash

                if knownUsers.getPubKey(username) is not None:
                    connections[ip].publicKey = knownUsers.getPubKey(username)
                
                elif knownUsers.getPubKey(username) == 'FindFailure':
                    knownUsers.pkError(username)
                    return
                else:
                    print('Something very unexpected went wrong...')
                    print('Check that the known_hosts file exists' +
                          ' and has not been tampered with.')
                    print('Please check that the rsa key for the requested ' +
                          'user also exists.')
                    return
            else:
                req_pass(user,ip,port)
        
        else:
            '''If the user does not exist in known_hosts...'''
            knownUsers.creatUser(username,passhash,connections[ip].publicKey)
            # Creates the new user
            # Finishes the handshake
            
            intent = 'CON_FIN:{0}:{1}'.format(localInfo.HOST, localInfo.PORT)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.0)
            sock.connect((ip,port))
            sock.sendall(intent)


    def con_fin(msg,ip,port):
        print('Connection established with {0}:{1}'.format(ip,port))
        global currcon = (ip,port)    

    def msg_decrypt(msg,ip,port):
        '''Decrypt and display an instant message'''
        IV = connections[ip].IV
        Key = connections[ip].Key
        nick = connections[ip].username

        # MSG:IP:PORT:Message <- Intent
        msg = msg.split(':')[3]

        decryptor = AES.new(Key ,AES.MODE_CBC, IV)
        msg = decryptor.decrypt(msg)

        print(nick + ':',msg)



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
