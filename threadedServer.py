#!/usr/bin/env python3

'''
Ian Guibas

This module defines the behavior of the threaded server. Splitting the modules
makes them easier to maintain. This also helps maintain readability.
'''

from passlib.hash import bcrypt_sha256
from remoteInfo import remoteInfo
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import socketserver
import knownUsers
import threading
import binascii
import logging
import getpass
import base64
import socket
import client
import Config
import os

BUFSIZE = 4096
localInfo = None
connections = dict()

global currcon
currcon = None

# For key verification
myKey = None
myIV  = None

# For determining if handshake is occuring
global inHandshake
inHandshake = False

# Getting root logger for config purposes
logging.getLogger()

class server:

    def __init__(self,ip,port):
        if not isinstance(port,int):
            try:
                self.port = int(port)
            except ValueError as e:
                print(e)
                print('Invalid format for port. Must be int')
        self.port = port
        self.ip = ip


    def serve(self):
        # Create the server socket and bind to the configured IP and port
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        server.bind((self.ip,self.port))
        
        # Start listening, accept incoming connections and pass them to handle
        server.listen(5)
        while True:
            conn, addr = server.accept()
            logging.info('Accepted connection from {0}'.format(addr))
            self.handle(conn)
            conn.close()

#============================================================[ Request Handler ]


    # Primary Handling Class
    def handle(self,conn):
        '''Handle incoming requests
        This method is called on each remote connection made. The use of global
        is required to reference variables outside of its own scope. This allows
        for keeping track of the client between requests.
        '''
        
        MSG = conn.recv(BUFSIZE)
        msg = str(MSG,'utf8')
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
            inHandshake = True
            self.init_conv(msg,ip,port)
            
        # Respond to INIT, connection establishment
        elif intent == 'INIT_ACK':
            self.init_ack(msg,ip,port)

        # Got a public key (Remote sent first)
        elif intent == 'PK_SEND':
            self.pk_send(msg,ip,port)

        # Got a public key (Server sent first)
        elif intent == 'PK_ACK':
            self.pk_ack(msg,ip,port)

        # Remote's proposed secret
        elif intent == 'SS_SET':
            self.ss_set(msg,ip,port)

        # Local acknowledging remote's secret
        elif intent == 'SS_ACK':
            self.ss_ack(msg,ip,port)
    
        
        # ---- AUTHENTICATION INTENTS ---- # 

        elif intent == 'REQ_PASS':
            self.req_pass(msg,ip,port)
        
        elif intent == 'KNOWN_AUTH':
            self.known_auth(msg,ip,port)

        elif intent == 'PASS_ACK':
            self.pass_ack(msg,ip,port)

        elif intent == 'CON_FIN':
            self.con_fin(msg,ip,port)

        # ---- CONVERSATIONAL INTENTS ---- #
        elif intent == 'MSG':
            self.mdecrypt(msg,ip,port)


    def init_conv(self, msg, ip, port):
        '''Handle the initial connection to client
        Sends INIT_ACK back to the connecting clients server to initiale key
        exhange and setup.
        '''
        
        # Pull and set remote username:
        username = msg.split(':')[3]
        connections[ip].username = username

        # Craft intent 
        intent = 'INIT_ACK:{0}:{1}:{2}'.format(localInfo.HOST,
                                               localInfo.PORT,
                                               localInfo.username)
        
        # handshake
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.connect((ip,port))
            sock.sendall(bytes(intent,'utf8'))


    def init_ack(self,msg,ip,port):
        '''Handle receiving the init acknowledgement. Reply PK_SEND'''
        
        # Grab username
        username = msg.split(':')[3]
        
        # Short circuit doesn't work well right now
        """
        # Short cirtuit the handshake if this user is known
        if knownUsers.check(username):
            intent = 'REQ_PASS:{0}:{1}:{2}'.format(localInfo.HOST,
                                                   localInfo.PORT,
                                                   username)
           
            # Socket
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
                sock.connect((ip,port))
                sock.sendall(bytes(intent,'utf8'))
        """
        #else:
        # Set user in information
        connections[ip].username = username
        intent = 'PK_SEND:{0}:{1}:{2}'.format(localInfo.HOST,
                                            localInfo.PORT,
                                            str(localInfo.publickey,'utf8'))
        
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.connect((ip,port))
            sock.sendall(bytes(intent,'utf8'))
    
    def pk_send(self,msg,ip,port):
        '''After receiving pk_send, do a pk_ack and supply own public key'''
        
        # Set remote public key
        pubkey = msg.split(':')[3]
        connections[ip].publicKey = RSA.importKey(pubkey,'PEM')
        
        # Craft intent
        intent = 'PK_ACK:{0}:{1}:{2}'.format(localInfo.HOST,
                                             localInfo.PORT,
                                             str(localInfo.publickey,'utf8'))
        
        # Socket setup
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.connect((ip,port))
            sock.sendall(bytes(intent,'utf8'))


    def pk_ack(self,msg,ip,port):
        '''Acknowledge pubkeys have been swapped, set up shared secret
           using the stored public key'''
    
        # Set remote pubkey
        pubkey = msg.split(':')[3]
        connections[ip].publicKey = RSA.importKey(pubkey)

        # Generate the IV and KEY as random 16 bytes
        Key = os.urandom(16)
        IV  = os.urandom(16)
        
        # Store values locally for this connection
        connections[ip].IV  = bytes(IV)
        connections[ip].key = bytes(Key)
        
        cinfo = str(connections[ip])
        logging.debug('Client Information:\n' + cinfo)

        global myKey
        global myIV
        myKey = Key
        myIV  = IV

        # Encrypt the IV and Key with remote party's public key
        eKey = connections[ip].publicKey.encrypt(Key,'')[0]
        eIV  = connections[ip].publicKey.encrypt(IV,'')[0]

        # Encode key and IV in base64 and conver to str
        eKey = base64.b64encode(eKey)
        eIV  = base64.b64encode(eIV)
        eKey = str(eKey, 'utf8')
        eIV  = str(eIV,  'utf8')
       
        # Send off intent
        intent = 'SS_SET:{0}:{1}:{2}:{3}'.format(localInfo.HOST,
                                                 localInfo.PORT,
                                                 eIV,
                                                 eKey)

        # Set up socket
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock: 
            sock.connect((ip,port))
            sock.sendall(bytes(intent,'utf8'))
    

    def ss_set(self,msg,ip,port):

        # Get IV and Key
        cIV  = msg.split(':')[3]
        cKey = msg.split(':')[4]
        
        # Convert back from base64 and decrypt
        pIV  = localInfo.privKey.decrypt(base64.b64decode(cIV))
        pKey = localInfo.privKey.decrypt(base64.b64decode(cKey))

        # Store for remote connection
        connections[ip].IV  = pIV
        connections[ip].key = pKey

        # Encrypt with remote pubkey and send for verification
        sKey = connections[ip].publicKey.encrypt(pKey,'')[0]
        sIV  = connections[ip].publicKey.encrypt(pIV,'')[0]

        sKey = str(base64.b64encode(sKey),'utf8')
        sIV  = str(base64.b64encode(sIV),'utf8')

        intent = 'SS_ACK:{0}:{1}:{2}:{3}'.format(localInfo.HOST,
                                                 localInfo.PORT,
                                                 sKey,
                                                 sIV) 
        
        # Socket Creation
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.connect((ip,port))
            sock.sendall(bytes(intent,'utf8'))



    def ss_ack(self,msg,ip,port):
        '''On receiving SS_ACK establish the connection'''
        
        # Parse out base64 parts
        cKey = msg.split(':')[3]
        cIV  = msg.split(':')[4]
        
        # Decrypt them
        pKey = localInfo.privKey.decrypt(base64.b64decode(cKey))
        pIV  = localInfo.privKey.decrypt(base64.b64decode(cIV))

        # Test for equality to expected values
        # This basically ensures that what was sent is what was received
        if not pKey == myKey or not pIV == myIV:
            print('Key and IV potentially not the same')
            print('Printing them for manual inspection')
            print('pKey:',pKey)
            print('myKey:',myKey)
            print('pIV:',pIV)
            print('myIV:',myIV)
            # FIX ME: abort connection on bad key

        else:
            print('Key exchange verified. Requesting password')
       
        # Get username to check for knonw user
        username = connections[ip].username
        
        # Check if user exists:
        if knownUsers.check(username):
            '''user exists, check pass to set values'''

            logging.debug('Entered user exists state')

            # Get salt
            salt = knownUsers.getSalt(username)
            logging.debug('Using Salt: {0}'.format(salt))

            # Craft and send intent to auth a known user
            intent = 'KNOWN_AUTH:{0}:{1}:{2}:{3}'.format(localInfo.HOST,
                                                         localInfo.PORT,
                                                         username,
                                                         salt)

            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
                sock.connect((ip,port))
                sock.sendall(bytes(intent,'utf8'))
            
            return

        else:
            username = connections[ip].username
            intent = 'REQ_PASS:{0}:{1}:{2}'.format(localInfo.HOST,
                                                localInfo.PORT,
                                                username)
            
            # Socket creation and sendoff
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
                sock.connect((ip,port))
                sock.sendall(bytes(intent,'utf8'))
 
 
 
    def known_auth(self,msg,ip,port):
        '''Deal with a request for a password for a KNOWN user'''
        # Get the username and set the salt
        username = connections[ip].username
        salt = msg.split(':')[4]
            
        logging.debug('Bcrypting with salt: {0}'.format(salt))

        print('Password requested by {0}:{1} for known user: {2}'.format(ip,
                                                                    port,
                                                                    username))
        
        # Prompt for the password:
        prompt = 'Press ENTER then enter password: '
        pw = ''
        while pw == None or pw == '':
            pw = getpass.getpass(prompt)
            logging.debug('PLAINTEXT: {0}'.format(pw))
            pw = bcrypt_sha256.using(salt=salt).hash(pw)
            if pw == '' or pw == None:
                print('Password is empty, perhaps you hit ENTER too many times')

    
        # Encrypt password with AES:
        pw = self.encrypt(ip,pw)

        # Convert to base64 and str
        pw = str(base64.b64encode(pw),'utf8')

        logging.debug('Encrypted Hash: {0}'.format(pw))
        
        intent = 'PASS_ACK:{0}:{1}:{2}:{3}'.format(localInfo.HOST,
                                                   localInfo.PORT,
                                                   username,
                                                   pw)
        
        # Send it off for the server to handle
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((ip,port))
            sock.sendall(bytes(intent,'utf8'))



    def req_pass(self,msg,ip,port):
        '''Deal with a request for a password for a NEW user''' 
        username = connections[ip].username
        print('Password requested by {0}:{1} for new user: {2}'.format(ip,
                                                                   port,
                                                                   username))
                
        # Get password       
        logging.debug('First time password creation')
        passwordPrompt = 'Press ENTER then enter password: '
        pw = ''
        while pw == '' or pw == '':
            pw = getpass.getpass(passwordPrompt)
            logging.debug('PLAINTEXT: {0}'.format(pw)) 
            pw = bcrypt_sha256.hash(pw)
            logging.debug('HASH: {0}'.format(pw))

            if pw == '' or pw == None:
                print('Password is empty, perhaps you hit ENTER too many times')

        # Encrypt password with AES:
        pw = self.encrypt(ip,pw)
        
        logging.debug('Encrypted Hash: {0}'.format(pw))

        # Convert to base64 and str
        pw = str(base64.b64encode(pw),'utf8')

        intent = 'PASS_ACK:{0}:{1}:{2}:{3}'.format(localInfo.HOST,
                                                   localInfo.PORT,
                                                   username,
                                                   pw)
        
        # Socket creation
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.connect((ip,port))
            sock.sendall(bytes(intent,'utf8'))
    


    def pass_ack(self,msg,ip,port):
        
        logging.debug('Entered PASS_ACK')

        # Parse uname and password hash
        username = msg.split(':')[3]
        passhash = msg.split(':')[4]

        logging.debug('b64 Hash: {0}'.format(passhash))

        # Convert back from base64 and decrypt
        passhash = base64.b64decode(passhash)
        passhash = self.decrypt(ip,passhash)
        
        logging.debug('Decrypted Hash: {0}'.format(passhash))
        
        if knownUsers.check(username):
                
            logging.debug('Entered known user state')
            logging.debug('Salt: {0}'.format(knownUsers.getSalt(username)))
            logging.debug('Hash: {0}'.format(knownUsers.getPass(username)))   
            
            # For debugging purposes
            val = passhash == knownUsers.getPass(username)
            logging.debug('Hash check: {0}'.format(val))
            
            if passhash == knownUsers.getPass(username):
                '''password matches record, set vals'''
                
                connections[ip].username = username
                connections[ip].password = passhash
                
                # If key is found...
                if knownUsers.getPubKey(username) is not None:
                    connections[ip].publicKey = knownUsers.getPubKey(username)
                 
                    # Sets the current connection server side
                    currcon = (ip,port)
                    
                    logging.debug('Set currcon and setting flag to false')
                    intent = 'CON_FIN:{0}:{1}'.format(localInfo.HOST, 
                                                      localInfo.PORT)

                    with socket.socket(socket.AF_INET, 
                            socket.SOCK_STREAM) as sock:
                        
                        sock.connect((ip,port))
                        sock.sendall(bytes(intent,'utf8'))
                    
                    # Free the client
                    inHandshake = False

                    return

                # Something broke and I don't know what
                else:
                    print('Something very unexpected went wrong...')
                    print('Check that the known_hosts file exists' +
                          ' and has not been tampered with.')
                    print('Please check that the rsa key for the requested ' +
                          'user also exists.')
                    return
            
            else:
                salt = knownUsers.getSalt(username)
                self.req_pass(username,ip,port)
        
        else:
            '''If the user does not exist in known_hosts...'''
            knownUsers.createUser(username,passhash,connections[ip].publicKey)
            # Creates the new user
            # Finishes the handshake
            
            logging.debug('Created new user')

            # Sets the current connection server side
            currcon = (ip,port)
            
            logging.debug('currcon: {0}'.format(currcon))

            intent = 'CON_FIN:{0}:{1}'.format(localInfo.HOST, localInfo.PORT)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((ip,port))
                sock.sendall(bytes(intent,'utf8'))
            
            est_msg  = 'Connection established with '
            est_msg += '{0}:{1}'.format(ip,port)
            logging.debug(est_msg)
            inHandshake = False



    def con_fin(self,msg,ip,port):
        print('Connection established with {0}:{1}'.format(ip,port))
        global currcon
        currcon = (ip,port)
        inHandshake = False



    def mdecrypt(self,msg,ip,port):
        '''Decrypt and display an instant message'''
        IV = connections[ip].IV
        Key = connections[ip].key
        nick = connections[ip].username

        # MSG:IP:PORT:Message <- Intent
        msg = msg.split(':')[3]
        
        print('Encrypted MSG:',msg)
        
        decryptor = AES.new(Key ,AES.MODE_CBC, IV)
        msg = decryptor.decrypt(msg)

        print(nick + ':',msg)

    
    #===============[ Server Crypto Methods ]===============#
    def lpad(self,msg):
        '''This method will pad the message with nullbytes for encryption with
        AES'''
        padlen = (16 - len(msg)) % 16
        padchar = '\x00' # Allow easily changing this
        msg = padchar*padlen + msg # pad to the left of the message
        return msg


    def unpad(self,msg):
        return msg.strip(b'\x00')


    def decrypt(self,ip,msg):

        # Get key and IV then create decryptor object
        aesIV  = connections[ip].IV
        aesKey = connections[ip].key
        decryptor = AES.new(aesKey, AES.MODE_CBC, aesIV)

        # Decrypt message then remove padding
        msg = decryptor.decrypt(msg)
        msg = self.unpad(msg)
        return str(msg,'utf8')


    def encrypt(self,ip,msg):
        
        # Get key and IV then create encryptor object
        aesIV  = connections[ip].IV
        aesKey = connections[ip].key
        encryptor = AES.new(aesKey, AES.MODE_CBC, aesIV)

        # Pad then encrypt the message
        msg = self.lpad(msg)
        msg = encryptor.encrypt(msg)

        return msg



#======================= [ Client Encryption Methods ] ========================#
# Used by the client to send
def send(msg):
    '''This is called to encrypt and send messages to the remote user verified
    via the handshake.'''
    
    # Try to pull the ip and port. If these are None, the connection has not yet
    # been established and the client must do /connect.
    try:
        global currcon
        ip,port = currcon
    
    except TypeError as e:
        if not inHandshake:
            print('Error: no connection has been established yet')
            print('Please connect using /connect <ip> <port>')
            return
        else:
            return

    # Grab the IV and key used by this connection
    aesIV = connections[ip].IV
    aesKey = connections[ip].key
    
    # Create the AES object to encrypt
    encryptor = AES.new(aesKey, AES.MODE_CBC, aesIV)
    
    # Pad the message then encrypt
    msg = lpad(msg)
    cMsg = encryptor.encrypt(msg)
    
    print('Padded plain:',msg)
    print('cMsg:',cMsg)

    # Craft intent
    intent = 'MSG:{0}:{1}:{2}'.format(localInfo.HOST,
                                      localInfo.PORT,
                                      cMsg)

    # Send it off
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.connect(currcon)
        sock.sendall(bytes(intent,'utf8'))


def lpad(msg):
    '''This method will pad the message with nullbytes for encryption with
    AES'''
    padlen = (16 - len(msg)) % 16
    padchar = '\x00' # Allow easily changing this
    msg = padchar*padlen + msg # pad to the left of the message
    return msg

def getState():
    return inHandshake

def setState(state):
    inHandshake = state

#===============================================================[ Server Class ]
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

def start_server(serverInfo):
    # Grab and set the HOST and port from config
    global localInfo
    localInfo = serverInfo # saves to global
    PORT = serverInfo.PORT
    HOST = serverInfo.HOST
    
    # Create a thread for the server in the background:
    pServer = server(HOST,PORT)
    serv_thread = threading.Thread(target=pServer.serve)
    serv_thread.start()
