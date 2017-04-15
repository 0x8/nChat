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

    def __init__(self, ip, port):
        
        # Verify that the port is an integer or can be made INTO an integer
        if not isinstance(port, int):
            
            try:
                self.port = int(port)
            
            except ValueError as e:
                print(e)
                print('Invalid format for port. Must be int')
        
        # Set local IP and PORT
        self.port = port
        self.ip = ip



    def serve(self):
        # Create the server socket and bind to the configured IP and port
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.ip, self.port))
        
        # Start listening, accept incoming connections and pass them to handle
        server.listen(5)
        while True:
            conn, addr = server.accept()
            #logging.info('Accepted connection from {0}'.format(addr))
            self.handle(conn)
            conn.close()

#============================================================[ Request Handler ]


    # Primary Handling Class
    def handle(self, conn):
        '''Handle incoming requests
        This method is called on each remote connection made. The use of global
        is required to reference variables outside of its own scope. This allows
        for keeping track of the client between requests.
        '''
        
        MSG = conn.recv(BUFSIZE)
        msg = str(MSG,'utf8')
        intent  = msg.split(':')[0]
        ip,port = msg.split(':')[1],int(msg.split(':')[2])
        
        logging.debug('Got intent: {0}'.format(intent))
        logging.debug('Msg: {0}'.format(msg))

        # Add connection to dict and set up information
        if ip not in connections.keys():
            connections[ip] = remoteInfo()
            connections[ip].HOST = ip
            connections[ip].PORT = port


        # ---- HAND SHAKE INTENTS ---- #
        # Determine if this is an init:
        if intent == 'INIT_CONV':
            inHandshake = True
            self.init_conv(msg, ip, port)
            
        # Respond to INIT, connection establishment
        elif intent == 'INIT_ACK':
            inHandshake = True
            self.init_ack(msg, ip, port)

        # Got a public key (Remote sent first)
        elif intent == 'PK_SEND':
            self.pk_send(msg, ip, port)

        # Got a public key (Server sent first)
        elif intent == 'PK_ACK':
            self.pk_ack(msg, ip, port)

        # Remote's proposed secret
        elif intent == 'SS_SET':
            self.ss_set(msg, ip, port)

        # Local acknowledging remote's secret
        elif intent == 'SS_ACK':
            self.ss_ack(msg, ip, port)
    
        
        # ---- AUTHENTICATION INTENTS ---- # 

        elif intent == 'AUTH_REQ':
            self.auth_req(msg, ip, port, 1)

        elif intent == 'REQ_NEWAUTH':
            self.req_newauth(msg, ip, port)
        
        elif intent == 'REQ_KNOWN':
            self.req_known(msg, ip, port)

        elif intent == 'AUTH_SETNEW':
            self.auth_setnew(msg, ip, port)

        elif intent == 'AUTH_VERIFY':
            self.auth_verify(msg, ip, port)

        elif intent == 'CON_EST':
            self.con_est(msg, ip, port)


        # ---- CONVERSATIONAL INTENTS ---- #
        elif intent == 'MSG':
            self.mdecrypt(msg, ip, port)



    def init_conv(self, msg, ip, port):
        '''Handle the initial connection to client
        Responds with INIT_ACK and sends this clients information to the remote
        connector. This includes the public key as I see no need to make this
        its own message.

        Format of intent recieved:
        INIT_CONV:IP:PORT:USERNAME:PUBKEY
        '''
        
        # Pull and set remote username and public key
        username = msg.split(':')[3]
        pubkey   = msg.split(':')[4]
        connections[ip].username  = username
        connections[ip].publicKey = RSA.importKey(pubkey)
        
        # Craft intent 
        intent = 'INIT_ACK:{0}:{1}:{2}:{3}'.format(
            localInfo.HOST,
            localInfo.PORT,
            localInfo.username,
            localInfo.publickey.exportKey('PEM'))

        # handshake
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.connect((ip,port))
            sock.sendall(bytes(intent, 'utf8'))



    def init_ack(self, msg, ip, port):
        '''Handle receiving the init acknowledgement. Reply PK_SEND
        Responds with SS_SEND and generates remotekeys to be used for this
        session (AES Key and AES IV, both 16 bytes and random). These get
        cached locally then encrypted with the remote server's public key
        and sent off. This allows some checking of eavesdropping as it should be
        trivial to decrypt, re-encrypt and return the same data (from the remote
        client) if they have the private key associated with the provided public
        key.

        IMPORTANT: This step MAY be spoofed with an attackers public key instead
        but this does not matter as  all keys and IVs are random and per 
        session, possesion of one does not allow anything more than 
        participating in that particular session. That said, there is no
        gaurantee that a Man-in-the-middle can not intercept and manipulate
        earlier handshake steps and as such only trusted networks should be used
        unless another form of security is also available on top of this (such
        as a VPN). I know how to fix this but it would require more changes that
        I unfortunately do not have time to implement.
        '''
        
        # Pull and set remote username and public key
        username = msg.split(':')[3]
        pubkey   = msg.split(':')[4]
        connections[ip].username  = username
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
        intent = 'SS_SET:{0}:{1}:{2}:{3}'.format(
            localInfo.HOST,
            localInfo.PORT,
            eIV,
            eKey)

        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.connect((ip,port))
            sock.sendall(bytes(intent, 'utf8'))
    
   

    def ss_set(self, msg, ip, port):

        # Get encrypted IV and Key
        cIV  = msg.split(':')[3]
        cKey = msg.split(':')[4]
        
        # Convert back from base64 and decrypt them
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

        intent = 'SS_ACK:{0}:{1}:{2}:{3}'.format(
            localInfo.HOST,
            localInfo.PORT,
            sKey,
            sIV) 

        # Socket Creation
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.connect((ip,port))
            sock.sendall(bytes(intent, 'utf8'))



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
            
            # Log some debugging information:
            logging.debug('Key and IV potentially changed')
            logging.debug('Printing them for manual inspection:')
            logging.debug('pKey:  {0}'.format(pKey))
            logging.debug('myKey: {0}'.format(myKey))
            logging.debug('pIV:   {0}'.fomrat(pIV))
            logging.debug('myIV:  {0}'.format(myIV))
            
            # Craft abortion intent and tell the remote client
            logging.debug('Aborting connection')
            intent = "CON_ABRT"
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((ip, port))
                sock.sendall(bytes(intent, 'utf8'))
                
            # Delete current client information
            del connections[ip]
            logging.debug('Aborted connection')
            return

        # Remote public key verified and AES information exchanged
        else:
            '''If control has reached here, it means that the public key and AES
            information were properly verified. At this point, this client can
            request to auth to the remote server using the AES information that
            just got set up.
            
            This sends the intent to authorize to the remote who will in turn
            prompt the local client for their password based.'''

            logging.info('Key exchange verified. Requesting to auth to remote')
       
            intent = 'AUTH_REQ:{0}:{1}:{2}'.format(
                localInfo.HOST,
                localInfo.PORT,
                localInfo.username)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((ip, port))
                sock.sendall(bytes(intent, 'utf8'))


    
    def auth_req(self, msg, ip, port, flg):
        '''Determine whether to ask for a known user or new user password.
        This method receives the AUTH_REQ intent and determines whether or not
        to prompt for a new password or to prompt for an existing password (and
        in doing so provide the appropriate salt to use for that).
        
        Will also be called during authorizing to send same to remote from
        local.

        format of calling intent: AUTH_REQ:IP:PORT:USERNAME
        responds with: REQ_NEWAUTH:IP:PORT:USERNAME
                   OR  REQ_KNOWN:IP:PORT:USERNAME:SALT
        '''
        
        # If called in response to receiving this from remote
        if flg == 1:
            
            # Grab the username:
            username = msg.split(':')[3]

            # Check if it exists:
            if knownUsers.check(username):
                logging.info('User {0} exists in known_users'.format(username))
                logging.info('Sending request to auth known user')

                # Get salt:
                salt = getSalt(username)
                
                # Craft and send request to auth a known user
                intent = 'REQ_KNOWN:{0}:{1}:{2}:{3}'.format(
                    localInfo.HOST,
                    localInfo.PORT,
                    username,
                    salt)

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((ip, port))
                    sock.sendall(bytes(intent, 'utf8'))

            # If user does not exist in local memory, go ahead and ask for a new
            # password.
            else:
                
                intent = 'REQ_NEWAUTH:{0}:{1}:{2}'.format(
                    localInfo.HOST,
                    localInfo.PORT,
                    username)

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((ip, port))
                    sock.sendall(bytes(intent, 'utf8'))
        

        # If called by internal function to auth remote
        else:
            # Set username to be remote username
            username = connections[ip].username
            
            # Check if it exists:
            if knownUsers.check(username):
                logging.info('User {0} exists in known_users'.format(username))
                logging.info('Sending request to auth known user')

                # Get salt:
                salt = getSalt(username)
                
                # Craft and send request to auth a known user
                intent = 'REQ_KNOWN:{0}:{1}:{2}:{3}'.format(
                    localInfo.HOST,
                    localInfo.PORT,
                    username,
                    salt)

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((ip, port))
                    sock.sendall(bytes(intent, 'utf8'))

            # If user does not exist in local memory, go ahead and ask for a new
            # password.
            else:
                
                intent = 'REQ_NEWAUTH:{0}:{1}:{2}'.format(
                    localInfo.HOST,
                    localInfo.PORT,
                    username)

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((ip, port))
                    sock.sendall(bytes(intent, 'utf8'))



    def req_known(self, msg, ip, port)
        '''Deals with a request for a known user
        This method deals with handling a request for a known user by prompting
        for the password of a known user and hashing with the specified salt
        then encrypting this with AES to send back to the server. It also will
        send another message to the server if the remote connection has not yet
        authorized which will depend upon whether that user exists locally or
        not.

        format of calling intent: REQ_KNOWN:IP:PORT:USERNAME:SALT
        format of response: AUTH_VERIFY:IP:PORT:USER:HASH
            note: HASH is AES encrypted base64
        '''
        
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
        
        intent = 'AUTH_VERIFY:{0}:{1}:{2}:{3}'.format(
            localInfo.HOST,
            localInfo.PORT,
            username,
            pw)
        
        # Send it off for the server to handle
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((ip,port))
            sock.sendall(bytes(intent, 'utf8'))
        
        # Also call auth_req if the user has not authed yet.
        if not connections[ip].Authed:
            self.auth_req(msg, ip, port, 0)


    def req_newauth(self, msg, ip, port):
        '''Handle request for new user password
        Takes care of prompting for a new password if the remote server does not
        already know the current nick.

        format of calling request: REQ_NEWAUTH:IP:PORT:USER
        format of response: AUTH_SETNEW:IP:PORT:USER:HASH
            note: HASH is AES encrypted base64
        '''
        
        # Get the username
        username = connections[ip].username
        print('Password requested by {0}:{1} for new user: {2}'.format(
            ip,
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

        intent = 'AUTH_SETNEW:{0}:{1}:{2}:{3}'.format(
            localInfo.HOST,
            localInfo.PORT,
            username,
            pw)
        
        # Socket creation
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.connect((ip, port))
            sock.sendall(bytes(intent, 'utf8'))
        
        # Also call auth_req if the user has not authed yet
        if not connections[ip].Authed:
            auth_req(msg, ip, port, 0)


    def auth_verify(self, msg, ip, port):
        '''Handles verifying a response to auth to a known user.
        This verifies that the remote hash is the same as the stored hash. In
        order to do this, the HASH portion must be first base64 decoded then
        decrypted with AES before finally being compared to the stored hash.

        From there, the server will either reprompt or accept. If I have time
        I will likely add a retry limit to avoid bruteforcing.
        
        format of calling intent: AUTH_VERIFY:IP:PORT:USERNAME:B64(AES(HASH))
        format of response: CON_FIN:IP:PORT
                        OR: calls auth_req again
        '''

        # Parse out the username and base64 encoded, encrypted hash
        username = msg.split(':')[3]
        passhash = msg.split(':')[4]
        
        # Decode and decrypt the hash
        passhash = base64.b64decode(passhash)
        passhash = decrypt(passhash)
        logging.debug('Recieved remote hash: {0}'.format(passhash))
        
        logging.debug('Entered known user state')
        logging.debug('Salt: {0}'.format(knownUsers.getSalt(username)))
        logging.debug('Hash: {0}'.format(knownUsers.getPass(username)))
        
        # Compare to the stored hash for the user
        check = passhash == getPass(username)
        logging.debug('Hash check: {0}'.format(check))
        if passhash == getPass(username):
            '''hashes matched, establish connection'''
            
            # Set currcon and send CON_EST
            currcon = (ip, port)
            intent = 'CON_EST:{0}:{1}'.format(localInfo.HOST, localInfo.PORT)
        
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((ip, port))
                sock.sendall(bytes(intent, 'utf8'))
            
            est_msg  = 'Connection established with '
            est_msg += '{0}:{1}'.format(ip,port)
            logging.debug(est_msg)
            
            # Set authed
            connections[ip].Authed = True

            # Release handshake
            inHandshake = False
        

        # Call the request again but as if it were requested remote
        else:
            self.auth_req(msg, ip, port, 1)

    

    def auth_setnew(self, msg, ip, port):
        '''Set up a new user with the new hash
        Because the calling nick is previously unknown this simply creates
        a new user with the current parameters.

        format of calling request: AUTH_SETNEW:IP:PORT:USERNAME:B64(AES(HASH))
        format of response: CON_FIN:IP:PORT
        '''
        
        # Parse out username and encoded, encrypted hash
        username = msg.split(':')[3]
        passhash = msg.split(':')[4]
        
        # Decode and decrypt the hash
        passhash = base64.b64decode(passhash)
        passhash = decrypt(passhash)
        
        # Set the public key
        pubkey = connections[ip].publicKey

        # Create the new user
        knownUsers.createUser(username, passhash, pubkey)

        # Set currcon and send CON_EST
        currcon = (ip, port)
        intent = 'CON_EST:{0}:{1}'.format(localInfo.HOST, localInfo.PORT)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((ip, port))
            sock.sendall(bytes(intent, 'utf8'))

        est_msg  = 'Connection established with '
        est_msg += '{0}:{1}'.format(ip,port)
        logging.debug(est_msg)
        
        # Set authed
        connections[ip].Authed = True

        # Release the handshake
        inHandshake = False
    


    def con_est(self,msg,ip,port):
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
        
        # Convert to bytes
        logging.debug('Msg len prior to bytes conversion: {0}'.format(len(msg)))
        bytes(msg,'utf8')
        logging.debug('Msg len after bytes conversion: {0}'.format(len(msg)))

        logging.debug('Encrypted Msg: {0}'.format(msg))
        
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
    logging.debug('Sent plaintext: {0}'.format(msg))
    msg = lpad(msg)
    cMsg = encryptor.encrypt(msg)
    logging.debug('Sent padded plaintext: {0}'.format(msg)) 
    logging.debug('Sent encrypted message: {0}'.format(cMsg))

    # Craft intent
    intent = 'MSG:{0}:{1}:{2}'.format(localInfo.HOST,
                                      localInfo.PORT,
                                      cMsg)

    # Send it off
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.connect(currcon)
        sock.sendall(bytes(intent, 'utf8'))



def lpad(msg):
    '''This method will pad the message with nullbytes for encryption with
    AES'''
    padlen = (16 - len(msg)) % 16
    padchar = '\x00' # Allow easily changing this 
    msg = padchar*padlen + msg # pad to the left of the message

    logging.debug('Padchar: {0}'.format(padchar))
    logging.debug('Paddedmsg: {0}'.format(msg))
    return msg



def getState():
    return inHandshake



def setState(state):
    inHandshake = state

#===============================================================[ Server Class ]



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
