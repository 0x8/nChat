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
Busy = False


# For key verification
myKey = None
myIV  = None

# For determining if handshake is occuring
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
        
        global inHandshake

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
            logging.debug('Updated inHandshake')
            logging.debug('inHandshake: {0}'.format(inHandshake))
            self.init_conv(msg, ip, port)
            
        # Respond to INIT, connection establishment
        elif intent == 'INIT_ACK':
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
        
        elif intent == 'CON_QUIT':
            self.con_quit(msg, ip, port)

        elif intent == 'NICK_CHANGE':
            self.nick_change(msg, ip, port)

        elif intent == 'SIG_BUSY':
            self.sig_busy(msg, ip, port)
        
        elif intent == 'SIG_ERR':
            self.sig_err(msg, ip, port)

        elif intent == 'NC_AUTHR':
            self.nc_authr(msg, ip, port)

        elif intent == 'NC_REQV':
            self.nc_reqv(msg, ip, port)


    def sig_busy(self, msg, ip, port):
        '''Aborts connection if remote is already connected to someone else'''
        print('Got SIG_BUSY from {0}:{1}'.format(ip, port))
        print('You must wait until they are free to connect.')
        return
        

    def sig_err(self, msg, ip, port):
        '''Aborts handshake and prints error message'''
        
        emsg = msg.split(':')[3]
        print('Got SIG_ERR from {0}:{1}'.format(ip, port))
        print('Error:', emsg)
        return



    def nick_change(self, msg, ip, port):
        '''Process a request to change a nick
        
        format of calling intent: NICK_CHANGE:IP:PORT:OLDUSER:NEWUSER 
        format of response: SIG_ERR:IP:PORT:eMSG
                        or  NC_AUTHR:IP:PORT:NEWUSER:SALT
        '''
        # Parse information
        olduser = msg.split(':')[3]
        newuser = msg.split(':')[4]


        # If no session has been started, send error
        if not currcon:
            intent == 'SIG_ERR:{0}:{1}:{2}'.format(
                localInfo.HOST,
                localInfo.PORT,
                'No connection started, please connect first')
            
            # Send to remote
            self.sendIntent(intent, ip, port)
        

        # If the sender is not the current connector also abort
        elif (ip, port) != currcon:
            '''Simply drop, no need to waste resource replying to a spoof'''
            return
                    

        # Ensure old user exists
        elif not knownUsers.check(olduser):
            intent = 'SIG_ERR:{0}:{1}:{2}'.fomrat(
                localInfo.HOST,
                localInfo.PORT,
                'Old user does not exist, unknown error.')

            self.sendIntent(intent, ip, port)
        
        # Ensure new user is unique
        elif knownUsers.check(newuser):
            intent = 'SIG_ERR:{0}:{1}:{2}'.format(
                localInfo.HOST,
                localInfo.PORT,
                'New username is already taken.')

            self.sendIntent(intent, ip, port)
        
        # If none of the above triggered, we can initiate the change
        else:
            
            salt = knownUsers.getSalt(olduser)
            salt = self.encrypt(ip, salt)
            salt = base64.b64encode(salt)

            intent = 'NC_AUTHR:{0}:{1}:{2}:{3}'.format(
                localInfo.HOST,
                localInfo.PORT,
                newuser,
                salt)

            self.sendIntent(intent, ip, port)


    def nc_authr(self, msg, ip, port):
        '''Prompts the user to enter their password for the server to verify

        format of calling intent: NC_AUTHR:IP:PORT:NEWUSER:B64(AES(SALT))  
        '''
        
        # Parse out the new user and salt
        newuser = msg.split(':')[3]
        salt    = msg.split(':')[4]

        # Decode then decrypt salt
        salt = base64.b64decode(salt)
        salt = decyrpt(ip, salt)

        print('Password requested for current nick by {0}:{1}'.format(ip, port))

        # Prompt the user for the password and hash with salt
        prompt = 'Current user password: '
        pw = ''
        while pw == '' or pw == None:
            pw = getpass.getpass(prompt)
            pw = bcrypt_sha256.using(salt=salt).hash(pw)
        
        # Encrypt and encode the new hash
        pw = encrypt(ip, pw)
        pw = base64.b64encode(pw)

        intent = 'NC_REQV:{0}:{1}:{2}:{3}'.format(
            localInfo.HOST,
            localInfo.PORT,
            newuser,
            pw)
        
        # Send off to the server.
        self.sendIntent(intent, ip, port)



    def nc_reqv(self, msg, ip, port):
        '''Attempts to verify the hash and set the new username

        format of calling intent: NC_REQV:IP:PORT:NEWUSER:B64(AES(HASH))
        format of response: NC_SUCC:IP:PORT
                        or  SIG_ERR:IP:PORT:EMSG
        '''

        # Pull the old username, new username, and hash
        olduser = connections[ip].username
        newuser = msg.split(':')[3]
        pw      = msg.split(':')[4]

        # Decode and decrypt the hash
        pw = base64.b64decode(pw)
        pw = self.decrypt(ip, pw)

        # Grab old hash and compare
        opw = knownUsers.getPass(olduser)
        if pw == opw:
            '''Auth'''
            
            knownUsers.changeUser(olduser, newuser)
            connections[ip].username = newuser

            intent = 'NC_SUCC:{0}:{1}'.format(localInfo.HOST, localInfo.PORT)
            
            # Confirm with remote user
            self.sendIntent(intent, ip, port)
        
        # If hashes did not match send error with notice of failure
        else:
            intent = 'SIG_ERR:{0}:{1}:{2}'.format(
                localInfo.HOST,
                localInfo.PORT,
                'Failed to verify identity. Nick unchanged.')
                
            self.sendIntent(intent, ip, port)
        return



    def sendIntent(self, intent, ip, port):
        '''Creates a socket and sends the provided intent message''' 
        # Create the socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((ip, port))
            sock.sendall(bytes(intent, 'utf8'))


    def init_conv(self, msg, ip, port):
        '''Handle the initial connection to client
        Responds with INIT_ACK and sends this clients information to the remote
        connector. This includes the public key as I see no need to make this
        its own message.

        Format of intent recieved:
        INIT_CONV:IP:PORT:USERNAME:PUBKEY
        '''
        
        # If a connection has already been established, send an busy message
        # and stop processing. Minor protection against someone trying to
        # reauth with a different key.
        global busy
        if busy:
            intent = "SIG_BUSY:{0}:{1}".format(localInfo.HOST, localInfo.PORT)
            self.sendIntent(intent, ip, port)
            

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
            str(localInfo.publickey.exportKey('PEM'), 'utf8'))

        # Send intent and continue hanshake
        self.sendIntent(intent, ip, port)


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
        
        # Help prevent spoofing by dropping the connection if busy.
        # Busy is set on connection establishment and freed on release
        # If Busy is set and someone sends init_ack, it is malicious
        global Busy
        if Busy:
            intent = 'SIG_BUSY:{0}:{1}'.format(localInfo.HOST, localInfo.PORT)
            self.sendIntent(intent, ip, port)
        

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
    
        # Send
        self.sendIntent(intent, ip, port) 
   

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
        
        # Send
        self.sendIntent(intent, ip, port)


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
            intent = "SIG_ERR:{0}:{1}:{2}".format(
                localInfo.HOST,
                localInfo.PORT,
                'AES information did not match, aborting')
            
            # Send
            self.sendIntent(intent, ip, port)
                
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

            self.sendIntent(intent, ip, port)

    
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
                salt = knownUsers.getSalt(username)
                
                # Craft and send request to auth a known user
                intent = 'REQ_KNOWN:{0}:{1}:{2}:{3}'.format(
                    localInfo.HOST,
                    localInfo.PORT,
                    username,
                    salt)

                self.sendIntent(intent, ip, port)

            # If user does not exist in local memory, go ahead and ask for a new
            # password.
            else:
                
                intent = 'REQ_NEWAUTH:{0}:{1}:{2}'.format(
                    localInfo.HOST,
                    localInfo.PORT,
                    username)

                self.sendIntent(intent, ip, port) 

        # If called by internal function to auth remote
        else:
            # Set username to be remote username
            username = connections[ip].username
            
            # Check if it exists:
            if knownUsers.check(username):
                logging.info('User {0} exists in known_users'.format(username))
                logging.info('Sending request to auth known user')

                # Get salt:
                salt = knownUsers.getSalt(username)
                
                # Craft and send request to auth a known user
                intent = 'REQ_KNOWN:{0}:{1}:{2}:{3}'.format(
                    localInfo.HOST,
                    localInfo.PORT,
                    username,
                    salt)

                self.sendIntent(intent, ip, port)
                    
            # If user does not exist in local memory, go ahead and ask for a new
            # password.
            else:
                
                intent = 'REQ_NEWAUTH:{0}:{1}:{2}'.format(
                    localInfo.HOST,
                    localInfo.PORT,
                    username)


                self.sendIntent(intent, ip, port)


    def req_known(self, msg, ip, port):
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
        self.sendIntent(intent, ip, port)


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
        global inHandshake
        logging.debug('inHandshake: {0}'.format(inHandshake))
        # Get the username
        username = msg.split(':')[3]
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
        self.sendIntent(intent, ip, port)
        logging.debug('SENT INTENT: {0}'.format(intent))

        
        # Also call auth_req if the user has not authed yet
        logging.debug('Asking remote to auth')
        if not connections[ip].Authed:
            self.auth_req(msg, ip, port, 0)


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
        passhash = self.decrypt(ip, passhash)
        logging.debug('Recieved remote hash: {0}'.format(passhash))
        
        logging.debug('Entered known user state')
        logging.debug('Salt: {0}'.format(knownUsers.getSalt(username)))
        logging.debug('Hash: {0}'.format(knownUsers.getPass(username)))
        
        # Compare to the stored hash for the user
        check = passhash == knownUsers.getPass(username)
        logging.debug('Hash check: {0}'.format(check))
        if passhash == knownUsers.getPass(username):
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
            
            # Set Busy
            global Busy
            Busy = True

            # Release handshake
            global inHandshake
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
        passhash = self.decrypt(ip, passhash)
        
        # Set the public key
        pubkey = connections[ip].publicKey

        # Create the new user
        knownUsers.createUser(username, passhash, pubkey)
        logging.debug('Created new user: {0}'.format(username))
    
        # Set currcon and send CON_EST
        currcon = (ip, port)
        logging.debug('Currcon: {0}'.format(currcon))
        intent = 'CON_EST:{0}:{1}'.format(localInfo.HOST, localInfo.PORT)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((ip, port))
            sock.sendall(bytes(intent, 'utf8'))

        logging.debug('SENT INTENT: {0}'.format(intent))

        est_msg  = 'Connection established with '
        est_msg += '{0}:{1}'.format(ip,port)
        logging.debug(est_msg)
        
        # Set authed
        logging.debug('Setting connection to Authed')
        connections[ip].Authed = True

        # Set Busy
        global Busy
        Busy = True

        # Release the handshake
        global inHandshake
        inHandshake = False


    def con_est(self,msg,ip,port):
        print('Connection established with {0}:{1}'.format(ip,port))
        global currcon
        
        currcon = (ip,port)
        logging.debug('Currcon set to: {0}'.format(currcon))
        inHandshake = False
        logging.debug('inHandshake: {0}'.format(inHandshake))



    def con_quit(self, msg, ip, port):
        '''Handles removing the connection to the client that quit'''
        
        # Pull username from dict
        username = connections[ip].username

        # Inform the user of the quit action
        print('{0} at {1}:{2} has quit.'.format(username, ip, port))
        

        # Remove dict entry and set currcon to none        
        del connections[ip]
        global currcon
        currcon = None
        
    

    def mdecrypt(self,msg,ip,port):
        '''Decrypt and display an instant message'''
        IV = connections[ip].IV
        Key = connections[ip].key
        nick = connections[ip].username

        logging.debug('inHandshake: {0}'.format(inHandshake))
        
        # MSG:IP:PORT:Message <- Intent
        msg = msg.split(':')[3]
        
        # Base64 decode the message
        msg = base64.b64decode(msg)
        logging.debug('Encrypted Msg: {0}'.format(msg))
        
        # Decrypt the message
        decryptor = AES.new(Key ,AES.MODE_CBC, IV)
        msg = decryptor.decrypt(msg).strip(b'\x00')
        msg = str(msg, 'utf8') 
        print(nick + ':',msg)

    
    #===============[ Server Crypto Methods ]===============#
    def lpad(self, msg):
        '''This method will pad the message with nullbytes for encryption with
        AES'''
        padlen = (16 - len(msg)) % 16
        padchar = '\x00' # Allow easily changing this
        msg = padchar*padlen + msg # pad to the left of the message
        return msg


    def unpad(self, msg):
        return msg.strip('\x00')


    def decrypt(self, ip, msg):

        # Get key and IV then create decryptor object
        aesIV  = connections[ip].IV
        aesKey = connections[ip].key
        decryptor = AES.new(aesKey, AES.MODE_CBC, aesIV)

        # Decrypt message then remove padding
        msg = decryptor.decrypt(msg)
        msg = str(msg, 'utf8')
        msg = self.unpad(msg)
        return msg


    def encrypt(self, ip, msg):
        
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
    global inHandshake
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

    # Base64 encode the message for transmission
    cMsg = base64.b64encode(cMsg)

    # Craft intent
    intent = 'MSG:{0}:{1}:{2}'.format(
        localInfo.HOST,
        localInfo.PORT,
        str(cMsg, 'utf8'))

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
    global inHandshake
    return inHandshake



def setState(state):
    global inHandshake
    inHandshake = state



def getCurrConn():
    global currcon
    return currcon


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
