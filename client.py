#!/usr/bin/env python3

'''
Ian Guibas

This module is the main client command-line interface. This module has the
responsibility of aggregating and displaying any information to the user as well
as handling local commands to dispatch the correct information.
'''

import logging
import socket
import knownUsers

welcomemsg = '''\
[nChat]
Welcome to nChat. This is a basic encrypted IM service that makes use of public
key cryptography (RSA) as well as secret key cryptography (AES) to provide
a reasonable CLI based chatting experience. To connect to a server please type:

    /connect <server_ip> <server_port>

For other options, please type /help.
'''

serverInformation = None
serverInstance = None
logging.getLogger()

ts = None
sthread = None

def start_client(serverInfo, tserv, servThread):
    '''Starts the client and begins prompts
    This method is the "main" of the client. It prints the welcome message and
    starts the frontend interface for the client portion of the program. It
    basically just continually reprompts the user for input checking if it
    starts with a '/' to determine whether or not the user input a command or
    simply is trying to send a message and handles each case approprately.
    '''

    logging.info('Client started')

    # Set global access to serverInfo
    global serverInformation 
    serverInformation = serverInfo
    
    # Set global server instance
    global ts
    ts = tserv

    global sthread
    sthread = servThread

    isConnected = False
    prompt = '>> '

    # Display the intro message once and give space for the prompt
    print(welcomemsg)
    print()

    # Main chat loop, constantly reprompts for input
    while True:
        
        # Grab the state of the server and do not prompt
        # the user for input until the handshake is done
        inHS = ts.getState()
        if inHS:
            #logging.debug('Suppresed prompt')
            continue
        
        else:
            try:
                # Grab message and check if it is a command
                msg = input(prompt)
            
                if msg.startswith('/'):
                    commandHandler(msg)
            
                else:
                    ts.send(msg)
            
            # On recieving ^C signal, gracefully kill the program
            except KeyboardInterrupt as e:
                commandHandler('/quit')
                sthread.stop()
                exit('Caught KeyboardInterrupt, exiting.')


def commandHandler(cmd):
    '''Handles parsing and execution of commands
    This method is responsible for parsing any commands the user creates and
    taking the appropriate action depending on which command it is.
    '''

    servInfo = serverInformation

    # Parse the command
    cmd = cmd.lower()
    cmd_parts = cmd.split(' ')
    command = cmd_parts[0][1:]
    
    global ts

    # >> /connect <host> <port>
    if command == 'connect':
        '''Set up a new connection
        This section attempts to establish a connection the remote server by
        sending the INIT_CONV intent. This begins a transfer of information
        directly between the servers that should be automatically taken care of.

        The server handler will set connection status so there is no need to do
        so in here.'''

        logging.info('Recieved connect command.')
        try:
            remoteHOST = cmd_parts[1]
            remotePORT = int(cmd_parts[2])
            
            if remotePORT < 1000 and remotePORT >= 0:
                print('Please note running on a port under 1000 require root.')
                
            
            if remotePORT > 65535 or remotePORT < 0:
                print('Port must be less than 65535')
                raise ValueError

            logging.info('Attempting to connect to {0}:{1}'.format(
                remoteHOST,
                remotePORT))
        
            
            # create the socket and try to connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((remoteHOST,remotePORT))
            
            logging.info('Connected')
            
            # Give username and publickey to remote host
            intent = 'INIT_CONV:{0}:{1}:{2}:{3}'.format(
                servInfo.HOST,
                servInfo.PORT,
                servInfo.username,
                str(servInfo.publickey.exportKey('PEM'), 'utf8'))

            sock.sendall(bytes(intent,'utf8'))
            logging.info('Intent to connect sent to {0}:{1}'.format(
                remoteHOST,
                remotePORT))

            # Force server into handshake mode
            print("Attempting to connect to {0}:{1}".format(
                remoteHOST,
                remotePORT))

            ts.setState(True)
            

        except ValueError as e:
            remotePORT = cmd_parts[2]
            logging.debug('Received invalid port: {0}'.format(remotePORT))
            print('Invalid port for connect: {0}'.format(remotePORT))
            return

    
        except IndexError as e:
            logging.debug('Too few commands given to connect command')
            print('Usage: >> /connect <ip> <port>')
    


    # >> /nick <new username>
    elif command == 'nick':
        try:
            new_user = cmd_parts[1]
            old_user = servInfo.username

            # Update username locally
            servInfo.username = new_user

            logging.info('Attempting to change nick with remote server')

            remoteHOST, remotePORT = ts.getCurrConn()

            intent = 'NICK_CHANGE:{0}:{1}:{2}:{3}'.format(
                servInfo.HOST,
                servInfo.PORT,
                old_user,
                new_user)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((remoteHOST,remotePORT))
                sock.sendall(bytes(intent, 'utf8'))
        
        except IndexError as e:
            print(e)

        except TypeError as e:
            print('Connection not yet established')

        except NameError as e:
            print(e)



    # >> /quit
    elif command == 'quit':
        
        logging.info('Quitting connection. Exiting')
        
        # Craft intent to inform the other server
        intent = 'CON_QUIT:{0}:{1}'.format(
            servInfo.HOST,
            servInfo.PORT)
        
        # Get remote ip and port if they exist, otherwise just exit
        try:
            remoteHOST, remotePORT = ts.getCurrConn()
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((remoteHOST, remotePORT))
                sock.sendall(bytes(intent, 'utf8'))
            
            # Stop server thread
            sthread.stop()

        except TypeError as e:
            #print(e)
            sthread.stop()
            exit('Client Quit.')
        
        except NameError as e:
            #print(e)
            sthread.stop()
            exit('Client Quit.')
        
        except IndexError as e:
            #print(e)
            sthread.stop()
            exit('Client Quit.')
        
        except Exception as e:
            #print(e)
            sthread.stop()
            exit('Client Quit.')

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((remoteHost, remotePORT))
            sock.sendall(bytes(intent, 'utf8'))

    # >> /help
    elif command == 'help':
        print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
        print('This is the help section. The following commands are as follows')
        print('/connect <ip> <port> - Connect to remote server to begin' +
              'chatting')
        print('---------------------------------------------------------------')
        print('/nick <new_username> - Once connected, ask the server to change'+
              ' your registered nickname. (requires existing connection and ' +
              'reauthentication via password)')
        print('---------------------------------------------------------------')
        print('/quit - Currently broken due to the fickle nature of threads. ' +
              'I am working on some way to fix this but it will take time.')
        print('---------------------------------------------------------------')
        print('/help - Displays this menu')
        print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
