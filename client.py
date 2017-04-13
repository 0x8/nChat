#!/usr/bin/env python3

'''
Ian Guibas

This module is the main client command-line interface. This module has the
responsibility of aggregating and displaying any information to the user as well
as handling local commands to dispatch the correct information.
'''

import logging
import socket

welcomemsg = '''\
[nChat]
Welcome to nChat. This is a basic encrypted IM service that makes use of public
key cryptography (RSA) as well as secret key cryptography (AES) to provide
a reasonable CLI based chatting experience. To connect to a server please type:

    /connect <server_ip> <server_port>

For other options, please type /help.
'''

serverInformation = None

def start_client(serverInfo):
    '''Starts the client and begins prompts
    This method is the "main" of the client. It prints the welcome message and
    starts the frontend interface for the client portion of the program. It
    basically just continually reprompts the user for input checking if it
    starts with a '/' to determine whether or not the user input a command or
    simply is trying to send a message and handles each case approprately.
    '''

    logging.info('Client started')

    # Set global access to serverInfo
    serverInformation = serverInfo

    isConnected = False
    prompt = '>> '

    # Display the intro message once and give space for the prompt
    print(welcomemsg)
    print()

    # Main chat loop, constantly reprompts for input
    while True:

        while not isConnected:
            cmd = input(prompt)
            if cmd.startswith('/'):
                commandHandler(cmd)

        # After we have connected look for commands but allow sending
        # if not a command
        msg = input(prompt)
        if msg.startswith('/'):
            commandHandler(msg)
        else:
            sendMsg(msg)


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

            logging.info('Attempting to connect to {0}:{1}'.format(remoteHOST,
                                                                   remotePORT))
        except ValueError as e:
            logging.debug('Received invalid port: {0}'.format(remotePORT))
            print('Invalid port for connect: {0}'.format(remotePORT))
            return

        except IndexError as e:
            logging.debug('Too few commands given to connect command')
            print('Usage: >> /connect <ip> <port>')
        
        # create the socket and try to connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((remoteHOST,remotePORT))
        
        logging.info('Connected')

        intent = 'INIT_CONV:{0}:{1}:{2}'.format(servInfo.HOST,
                                                servInfo.PORT,
                                                len(servInfo.publickey))
        sock.sendall(intent)
        logging.info('Intent to connect sent to {0}:{1}'.format(remoteHOST,
                                                                remotePORT))

    # >> /nick <new username>
    elif command == 'nick':
        new_user = cmd_parts[1]
        old_user = None 
        servInfo.username = new_user

        # Inform remote server of intent to change user
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #sock.settimeout(0.0) # Non-blocking
        sock.connect((remoteHOST,remotePORT))
        
        intent = 'NICK_CHANGE:{0}:{1}:{2}'.format(servInfo.HOST,
                                                  servInfo.PORT,
                                                  servInfo.username)
