#!/usr/bin/env python3

'''
Ian Guibas

This module is responsible for parsing the config files and wrapping information
in objects to be used in other modules.
'''
from Crypto.PublicKey import RSA
from Crypto.Util import number
import configparser
import logging
import time
import sys

# Initial read
config = configparser.ConfigParser()
config.read('nchat_config.ini')

# local logging instance
log = logging.getLogger(__name__)
log_format  = '%(asctime)s | %(levelname)s %(module)s:%(funcName)s:%(lineno)d'
log_format += ' [%(process)d] | %(message)s'
log_dateformat = '%Y-%m-%dT%H:%M:%S'

class ServerInfo:
    ''' Contains information related to the server portion of the nChat program.
    This class holds all information related to the server running for this
    program. This includes the desired IP to run on, the desired port to run on,
    username, rsa path if a previous key exists and whatever else needs to be
    accessed easily by the server.
    '''

    def __init__(self):
        # Read server section and fill fields
        serverSection = config['SERVER']
       
        # Set the options
        try:    
            log.info('Setting server values')
            self.HOST       = serverSection['HOST']
            self.PORT       = int(serverSection['PORT'])
            self.user       = serverSection['username']
            self.rsa_bits   = int(serverSection['rsa_bits'])
            self.rsa_dir    = serverSection['rsa_dir']
            self.username   = serverSection['username']
            self.serverpass = serverSection['serverpass']
            log.info('Finished setting server values')
            
            # Public Key Stuff
            self.privKey = None
            self.publickey = None


        except KeyError as e:
            log.error('Missing config value in [\'SERVER\']: {0}',e)
            sys.exit('Config file is missing parameters, exiting')


        # Set up the crypto stuff
        if self.rsa_dir == '':
            
            log.info('RSA_DIR left blank, creating new instance')
            
            if self.rsa_bits == '':
                log.info('Missing rsa_bits entry, defaulting to 2048')
                self.rsa_bits = 2048
                self.rsa = RSA.generate(2048)
            
            else:
                log.info('Creating key of size rsa_bits')
                self.rsa = RSA.generate(int(self.rsa_bits))
            
            # Save the key to a PEM file
            filepath = 'rsa/{0}_rsakey_{1}'.format(self.username, 
                                                   round(time.time()))
            
            log.info('Saving generated key to: {0}'.format(filepath))
            
            with open(filepath,'wb') as f:
                f.write(bytes(self.rsa.exportKey('PEM')))
                log.info('Saved private key to {0}'.format(filepath))
                self.privKey = RSA.importKey(self.rsa.exportKey('PEM'))

            with open(filepath+'.pub','wb') as f:
                f.write(bytes(self.rsa.publickey().exportKey('PEM')))
                log.info('Saved public key to {0}.pub'.format(filepath))
                self.publickey = RSA.importKey(
                                    self.rsa.publickey().exportKey('PEM'))

        else:
            # Import the key from the rsa_dir
            try:
                
                log.info('Opening {0} to import the key'.format(
                            self.rsa_dir))

                with open(self.rsa_dir,'rb') as f:
                    self.privKey = RSA.importKey(f.read())
                    
                with open(self.rsa_dir+'.pub','wb') as f:
                    self.publickey = RSA.importkey(f.read())
                    log.info('Key imported')

            except FileNotFoundError as e:
                log.error('Failed to import key, file not found')
                log.error('File provided: {0}'.format(self.rsa_dir))
                print('Could not find file:',e)
                print('Double check the rsa_dir path')
                print('Defaulting to 2048 bit for this session')
                self.rsa = RSA.generate(2048)

        if self.serverpass == '':
            log.info('Serverpass field left blank, setting usespass to' +
                         ' false')

            self.usespass = False
        else:
            self.usespass = True

    def socketInfo(self):
        return (self.HOST,self.PORT)
    
    def printInfo(self):
        print('Server Information:')
        print('HOST:',self.HOST)
        print('PORT:',self.PORT)
        print('rsa_dir:',self.rsa_dir)
        print('rsa_bits:',self.rsa_bits)
        print('username:',self.username)
        print('serverpass:',self.serverpass)
        print('usespass:',self.usespass)

if __name__ == '__main__':
    try:
        import coloredlogs
    except ImportError:
        logging.basicConfig(
            filename='logs/nchat.log',
            level=logging.INFO,
            format=log_format,
            datefmt=log_dateformat)
    else:
        coloredlogs.install(
            filename='logs/nchat.log',
            level=logging.INFO,
            datefmt=log_dateformat,
            field_styles = {
                'asctime': {'color': 'green'},
                'levelname': {'color': 'black', 'bold': True},
                'module': {'color': 'yellow'},
                'process':{'color':'magenta'}},
            fmt = log_format)
    
    serverInfo = ServerInfo()
    serverInfo.printInfo()

