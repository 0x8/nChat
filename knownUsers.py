#!/usr/bin/env python3

'''
Ian Guibas

This module handles the known_users file. It provides an interface to read,
write to, and keep track of the file.
'''

import fileinput
import logging
import os

def check(username):
    '''Checks if a user is in the known_users file'''

    # If the file does not exist, return false but create it first
    if not os.path.exists('known_users'):
        logging.info('Failed to find known_users. Creating...')
        open('known_users','w').close() # Create but don't write
        logging.info('Created known_users file')
        logging.info('Failed to find {0} in known_users'.format(username))
        return False

    # Otherwise read the file and search
    with open('known_hosts','r') as f:
        for line in f.readlines():
            if line.startswith(username):
                return True
        return False

def createUser(username,password,pubkey):
    '''Create a new stored user
    This module allows the creation of a new user entry in known_hosts as well
    as ensuring their public key gets cached for use in the future.
    '''

    # Check if known_users exists creating it if not
    if not os.path.exists('known_users'):
        logging.info('Failed to find known_users. Creating...')
        open('known_users','w').close()
        logging.info('Created known_users file')
        
    # Ensure that the user does not already have a row
    if check(username):
        logging.info('Found {0} in known_users, cannot create new'.format(
            username))
        print('User {0} already exists'.format(username))
        return
        
    # File exists and user does not, creating new row
    with open('known_users','a') as f:
        f.write('{0}:{1}'.format(username,password))

    # Write out the pubkey too
    with open('rsa/{0}.pub'.format(username),'w') as f:
        f.write(pubkey.exportKey('PEM'))


def delUser(username):
    '''Delete a stored remote user
    This module allows the quick and easy deletion of a stored user and their
    data.
    '''

    # Check if known_users exists creating it if not
    if not os.path.exists('known_users'):
        logging.info('Failed to find known_users. Creating...')
        open('known_users','w').close()
        logging.info('Created known_users file')
        return  # No need to remove what doesn't exist

    # Check if the username is in the file at all and remove the line if it
    # exists
    logging.info('Attempting to remove {0}...'.format(username))
    with open('known_users','r') as f:
        lines = f.readlines()

    with open('known_users','w') as f:
        for line in lines:
            if not line.startswith(username):
                f.write(line)
    
    logging('Removed user {0} from known_users'.format(username)

    # Attempt to remove the publickey file as well
    try:
        os.remove('rsa/{0}.pub'.format(username))
    except FileNotFoundError as e:
        print('No public key found for {0}'.format(username))
        logging('Public key for {0} does not exist'.format(username))
        
    return

def getPass(username):
    '''Returns the password hash for a user
    This method will return the password hash for a user if that user is in the
    known_users file or return None otherwise.
    '''

    # Check for existance of known_users
    if not os.path.exists('known_users'):
        logging.info('Failed to find known_users. Creating...')
        open('known_users','w').close()
        logging.info('Created known_users file')
        return None
    
    # Check that username is in the file, returning pass if found
    with open('known_users','r') as f:
        for line in f.readlines():
            if line.startswith(username):
                password = line.split(':')[1]
                if password == '-':
                    return None
                return password
        return None
