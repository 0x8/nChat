#!/usr/bin/env python3

'''
Ian Guibas

This module contains a class meant to hold details about each remote connection.
This is just to make life easier when working with connections and maintain some
sort of memory
'''

class remoteInfo:

    def __init__(self):
        self.HOST = None
        self.PORT = None
        self.username = None
        self.password = None
        self.publicKey = None
        self.key = None
        self.IV = None
        self.Authed = False

    def __str__(self):
        '''Allows printing the object'''
        str_rep  = 'HOST:{0}\nPORT:{1}\nusername:{2}\n'.format(self.HOST,
                                                               self.PORT,
                                                               self.username)
        
        str_rep += 'publicKey:{0}\npassword:{1}\n'.format(self.publicKey,
                                                          self.password)
        
        str_rep += 'key:{0}\nIV:{1}\n'.format(self.key, self.IV)
        
        str_rep += 'Authed:{0}\n'.format(Authed)

        return str_rep

