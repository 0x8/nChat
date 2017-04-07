#!/usr/bin/env python3

import os

def conf_parse():
    with open('./config','r') as f:
        lines = f.readlines()
 
        # Set defaults
        rsa_dir = None
        username = None
        password = None
        rsa_bits = 2048
        
        for line in lines:
            # Skip comments beginning with '#'
            if line.strip().startswith('#'):
                continue
            else:
                if line.startswith('rsadir'):
                    parts = line.split('=')
                    rsa_dir = parts[1]
                    if rsa_dir == '':
                        rsa_dir = None
                    else:
                        rsa_dir = rsa_dir.strip()
                elif line.startswith('username'):
                    parts = line.split('=')
                    username = parts[1]
                    if username == '':
                        username = None
                    else:
                        username = username.strip()
                elif line.startswith('rsa_bits'):
                    parts = line.split('=')
                    rsa_bits = int(parts[1]) if parts[1] is not '' else 2048
                elif line.startswith('password'):
                    parts = line.split('=')
                    password = parts[1]
        print(rsa_dir,rsa_bits,username,password)
        return(rsa_dir,rsa_bits,username,password)

conf_parse()
