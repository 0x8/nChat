#!/usr/bin/env python3

'''
Ian Guibas

This is the primary module for nchat. It is the only one that need be run and
will act as the "brain" of the program, tying everything together.
'''

import threadedServer
import Config
import client
import logging

# Allow color log debug mode
DEBUG = True

if __name__ == '__main__':
    # Start logging
                                                                        
    log_dateformat = '%Y-%m-%dT%H:%M:%S'
    log_format  = '%(asctime)s | %(levelname)s %(module)s:%(funcName)s'
    log_format += ':%(lineno)d [%(process)d] | %(message)s'
    
    # If debug is on, use colored logs if available
    if DEBUG:
        
        try:
                import coloredlogs                                                      
                coloredlogs.install(                                                    
                    filename='logs/nchat.log',                                          
                    level=logging.DEBUG,                                                 
                    datefmt=log_dateformat,                                             
                    field_styles = {                                                    
                        'asctime': {'color': 'green'},                                  
                        'levelname': {'color': 'black', 'bold': True},                  
                        'module': {'color': 'yellow'},                                  
                        'process':{'color':'magenta'}},                                 
                    fmt = log_format) 
        
        except ImportError:                                                         
            logging.basicConfig(                                                    
                filename='logs/nchat.log',                                          
                level=logging.DEBUG,                                                 
                format=log_format,                                                  
                datefmt=log_dateformat)                                             
    
    # If DEBUG is set to False (default) all logging goes to a file
    else:                                                                       
        logging.basicConfig(
            filename='logs/nchat.log',
            level=logging.INFO,                                                 
            format=log_format,                                                  
            datefmt=log_dateformat)
    
    logging.info('Started logging')
    logging.info('Started main chat program')
    logging.info('Parsing server config...')

    # Get information then start the server
    serverInfo = Config.ServerInfo()
    logging.info('Config parsed successfully')
    logging.info('Starting server on {0}:{1}'.format(serverInfo.HOST,
                                                     serverInfo.PORT))
    # Start client and server 
    ts = threadedServer
    sthread = ts.start_server(serverInfo)
    
    logging.info('Server started on {0}:{1}'.format(serverInfo.HOST,
                                                        serverInfo.PORT))
    
    logging.info('Starting client...')
    client.start_client(serverInfo,ts, sthread)
