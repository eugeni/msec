#---------------------------------------------------------------
# Project         : Mandriva Linux
# Module          : msec
# File            : Config.py
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Thu Dec  6 19:54:35 2001
# Purpose         : configuration settings
#---------------------------------------------------------------

CONFIG='/etc/security/msec2.conf'

_config={ 'root' : '',
          'run_commands': 1,
          'log': 'syslog',
          }
try:
    execfile(CONFIG, _config)
except IOError:
    #sys.stderr.write("no config file in %s. Using default values.\n" % CONFIG)
    pass

def get_config(name, default=None):
    try:
        return _config[name]
    except KeyError:
        return default

def set_config(name, value):
    _config[name] = value
    
# def converthexa(array):
#     result=""
#     for c in array:
#         o=ord(c)
#         d=int(o/16)
#         u=o-(d*16)
#         result=result + "%x%x" % (d, u)
#     return result
# 
# def hashstring(str):
#     return converthexa(md5.new(str).digest())

# Config.py ends here
