#!/usr/bin/python
#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : share
# File            : shadow.py
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Sat Jan 26 17:38:39 2002
# Purpose         : loads a python module and creates another one
# on stdout. All the functions of the module are shadowed according
# to their doc string: "D" direct mapping, "1" indirect call but
# name + first arg used as the key and all other cases indirect
# call with the name as the key.
#---------------------------------------------------------------

import sys
import imp
import inspect

### strings used in the rewritting
direct_str = """
%s=%s.%s

"""

indirect_str = """
def %s(*args):
    indirect(\"%s\", %s.%s, %d, args)
    
"""

header = """

NONE=0
ALL=1
LOCAL=2

FAKE = {}

def indirect(name, func, type, args):
    if type == 1:
        key = (name, args[0])
    else:
        key = name
    FAKE[key] = (func, args)

def commit_changes():
    for f in FAKE.values():
        apply(f[0], f[1])

"""

### code
modulename = sys.argv[1]

module = __import__(modulename)

sys.stdout.write(header)

sys.stdout.write("import %s\n\n" % modulename)

for f in inspect.getmembers(module, inspect.isfunction):
    (args, varargs, varkw, locals) = inspect.getargspec(f[1])
    if f[1].__doc__ and f[1].__doc__[0] == 'D':
        #argspec = inspect.formatargspec(args, varargs, varkw, locals)
        s = direct_str % (f[0], modulename, f[0])
    else:
        if f[1].__doc__ and f[1].__doc__[0] == '1':
            type = 1
        else:
            type = 0
        s = indirect_str % (f[0], f[0], modulename, f[0], type)
    sys.stdout.write(s)

# shadow.py ends here
