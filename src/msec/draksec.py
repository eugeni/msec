#!/usr/bin/python -O
"""
This is graphical frontend to msec.
"""

import os
import sys

# PyGTK
import gtk
#import gtk.glade
import pygtk
import gobject

# config
import config

# version
try:
    from version import version
except:
    version = "development version"

# libmsec
from libmsec import MSEC, Log

import logging

# localization
try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

class MsecGui:
    """Msec GUI"""
    def __init__(self):
        """Initializes gui"""
        self.window = gtk.Window


if __name__ == "__main__":
    # configuring logging
    interactive = sys.stdin.isatty()
    if interactive:
        # logs to file and to terminal
        log = Log(log_path=config.SECURITYLOG, interactive=True, log_syslog=False, log_level=log_level)
    else:
        log = Log(log_path=config.SECURITYLOG, interactive=False, log_level=log_level)

    print "Starting gui.."
