#!/usr/bin/python
"""PolicyKit plugin for msec """

# main plugin class name
PLUGIN = "policykit"

import os

# configuration
import config

class policykit:
    def __init__(self, log=None, configfiles=None, root=None):
        # initializing plugin
        self.log = log
        self.configfiles = configfiles
        self.root = root

        # configuring entry in global settings
        param = 'ENABLE_POLICYKIT'
        callback = "%s.enable_policykit" % PLUGIN
        valid_values = ['yes', 'no']
        config.SETTINGS[param] = (callback, valid_values)

        # insert entry into system security settings
        config.SETTINGS_SYSTEM.append(param)

    def enable_policykit(self, params):
        """Enable PolicyKit security framework"""
        if self.log:
            #self.log.info("policykit plugin: not implemented yet!")
            pass
