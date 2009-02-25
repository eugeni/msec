#!/usr/bin/python
"""AppArmor plugin for msec """

# main plugin class name
PLUGIN = "apparmor"

import os

# configuration
import config

class apparmor:
    def __init__(self, log=None, configfiles=None, root=None):
        # initializing plugin
        self.log = log
        self.configfiles = configfiles
        self.root = root

        # configuring entry in global settings
        param = 'ENABLE_APPARMOR'
        callback = "%s.enable_apparmor" % PLUGIN
        valid_values = ['yes', 'no']
        config.SETTINGS[param] = (callback, valid_values)

        # insert entry into system security settings
        config.SETTINGS_SYSTEM.append(param)

    def enable_apparmor(self, params):
        """Enable AppArmor security framework on boot"""
        if self.log:
            self.log.info("AppArmor plugin: not implemented yet!")
