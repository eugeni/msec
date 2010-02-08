#!/usr/bin/python
"""Msec plugin for running sectool tests"""

# main plugin class name
PLUGIN = "sectool"

import os
import re
import gettext
import sys

# configuration
import config

# localization
try:
    gettext.install('msec')
except IOError:
    _ = str

class sectool:
    SECTOOL_LEVELS = ["1", "2", "3", "4", "5"]
    def __init__(self, log=None, configfiles=None, root=None):
        """This plugin provides support for RedHat's sectool"""
        # initializing plugin
        self.log = log
        self.configfiles = configfiles
        self.root = root

        config.SETTINGS['CHECK_SECTOOL'] = ("sectool.check_sectool", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_SECTOOL_LEVEL'] = ("sectool.check_sectool_level", self.SECTOOL_LEVELS)

        config.SETTINGS_PERIODIC.extend(['CHECK_SECTOOL', 'CHECK_SECTOOL_LEVEL'])

        # defining additional packages that should be installed
        config.REQUIRE_PACKAGES['CHECK_SECTOOL_LEVEL'] = (['yes'], ['sectool'])


    def check_sectool(self, param):
        """Enable sectools checks. This check will run all sectool checks for a security level configuration. The security level to be used during this test is determined by the CHECK_SECTOOL_LEVELS variable."""
        pass

    def check_sectool_level(self, param):
        """Defines the sectool level to use during the periodic security check. You may use the sectool-gui application to select individual tests for each level. If this variable is not defined, the default level defined in sectool configuration will be used."""
        pass
