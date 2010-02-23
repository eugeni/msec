#!/usr/bin/python
"""Msec plugin for sudo"""

# main plugin class name
PLUGIN = "sudo"

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

class sudo:
    SUDOERS="/etc/sudoers"
    SUDO_WHEEL_MATCH = re.compile("^\s*%wheel\s+ALL\s*=\s*\(ALL\)\s+(NOPASSWD:)?\s*ALL")
    SUDO_WHEEL = "%wheel\tALL=(ALL)\tALL"
    SUDO_WHEEL_NO_PASSWORD="%wheel\tALL=(ALL)\tNOPASSWD: ALL"
    def __init__(self, log=None, configfiles=None, root=None):
        """This plugin provides support for configuring sudo settings"""
        # initializing plugin
        self.log = log
        self.configfiles = configfiles
        self.root = root

        config.SETTINGS['ALLOW_SUDO_TO_WHEEL'] = ("sudo.allow_sudo_to_wheel", ["yes", "without-password", "no"])

        config.SETTINGS_SYSTEM.extend(['ALLOW_SUDO_TO_WHEEL'])

        # defining additional packages that should be installed
        config.REQUIRE_PACKAGES['ALLOW_SUDO_TO_WHEEL'] = (['yes', 'without-password'], ['sudo'])

    def allow_sudo_to_wheel(self, param):
        """Allow users in wheel group to use sudo. If this option is set to 'yes', the users in wheel group are allowed to use sudo and run commands as root by using their passwords. If this option to set to 'without-password', the users can use sudo without being asked for their password. WARNING: using sudo without any password makes your system very vulnerable, and you should only use this setting if you know what you are doing!"""
        sudoers = self.configfiles.get_config_file(self.SUDOERS)
        val = sudoers.get_match(self.SUDO_WHEEL_MATCH)

        if param != val:
            if param == "yes":
                if val and val.find('NOPASSWD:') < 0:
                        return
                self.log.info(_("Allowing users in wheel group to use sudo"))
                sudoers.replace_line_matching(self.SUDO_WHEEL_MATCH, self.SUDO_WHEEL, at_end_if_not_found=1)
            elif param == "without-password":
                if val and val.find('NOPASSWD:') >= 0:
                    return
                self.log.info(_("Allowing users in wheel group to use sudo without password"))
                sudoers.replace_line_matching(self.SUDO_WHEEL_MATCH, self.SUDO_WHEEL_NO_PASSWORD, at_end_if_not_found=1)
            else:
                self.log.info(_("Not allowing users in wheel group to use sudo"))
                sudoers.remove_line_matching(self.SUDO_WHEEL_MATCH)
