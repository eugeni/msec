#!/usr/bin/python
"""Msec plugin for running sectool tests"""

# main plugin class name
PLUGIN = "sectool"

import os
import re
import gettext
import sys
import glob
import traceback

# configuration
import config

# localization
try:
    gettext.install('msec')
except IOError:
    _ = str

class sectool:
    def __init__(self, log=None, configfiles=None, root=None, sectool_path="/usr/share/sectool", sectool_config_path="/etc/sectool/"):
        # initializing plugin
        self.log = log
        self.configfiles = configfiles
        self.root = root

        self.sectool_path = sectool_path
        self.sectool_config_path = sectool_config_path

        # try importing sectool
        if not os.access(sectool_path, os.F_OK):
            # no sectool installed
            self.log.warning(_("sectool: Sectool is not installed, disabling sectool checks"))
            return
        try:
            sys.path.append(sectool_path)
            from scheduler import scheduler
        except:
            self.log.error(_("sectool: Error importing sectool library: %s" % (sys.exc_value)))
            return

        # find the list of sectool checks
        sectool_checks = glob.glob("%s/tests/*" % sectool_config_path)
        if not sectool_checks:
            self.log.info(_("sectool: No sectool checks found"))
            return
        for z in sectool_checks:
            try:
                check = scheduler.Description(z)
                name = check["HEADER"]["NAME"]
                func_name = ("sectool_%s" % name).upper()
                # create virtual functions for each test
                setattr(self, func_name, lambda x: True)
                func = getattr(self, func_name)
                func.__doc__ = check["HEADER"]["DESCRIPTION"]
                config.SETTINGS_PERIODIC.append(func_name)
                config.SETTINGS[func_name] = ("sectool.%s" % func_name, ['yes', 'no'])
            except:
                traceback.print_exc()
        print sectool_checks

        # configuring entry in global settings
        config.SETTINGS['ENABLE_PAM_WHEEL_FOR_SU'] = ("pam.enable_pam_wheel_for_su", ['yes', 'no'])
        config.SETTINGS['ENABLE_PAM_ROOT_FROM_WHEEL'] = ("pam.enable_pam_root_from_wheel", ['yes', 'no'])
        # password stuff
        config.SETTINGS['ENABLE_PASSWORD'] = ("pam.enable_password", ['yes', 'no'])
        config.SETTINGS['PASSWORD_HISTORY'] = ("pam.password_history", ['*'])
        #                                     format: min length, num upper, num digits
        config.SETTINGS['PASSWORD_LENGTH'] = ("pam.password_length", ['*'])

        # insert entry into system security settings
        config.SETTINGS_SYSTEM.append('ENABLE_PAM_WHEEL_FOR_SU')
        config.SETTINGS_SYSTEM.append('ENABLE_PAM_ROOT_FROM_WHEEL')
        config.SETTINGS_SYSTEM.append('ENABLE_PASSWORD')
        config.SETTINGS_SYSTEM.append('PASSWORD_HISTORY')
        config.SETTINGS_SYSTEM.append('PASSWORD_LENGTH')

