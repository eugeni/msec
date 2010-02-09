#!/usr/bin/python
"""Msec plugin for log file handling"""

# main plugin class name
PLUGIN = "log"

import re
import gettext

# configuration
import config

# localization
try:
    gettext.install('msec')
except IOError:
    _ = str

class log:
    # configuration variables
    # logrotate file
    LOGROTATE = '/etc/logrotate.conf'
    # pam
    LOGROTATE_ROTATE = re.compile('^rotate\s*(\d+)$')

    def __init__(self, log=None, configfiles=None, root=None):
        # initializing plugin
        self.log = log
        self.configfiles = configfiles
        self.root = root

        # configuring entry in global settings
        config.SETTINGS['LOG_RETENTION'] = ("log.log_retention", ['*'])

        # insert entry into system security settings
        config.SETTINGS_SYSTEM.append('LOG_RETENTION')

    def log_retention(self, arg):
        '''Define the default retention period for logs, in weeks. Some countries require that the log files should be kept for 12 months, other do not have such strict requirements. This variable defines the number of past log files that should be kept by logrotate on the system.'''

        # verify parameter validity
        try:
            retention = int(arg)
        except:
            self.log.error(_('Invalid maximum password history length: "%s"') % arg)
            return

        logrotate = self.configfiles.get_config_file(self.LOGROTATE)

        val = logrotate.get_match(self.LOGROTATE_ROTATE)

        if val != retention:
            self.log.info(_("Setting log retention period to %d weeks") % retention)
            logrotate.replace_line_matching(self.LOGROTATE_ROTATE, ("rotate %d" % retention))
