#!/usr/bin/python -O
"""This is the configuration file for msec.
The following variables are defined here:
    SECURITY_LEVELS: list of supported security levels
    SECURITYCONF: location of msec configuration file
    SECURITYLOG: log file for msec messages
    SETTINGS: all security settings, with correspondent options for each
              level, callback functions, and regexp of valid parameters.

A helper function load_defaults parses the SETTINGS variable.

The MsecConfig class processes the main msec configuration file.
"""

import gettext
import sys
import traceback
import re
import os
import glob

# security levels
NONE_LEVEL="none"
STANDARD_LEVEL="standard"
SECURE_LEVEL="secure"
SECURITY_LEVEL="%s/etc/security/msec/level.%s"

# msec configuration file
SECURITYCONF = '/etc/security/msec/security.conf'
EXCEPTIONSCONF = '/etc/security/msec/exceptions'

# permissions
PERMCONF = '/etc/security/msec/perms.conf'
PERMISSIONS_LEVEL = '%s/etc/security/msec/perm.%s' # for level

# logging
SECURITYLOG = '/var/log/msec.log'

# localization
try:
    gettext.install('msec')
except IOError:
    _ = str

# shared strings
MODIFICATIONS_FOUND = _('Modified system files')
MODIFICATIONS_NOT_FOUND = _('No changes in system files')

# plugins
MSEC_DIR="/usr/share/msec"
MAIN_LIB="libmsec"
PLUGINS_DIR="/usr/share/msec/plugins"

# msec callbacks and valid values
#               OPTION                           callback                            valid values
SETTINGS =    {
               'BASE_LEVEL':                    ("libmsec.base_level",                      ['*']),
              }
# text for disabled options
OPTION_DISABLED=_("Disabled")

# options for periodic checks
VALUES_PERIODIC=['manual', 'daily', 'weekly', 'monthly', 'no']
# options for yes-no checks
VALUES_YESNO=['yes', 'no']

# some checks require installation of additional packages if a specific option was activated
REQUIRE_PACKAGES = {
        # the format is: 'OPTION_NAME': (['option values which requires package installation]', ['packages'])
        # for example, 'CHECK_CHKROOTKIT': (['yes'], ['chkrootkit'])
        }

# settings organizes by category
# system security settings - defined by 'msec' plugin
SETTINGS_SYSTEM = []
# network security settings - defined by 'msec' plugin
SETTINGS_NETWORK = []
# periodic checks - defined by 'audit' plugin
SETTINGS_PERIODIC = []

# checks that support exceptions - defined by 'audit' plugin
CHECKS_WITH_EXCEPTIONS = []

# localized help
try:
    from help import HELP
except:
    HELP = {}

# helper function to find documentation for an option
def find_doc(msec, option, cached=None):
    """Helper function to find documentation for an option."""
    if option not in SETTINGS:
        # invalid option ?
        return None
    callback, values = SETTINGS[option]
    # is it already cached?
    if option in cached:
        return cached[option]
    if option in HELP:
        doc = HELP[option]
    else:
        # option not found in HELP, lets look in docstring
        # get description from function comments
        func = msec.get_action(callback)
        if func.__doc__:
            doc = func.__doc__.strip()
        else:
            # well, no luck. Just use the callback then
            doc = callback
    # updated cached values
    if cached:
        cached[option] = doc
    return doc

def find_callback(param):
    '''Finds a callback for security option'''
    if param not in SETTINGS:
        return None
    else:
        callback, valid_params = SETTINGS[param]
        return callback

def find_valid_params(param):
    '''Finds valid parameters for security option'''
    if param not in SETTINGS:
        return None
    else:
        callback, valid_params = SETTINGS[param]
        return valid_params

# helper functions
def list_available_levels(log, root=''):
    """Lists available msec levels"""
    path = SECURITY_LEVEL % (root, "*")
    levels = []
    levels_glob = glob.glob(path)
    for z in levels_glob:
        # skip rpm junk
        if z.find(".rpmsave") >= 0 or z.find(".rpmnew") >= 0:
            continue
        levels_re = re.compile(".*/level.(.*)")
        levelname = levels_re.findall(z)
        if levelname:
            levels.append(levelname[0])
    return levels

def load_defaults(log, level, root=''):
    """Loads default configuration for given security level, returning a
        MsecConfig instance.
        """
    config = MsecConfig(log, config=SECURITY_LEVEL % (root, level))
    config.load()
    return config

def load_default_perms(log, level, root=''):
    """Loads default permissions for given security level, returning a
        MsecConfig instance.
        """
    config = PermConfig(log, config=PERMISSIONS_LEVEL % (root, level))
    config.load()
    return config

def merge_with_baselevel(log, config, base_level, load_func, root=''):
    """Merges a config with its base level"""
    # reloading levelconf for base level
    levelconf = load_func(log, base_level, root=root)
    config.merge(levelconf)


# {{{ MsecConfig
class MsecConfig:
    """Msec configuration parser"""
    def __init__(self, log, config=SECURITYCONF):
        self.config = config
        self.options = {}
        self.comments = []
        self.log = log
        self.base_level = None

    def merge(self, newconfig, overwrite=False):
        """Merges parameters from newconfig to current config"""
        for opt in newconfig.list_options():
            if overwrite:
                self.set(opt, newconfig.get(opt))
            else:
                self.get(opt, newconfig.get(opt))

    def reset(self):
        """Resets all configuration"""
        del self.options
        self.options = {}
        del self.comments
        self.comments = []

    def get_base_level(self, base_level=None):
        """Configures base level for current level, so the settings could be pulled from it"""
        if not base_level:
            base_level = self.get('BASE_LEVEL')
        self.base_level = base_level
        return self.base_level

    def load(self):
        """Loads and parses configuration file"""
        if not self.config:
            # No associated file
            return True
        try:
            fd = open(self.config)
        except:
            self.log.error(_("Unable to load configuration file %s: %s") % (self.config, sys.exc_value[1]))
            return False
        for line in fd.readlines():
            line = line.strip()
            if not line:
                continue
            if line[0] == "#":
                # comment
                self.comments.append(line)
                continue
            try:
                option, val = line.split("=", 1)
                self.options[option] = val
            except:
                self.log.warn(_("Bad config option: %s") % line)
                continue
        fd.close()
        return True

    def get(self, option, default=None):
        """Gets a configuration option, or defines it if not defined"""
        if option not in self.options:
            self.options[option] = default
        return self.options[option]

    def remove(self, option):
        """Removes a configuration option."""
        if option in self.options:
            self.options[option]=None

    def set(self, option, value):
        """Sets a configuration option"""
        self.options[option] = value

    def list_options(self):
        """Sorts and returns configuration parameters"""
        sortedparams = self.options.keys()
        if sortedparams:
            sortedparams.sort()
        return sortedparams

    def save(self, base_level=None):
        """Saves configuration. Comments go on top. If a variable is present in base_level, and it is identical to the one to be saved, it is skipped"""
        if not self.config:
            # No associated file
            return True
        try:
            fd = open(self.config, "w")
        except:
            self.log.error(_("Unable to save %s: %s") % (self.config, sys.exc_value))
            return False
        for comment in self.comments:
            print >>fd, comment
        # sorting keys
        for option in self.list_options():
            value = self.options[option]
            # is it already on base level?
            if base_level:
                if option in base_level.options and option != "BASE_LEVEL":
                    if value == base_level.get(option):
                        self.log.debug("Option %s=%s already on base level!" % (option, value))
                        continue
            # prevent saving empty options
            # TODO: integrate with remove()
            if value == None or value == OPTION_DISABLED:
                self.log.debug("Skipping %s" % option)
                value=""
            print >>fd, "%s=%s" % (option, value)
        return True
# }}}

# {{{ ExceptionConfig
class ExceptionConfig:
    """Exceptions configuration parser"""
    def __init__(self, log, config=EXCEPTIONSCONF):
        self.config = config
        self.options = []
        self.comments = []
        self.log = log

    def reset(self):
        """Resets all configuration"""
        del self.options
        self.options = []
        del self.comments
        self.comments = []

    def load(self):
        """Loads and parses configuration file"""
        if not self.config:
            # No associated file
            return True
        try:
            fd = open(self.config)
        except:
            self.log.error(_("Unable to load configuration file %s: %s") % (self.config, sys.exc_value[1]))
            return False
        for line in fd.readlines():
            line = line.strip()
            if not line:
                continue
            if line[0] == "#":
                # comment
                self.comments.append(line)
                continue
            try:
                option, val = line.split(" ", 1)
                self.options.append((option, val))
            except:
                self.log.warn(_("Bad config option: %s") % line)
                continue
        fd.close()
        return True

    def get(self, pos, default=None):
        """Gets a configuration option, or defines it if not defined"""
        if pos > len(self.options):
            return default
        return self.options[pos]

    def remove(self, pos):
        """Removes a configuration option."""
        if pos < len(self.options):
            del self.options[pos]

    def set(self, pos, value):
        """Sets a configuration option"""
        if pos > 0:
            print "Pos: %d" % pos
            self.options[pos] = value
        else:
            self.options.append(value)

    def list_options(self):
        """Sorts and returns configuration parameters"""
        sortedparams = self.options
        if sortedparams:
            sortedparams.sort()
        return sortedparams

    def save(self):
        """Saves configuration. Comments go on top"""
        if not self.config:
            # No associated file
            return True
        try:
            fd = open(self.config, "w")
        except:
            self.log.error(_("Unable to save %s: %s") % (self.config, sys.exc_value))
            return False
        for comment in self.comments:
            print >>fd, comment
        # sorting keys
        for option,value in self.options:
            # TODO: integrate with remove()
            if value == None or value == OPTION_DISABLED:
                self.log.debug("Skipping %s" % option)
            else:
                print >>fd, "%s %s" % (option, value)
        return True
# }}}

# {{{ PermConfig
class PermConfig(MsecConfig):
    """Msec file permission parser"""
    def __init__(self, log, config=PERMCONF):
        self.config = config
        self.options = {}
        self.options_order = []
        self.comments = []
        self.log = log
        self.regexp = re.compile("^([^\s]*)\s*([a-z]*)\.([a-z]*)\s*([\d]?\d\d\d|current)\s*(force)?$")

    def merge(self, newconfig, overwrite=False):
        """Merges parameters from newconfig to current config"""
        for opt in newconfig.list_options():
            if overwrite:
                self.set(opt, newconfig.get(opt))
            else:
                self.get(opt, newconfig.get(opt))

    def reset(self):
        MsecConfig.reset(self)
        del self.options_order
        self.options_order = []

    def remove(self, option):
        """Removes a configuration option."""
        MsecConfig.remove(self, option)
        if option in self.options_order:
            pos = self.options_order.index(option)
            del self.options_order[pos]

    def load(self):
        """Loads and parses configuration file"""
        try:
            fd = open(self.config)
        except:
            self.log.error(_("Unable to load configuration file %s: %s") % (self.config, sys.exc_value))
            return False
        for line in fd.readlines():
            line = line.strip()
            if not line:
                continue
            if line[0] == "#":
                # comment
                self.comments.append(line)
                continue
            try:
                res = self.regexp.findall(line)
                if res:
                    if len(res[0]) == 5:
                        file, user, group, perm, force = res[0]
                    else:
                        force = None
                        file, user, group, perm = res[0]
                    self.options[file] = (user, group, perm, force)
                    self.options_order.append(file)
            except:
                traceback.print_exc()
                self.log.warn(_("Bad config option: %s") % line)
                continue
        fd.close()
        return True

    def list_options(self):
        """Sorts and returns configuration parameters"""
        return self.options_order

    def get(self, option, default=None):
        """Gets a configuration option, or defines it if not defined"""
        if option not in self.options:
            self.set(option, default)
        return self.options[option]

    def set(self, option, value):
        """Sets a configuration option"""
        self.options[option] = value
        if option not in self.options_order:
            self.options_order.append(option)

    def save(self, base_level=None):
        """Saves configuration. Comments go on top. If a variable is present in base_level, and it is identical to the one to be saved, it is skipped"""
        try:
            fd = open(self.config, "w")
        except:
            self.log.error(_("Unable to save %s: %s") % (self.config, sys.exc_value))
            return False
        for comment in self.comments:
            print >>fd, comment
        # sorting keys
        for file in self.options_order:
            value = self.options[file]
            if base_level:
                if file in base_level.options:
                    new_value = base_level.get(file)
                    if value == new_value:
                        self.log.debug("Option %s=%s already on base level!" % (file, value))
                        continue
            if not value:
                # the option was removed
                continue
            user, group, perm, force = value
            if force:
                force = "\tforce"
            else:
                force = ""
            print >>fd, "%s\t%s.%s\t%s%s" % (file, user, group, perm, force)
        return True
# }}}
