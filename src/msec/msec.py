#!/usr/bin/python -O
"""This is the main msec module.
It checks/sets the security levels, configures security variables,
and works as a frontend to libmsec.
"""

import sys
import os
import string
import getopt
import gettext
import imp
import re

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
    gettext.install('msec')
except IOError:
    _ = str

# {{{ usage
def usage():
    """Prints help message"""
    print """Msec: Mandriva Security Center (%s).

When run without parameters, msec will read the configuration from
/etc/security/msec/msec.conf, and enforce the specified security settings.
If no configuration file is found on the system, a default configuration
will be created.

Arguments to msec:
    -h, --help              displays this helpful message.
    -l, --level <level>     displays configuration for specified security
                            level.
    -f, --force <level>     force new level, overwriting user settings.
    -d                      enable debugging messages.
    -p, --pretend           only pretend to change the level, perform no real
                            actions. Use this to see what operations msec
                            will perform.
    -r, --root <path>       path to use as root
    -q, --quiet             run quietly
    -s, --save <level>      save current configuration as a new security level
""" % version
# }}}

if __name__ == "__main__":
    # default options
    force_level = False
    log_level = logging.INFO
    commit = True
    root = ''
    quiet = False
    save = False

    # parse command line
    try:
        opt, args = getopt.getopt(sys.argv[1:], 'hl:f:dpr:qs:', ['help', 'list=', 'force=', 'debug', 'pretend', 'root=', 'quiet', 'save='])
    except getopt.error:
        usage()
        sys.exit(1)
    for o in opt:
        # help
        if o[0] == '-h' or o[0] == '--help':
            usage()
            sys.exit(0)
        # list
        elif o[0] == '-l' or o[0] == '--list':
            level = o[1]
            log = Log(interactive=True, log_syslog=False, log_file=False)
            levelconf = config.load_defaults(log, level)
            params = levelconf.list_options()
            if not params:
                print >>sys.stderr, _("Invalid security level '%s'.") % level
                sys.exit(1)
            for item in params:
                print "%s=%s" % (item, levelconf.get(item) )
            sys.exit(0)
        # force new level
        elif o[0] == '-f' or o[0] == '--force':
            level = o[1]
            force_level = True
        # save as new security level
        elif o[0] == '-s' or o[0] == '--save':
            level = o[1]
            save = True
        # custom root
        elif o[0] == '-r' or o[0] == '--root':
            root = o[1]
        # debugging
        elif o[0] == '-d' or o[0] == '--debug':
            log_level = logging.DEBUG
        # check-only mode
        elif o[0] == '-p' or o[0] == '--pretend':
            commit = False
        elif o[0] == '-q' or o[0] == '--quiet':
            quiet = True

    # verifying use id
    if os.geteuid() != 0:
        print >>sys.stderr, _("Msec: Mandriva Security Center (%s)\n") % version
        print >>sys.stderr, _("Error: This application must be executed by root!")
        print >>sys.stderr, _("Run with --help to get help.")
        sys.exit(1)

    # configuring logging
    interactive = sys.stdin.isatty()
    if interactive:
        # logs to file and to terminal
        log = Log(log_path="%s%s" % (root, config.SECURITYLOG), interactive=True, log_syslog=False, log_level=log_level, quiet=quiet)
    else:
        # TODO: review logging messages
        #log_level = logging.WARN
        log = Log(log_path="%s%s" % (root, config.SECURITYLOG), interactive=False, log_syslog=False, log_level=log_level, quiet=quiet)

    # loading initial config
    msec_config = config.MsecConfig(log, config="%s%s" % (root, config.SECURITYCONF))
    permconf = None
    # loading permissions
    permconf = config.PermConfig(log, config="%s%s" % (root, config.PERMCONF))
    permconf.load()

    # forcing new level
    if force_level:
        # first load the default configuration for level
        levelconf = config.load_defaults(log, level, root=root)
        params = levelconf.list_options()
        if not params:
            log.error(_("Level '%s' not found, aborting.") % level)
            sys.exit(1)
        log.info(_("Switching to '%s' level.") % level)
        msec_config.reset()
        msec_config.merge(levelconf, overwrite=True)
        # now saving new permissions
        standard_permconf = config.load_default_perms(log, level, root=root)
        params = standard_permconf.list_options()
        if not params:
            log.error(_("No custom file permissions for level '%s'.") % level)
        log.info(_("Saving file permissions to '%s' level.") % level)
        # updating base level
        permconf.reset()
        permconf.merge(standard_permconf, overwrite=True)
    else:
        msec_config.load()

    # load base levels
    baselevel_name = msec_config.get_base_level()
    if baselevel_name:
        levelconf = config.load_defaults(log, baselevel_name, root=root)
        standard_permconf = config.load_default_perms(log, baselevel_name, root=root)

    # load variables from base levels
    config.merge_with_baselevel(log, msec_config, msec_config.get_base_level(), config.load_defaults, root='')
    config.merge_with_baselevel(log, permconf, msec_config.get_base_level(), config.load_default_perms, root='')

    # saving current setting as new level
    if save:
        newlevel = config.MsecConfig(log, config=config.SECURITY_LEVEL % (root, level))
        newlevel.merge(msec_config, overwrite=True)
        # update new level name
        newlevel.set("BASE_LEVEL", level)
        newlevel.save()
        # saving new file permissions, if any
        newpermlevel = config.PermConfig(log, config=config.PERMISSIONS_LEVEL % (root, level))
        newpermlevel.merge(permconf, overwrite=True)
        newpermlevel.save()
        sys.exit(0)

    # load the msec library
    msec = MSEC(log, root=root)

    # apply the config to msec
    msec.apply(msec_config)
    # writing back changes
    msec.commit(commit)
    # saving updated config
    if commit:
        if not msec_config.save(levelconf):
            log.error(_("Unable to save config!"))
        if not permconf.save(standard_permconf):
            log.error(_("Unable to save file system permissions!"))
    sys.exit(0)
