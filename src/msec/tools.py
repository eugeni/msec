#!/usr/bin/python
#
# msec: helper tools
#

import os
import stat
import sys
import time
import locale

# localization
import gettext
try:
    gettext.install("msec")
except IOError:
    _ = str

# constants
FIREWALL_CMD = "drakfirewall &"
UPDATE_CMD = "MandrivaUpdate &"

def find_firewall_info(log):
    """Finds information about firewall"""
    # read firewall settings
    firewall_entries = []
    try:
        data = os.popen("iptables -S").readlines()
        for l in data:
            if l[:3] == "-A ":
                firewall_entries.append(l.strip())
    except:
        log.error(_("Unable to parse firewall configuration: %s") % sys.exc_value)
    # not find out if the firewall is enabled
    if len(firewall_entries) == 0:
        firewall_status = _("Disabled")
    else:
        firewall_status = _("Enabled, with %d rules") % len(firewall_entries)
    return firewall_status

def get_updates_status(log, updatedir="/var/lib/urpmi"):
    """Get current update status"""
    # just find out the modification time of /var/lib/urpmi
    try:
        ret = os.stat(updatedir)
        updated = time.localtime(ret[stat.ST_MTIME])
        updated_s = time.strftime(locale.nl_langinfo(locale.D_T_FMT), updated)
        status = _("Last updated: %s") % updated_s
    except:
        log.error(_("Unable to access %s: %s") % (updatedir, sys.exc_value))
        status = _("Unable to determine update status")
    return status
