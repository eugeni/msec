#!/usr/bin/python
"""Msec plugin for auditing checks"""

# main plugin class name
PLUGIN = "audit"

# configuration
import config

import gettext
# localization
try:
    gettext.install('msec')
except IOError:
    _ = str

CRON = '/etc/cron.d/msec'
CRON_REGEX = '[^#]+/usr/share/msec/promisc_check.sh'
CRON_ENTRY = '*/1 * * * *    root    /usr/share/msec/promisc_check.sh'
SECURITYCRON = '/etc/cron.daily/msec'
SECURITYSH = '/usr/share/msec/security.sh'

class audit:
    def __init__(self, log=None, configfiles=None, root=None):
        """This plugins is responsible for all auditing checks, which are performed by
        /usr/share/msec/security.sh. The following functions are used as wrappers,
        and are defined by msecgui."""
        self.log = log
        self.configfiles = configfiles
        self.root = root

        # defining the checks
        config.SETTINGS['CHECK_PERMS'] = ("audit.check_perms", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_PERMS_ENFORCE'] = ("audit.check_perms_enforce", config.VALUES_YESNO)
        config.SETTINGS['CHECK_USER_FILES'] = ("audit.check_user_files", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_SUID_ROOT'] = ("audit.check_suid_root", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_SUID_MD5'] = ("audit.check_suid_md5", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_SGID'] = ("audit.check_sgid", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_WRITABLE'] = ("audit.check_writable", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_UNOWNED'] = ("audit.check_unowned", config.VALUES_PERIODIC)
        config.SETTINGS['FIX_UNOWNED'] = ("audit.fix_unowned", config.VALUES_YESNO)
        config.SETTINGS['CHECK_PROMISC'] = ("audit.check_promisc", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_OPEN_PORT'] = ("audit.check_open_port", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_FIREWALL'] = ("audit.check_firewall", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_PASSWD'] = ("audit.check_passwd", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_SHADOW'] = ("audit.check_shadow", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_CHKROOTKIT'] = ("audit.check_chkrootkit", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_RPM_PACKAGES'] = ("audit.check_rpm_packages", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_RPM_INTEGRITY'] = ("audit.check_rpm_integrity", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_SHOSTS'] = ("audit.check_shosts", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_USERS'] = ("audit.check_users", config.VALUES_PERIODIC)
        config.SETTINGS['CHECK_GROUPS'] = ("audit.check_groups", config.VALUES_PERIODIC)
        # notifications
        config.SETTINGS['TTY_WARN'] = ("audit.tty_warn", config.VALUES_YESNO)
        config.SETTINGS['MAIL_WARN'] = ("audit.mail_warn", config.VALUES_YESNO)
        config.SETTINGS['MAIL_USER'] = ("audit.mail_user", ['*'])
        config.SETTINGS['MAIL_EMPTY_CONTENT'] = ("audit.mail_empty_content", config.VALUES_YESNO)
        config.SETTINGS['SYSLOG_WARN'] = ("audit.syslog_warn", config.VALUES_YESNO)
        config.SETTINGS['NOTIFY_WARN'] = ("audit.notify_warn", config.VALUES_YESNO)
        # security checks from audit plugins
        config.SETTINGS['CHECK_SECURITY'] = ("audit.check_security", config.VALUES_YESNO)
        config.SETTINGS['CHECK_ON_BATTERY'] = ("audit.check_on_battery", config.VALUES_YESNO)

        # defining additional packages that should be installed
        config.REQUIRE_PACKAGES['CHECK_CHKROOTKIT'] = (['yes'], ['chkrootkit'])

        # preparing msecgui menu
        for check in ["CHECK_PERMS", "CHECK_PERMS_ENFORCE", "CHECK_USER_FILES", "CHECK_SUID_ROOT", "CHECK_SUID_MD5", "CHECK_SGID",
                    "CHECK_WRITABLE", "CHECK_UNOWNED", "FIX_UNOWNED", "CHECK_PROMISC", "CHECK_OPEN_PORT", "CHECK_FIREWALL",
                    "CHECK_PASSWD", "CHECK_SHADOW", "CHECK_CHKROOTKIT", "CHECK_RPM_PACKAGES", "CHECK_RPM_INTEGRITY",
                    "CHECK_SHOSTS", "CHECK_USERS", "CHECK_GROUPS",
                    "TTY_WARN", "SYSLOG_WARN", "MAIL_EMPTY_CONTENT", "CHECK_ON_BATTERY"]:
            config.SETTINGS_PERIODIC.append(check)

        # checks with exceptions
        for check in ["CHECK_PERMS", "CHECK_USER_FILES", "CHECK_SUID_ROOT", "CHECK_SUID_MD5", "CHECK_SGID",
                    "CHECK_WRITABLE", "CHECK_UNOWNED", "CHECK_OPEN_PORT", "CHECK_FIREWALL",
                    "CHECK_PASSWD", "CHECK_SHADOW", "CHECK_RPM_PACKAGES", "CHECK_RPM_INTEGRITY",
                    "CHECK_SHOSTS", "CHECK_USERS", "CHECK_GROUPS"]:
            config.CHECKS_WITH_EXCEPTIONS.append(check)

    # The following checks are run from crontab. We only have these functions here
    # to get their descriptions.

    def check_perms(self, param):
        """ Enable periodic permission checking for files specified in msec policy."""
        pass

    def check_perms_enforce(self, param):
        """ Enable msec to enforce file permissions to the values specified in the msec security policy."""
        pass

    def check_user_files(self, param):
        """ Enable permission checking on users' files that should not be owned by someone else, or writable."""
        pass

    def check_suid_root(self, param):
        """ Enable checking for additions/removals of suid root files."""
        pass

    def check_suid_md5(self, param):
        """ Enable checksum verification for suid files."""
        pass

    def check_sgid(self, param):
        """ Enable checking for additions/removals of sgid files."""
        pass

    def check_writable(self, param):
        """ Enable checking for files/directories writable by everybody."""
        pass

    def check_unowned(self, param):
        """ Enable checking for unowned files."""
        pass

    def fix_unowned(self, param):
        """ Fix owner and group of unowned files to use nobody/nogroup."""
        pass

    def check_open_port(self, param):
        """ Enable checking for open network ports."""
        pass

    def check_firewall(self, param):
        """ Enable checking for changes in firewall settings."""
        pass

    def check_passwd(self, param):
        """ Enable password-related checks, such as empty passwords and strange super-user accounts."""
        pass

    def check_shadow(self, param):
        """ Enable checking for empty passwords in /etc/shadow (man shadow(5))."""
        pass

    def check_chkrootkit(self, param):
        """ Enable checking for known rootkits using chkrootkit."""
        pass

    def check_rpm_packages(self, param):
        """ Enable verification for changes in the installed RPM packages. This will notify you when new packages are installed or removed."""
        pass

    def check_rpm_integrity(self, param):
        """ Enable verification of integrity of installed RPM packages. This will notify you if checksums of the installed files were changed, showing separate results for binary and configuration files."""
        pass

    def tty_warn(self, param):
        """ Enable periodic security check results to terminal."""
        pass

    def mail_warn(self, param):
        """ Send security check results by email."""
        pass

    def mail_empty_content(self, param):
        """ Send mail reports even if no changes were detected."""
        pass

    def syslog_warn(self, param):
        """ Enables logging of periodic checks to system log."""
        pass

    def mail_user(self, param):
        """ User email to receive security notifications."""
        pass

    def check_shosts(self, param):
        """ Enable checking for dangerous options in users' .rhosts/.shosts files."""
        pass

    def check_users(self, param):
        """ Enable checking for changes in system users."""
        pass

    def check_groups(self, param):
        """ Enable checking for changes in system groups."""
        pass

    def notify_warn(self, param):
        """Show security notifications in system tray using libnotify."""
        pass

    def check_on_battery(self, param):
        """Run security checks when machine is running on battery power."""
        pass

    def check_promisc(self, param):
        '''  Activate ethernet cards promiscuity check.'''
        cron = self.configfiles.get_config_file(CRON)

        val = cron.get_match(CRON_REGEX)

        if param == "yes":
            if val != CRON_ENTRY:
                self.log.info(_('Activating periodic promiscuity check'))
                cron.replace_line_matching(CRON_REGEX, CRON_ENTRY, 1)
        else:
            if val:
                self.log.info(_('Disabling periodic promiscuity check'))
                cron.remove_line_matching('[^#]+/usr/share/msec/promisc_check.sh')

    def check_security(self, arg):
        """ Enable daily security checks."""
        cron = self.configfiles.get_config_file(CRON)
        cron.remove_line_matching('[^#]+/usr/share/msec/security.sh')

        securitycron = self.configfiles.get_config_file(SECURITYCRON)

        if arg == "yes":
            if not securitycron.exists():
                self.log.info(_('Activating daily security check'))
                securitycron.symlink(SECURITYSH)
        else:
            if securitycron.exists():
                self.log.info(_('Disabling daily security check'))
                securitycron.unlink()

