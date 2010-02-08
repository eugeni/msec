#!/usr/bin/python
"""Msec plugin for enforcing pam-related settings"""

# main plugin class name
PLUGIN = "pam"

import os
import re
import gettext
import grp

# configuration
import config

# localization
try:
    gettext.install('msec')
except IOError:
    _ = str

class pam:
    # configuration variables
    SIMPLE_ROOT_AUTHEN = '/etc/pam.d/simple_root_authen'
    SU = '/etc/pam.d/su'
    SYSTEM_AUTH = '/etc/pam.d/system-auth'
    # pam
    SUCCEED_MATCH = '^auth\s+sufficient\s+pam_succeed_if.so\s+use_uid\s+user\s+ingroup\s+wheel\s*$'
    SUCCEED_LINE = 'auth       sufficient   pam_succeed_if.so use_uid user ingroup wheel'
    # password stuff
    LENGTH_REGEXP = re.compile('^(password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*?)\sminlen=([0-9]+)\s(.*)')
    NDIGITS_REGEXP = re.compile('^(password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*?)\sdcredit=([0-9]+)\s(.*)')
    UCREDIT_REGEXP = re.compile('^(password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*?)\sucredit=([0-9]+)\s(.*)')
    PASSWORD_REGEXP = '^\s*auth\s+sufficient\s+(?:/lib/security/)?pam_permit.so'
    UNIX_REGEXP = re.compile('(^\s*password\s+sufficient\s+(?:/lib/security/)?pam_unix.so.*)\sremember=([0-9]+)(.*)')
    PAM_TCB_REGEXP = re.compile('(^\s*password\s+sufficient\s+(?:/lib/security/)?pam_tcb.so.*)')

    def __init__(self, log=None, configfiles=None, root=None):
        # initializing plugin
        self.log = log
        self.configfiles = configfiles
        self.root = root

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

    def enable_password(self, arg):
        ''' Use password to authenticate users. Take EXTREME care when disabling passwords, as it will leave the machine vulnerable.'''
        system_auth = self.configfiles.get_config_file(self.SYSTEM_AUTH)

        val = system_auth.get_match(self.PASSWORD_REGEXP)

        if arg == "yes":
            if val:
                self.log.info(_('Using password to authenticate users'))
                system_auth.remove_line_matching(self.PASSWORD_REGEXP)
        else:
            if not val:
                self.log.info(_('Don\'t use password to authenticate users'))
                system_auth.replace_line_matching(self.PASSWORD_REGEXP, 'auth        sufficient    pam_permit.so') or \
                system_auth.insert_before('auth\s+sufficient', 'auth        sufficient    pam_permit.so')

    def password_history(self, arg):
        ''' Set the password history length to prevent password reuse. This is not supported by pam_tcb. '''

        system_auth = self.configfiles.get_config_file(self.SYSTEM_AUTH)

        pam_tcb = system_auth.get_match(self.PAM_TCB_REGEXP)
        if pam_tcb:
            self.log.info(_('Password history not supported with pam_tcb.'))
            return

        # verify parameter validity
        # max
        try:
            history = int(arg)
        except:
            self.log.error(_('Invalid maximum password history length: "%s"') % arg)
            return

        if system_auth.exists():
            val = system_auth.get_match(self.UNIX_REGEXP, '@2')

            if val and val != '':
                val = int(val)
            else:
                val = 0
        else:
            val = 0

        if history != val:
            if history > 0:
                self.log.info(_('Setting password history to %d.') % history)
                system_auth.replace_line_matching(self.UNIX_REGEXP, '@1 remember=%d@3' % history) or \
                system_auth.replace_line_matching('(^\s*password\s+sufficient\s+(?:/lib/security/)?pam_unix.so.*)', '@1 remember=%d' % history)
                opasswd = self.configfiles.get_config_file(self.OPASSWD)
                opasswd.exists() or opasswd.touch()
            else:
                self.log.info(_('Disabling password history'))
                system_auth.replace_line_matching(self.UNIX_REGEXP, '@1@3')

    def password_length(self, arg):
        ''' Set the password minimum length and minimum number of digit and minimum number of capitalized letters, using length,ndigits,nupper format.'''

        try:
            length, ndigits, nupper = arg.split(",")
            length = int(length)
            ndigits = int(ndigits)
            nupper = int(nupper)
        except:
            self.log.error(_('Invalid password length "%s". Use "length,ndigits,nupper" as parameter') % arg)
            return

        passwd = self.configfiles.get_config_file(self.SYSTEM_AUTH)

        val_length = val_ndigits = val_ucredit = 999999

        if passwd.exists():
            val_length  = passwd.get_match(self.LENGTH_REGEXP, '@2')
            if val_length:
                val_length = int(val_length)

            val_ndigits = passwd.get_match(self.NDIGITS_REGEXP, '@2')
            if val_ndigits:
                val_ndigits = int(val_ndigits)

            val_ucredit = passwd.get_match(self.UCREDIT_REGEXP, '@2')
            if val_ucredit:
                val_ucredit = int(val_ucredit)

        if passwd.exists() and (val_length != length or val_ndigits != ndigits or val_ucredit != nupper):
            self.log.info(_('Setting minimum password length %d') % length)
            (passwd.replace_line_matching(self.LENGTH_REGEXP,
                                          '@1 minlen=%s @3' % length) or \
             passwd.replace_line_matching('^password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*',
                                          '@0 minlen=%s ' % length))

            (passwd.replace_line_matching(self.NDIGITS_REGEXP,
                                          '@1 dcredit=%s @3' % ndigits) or \
             passwd.replace_line_matching('^password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*',
                                          '@0 dcredit=%s ' % ndigits))

            (passwd.replace_line_matching(self.UCREDIT_REGEXP,
                                          '@1 ucredit=%s @3' % nupper) or \
             passwd.replace_line_matching('^password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*',
                                          '@0 ucredit=%s ' % nupper))

    def enable_pam_wheel_for_su(self, arg):
        ''' Allow only users in wheel group to su to root.'''
        su = self.configfiles.get_config_file(self.SU)

        val = su.get_match('^auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$')

        if arg == "yes":
            if not val:
                self.log.info(_('Allowing su only from wheel group members'))
                try:
                    ent = grp.getgrnam('wheel')
                except KeyError:
                    error(_('no wheel group'))
                    return
                members = ent[3]
                if members == [] or members == ['root']:
                    self.log.error(_('Security configuration is defined to allow only members of the wheel group to su to root, but this group is empty. Please add the allowed users into the wheel group.'))
                    return
                if su.exists():
                    (su.replace_line_matching('^[#\s]*auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$',
                                                          'auth       required     pam_wheel.so use_uid') or \
                                 su.insert_before('^auth\s+include', 'auth       required     pam_wheel.so use_uid'))
        else:
            if val:
                self.log.info(_('Allowing su for all'))
                if su.exists():
                    su.replace_line_matching('^auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$',
                                                          '# auth       required     pam_wheel.so use_uid')

    def enable_pam_root_from_wheel(self, arg):
        '''   Allow root access without password for the members of the wheel group.'''
        su = self.configfiles.get_config_file(self.SU)
        simple = self.configfiles.get_config_file(self.SIMPLE_ROOT_AUTHEN)

        if not su.exists():
            return

        val = su.get_match(self.SUCCEED_MATCH)

        val_simple = simple.get_match(self.SUCCEED_MATCH)

        if arg == "yes":
            if not val or not val_simple:
                self.log.info(_('Allowing transparent root access for wheel group members'))
                if not val:
                    su.insert_before('^auth\s+sufficient', self.SUCCEED_LINE)
                if simple.exists() and not val_simple:
                    simple.insert_before('^auth\s+sufficient', self.SUCCEED_LINE)
        else:
            if val or val_simple:
                self.log.info(_('Disabling transparent root access for wheel group members'))
                if val:
                    su.remove_line_matching(self.SUCCEED_MATCH)
                if simple.exists() and val_simple:
                    simple.remove_line_matching(self.SUCCEED_MATCH)

