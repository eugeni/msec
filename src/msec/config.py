#!/usr/bin/python -O
# Mandriva Linux - MSEC - configuration

# security levels
SECURITY_LEVELS = {
            "none": 0,
            "default": 1,
            "secure": 2
        }
DEFAULT_LEVEL="default"

# msec configuration file
SECURITYCONF = '/etc/security/msec/security.conf'
SECURITYLOG = '/var/log/msec.log'

# default parameters
#                                                   security level
#               OPTION                           none   default secure   callback         valid values
SETTINGS =    {'CHECK_SECURITY' :               (['yes', 'yes',  'yes'], "check_security", r'^(yes|no)$'),
               'CHECK_PERMS' :                  (['no',  'yes',  'yes'], "check_perms", r'^(yes|no)$'),
               'CHECK_SUID_ROOT' :              (['yes', 'yes',  'yes'], "check_suid_root", r'^(yes|no)$'),
               'CHECK_SUID_MD5' :               (['yes', 'yes',  'yes'], "check_suid_md5", r'^(yes|no)$'),
               'CHECK_SGID' :                   (['yes', 'yes',  'yes'], "check_sgid", r'^(yes|no)$'),
               'CHECK_WRITABLE' :               (['yes', 'yes',  'yes'], "check_writable", r'^(yes|no)$'),
               'CHECK_UNOWNED' :                (['no',  'no',   'yes'], "check_unowned", r'^(yes|no)$'),
               'CHECK_PROMISC' :                (['no',  'no',   'yes'], "check_promisc", r'^(yes|no)$'),
               'CHECK_OPEN_PORT' :              (['no',  'yes',  'yes'], "check_open_port", r'^(yes|no)$'),
               'CHECK_PASSWD' :                 (['no',  'yes',  'yes'], "check_passwd", r'^(yes|no)$'),
               'CHECK_SHADOW' :                 (['no',  'yes',  'yes'], "check_shadow", r'^(yes|no)$'),
               'CHECK_CHKROOTKIT' :             (['no',  'yes',  'yes'], "check_chkrootkit", r'^(yes|no)$'), # was: CHKROOTKIT_CHECK
               'CHECK_RPM' :                    (['no',  'yes',  'yes'], "check_rpm", r'^(yes|no)$'), # was: RPM_CHECK
               'CHECK_SHOSTS' :                 (['no',  'yes',  'yes'], "check_shosts", r'^(yes|no)$'),
               'TTY_WARN' :                     (['no',  'no',   'yes'], "tty_warn", r'^(yes|no)$'),
               'MAIL_WARN' :                    (['no',  'yes',  'yes'], "mail_warn", r'^(yes|no)$'),
               'MAIL_USER' :                    (['root','root','root'], "mail_user", r'^([a-zA-Z0-9@\.]*)$'),
               'MAIL_EMPTY_CONTENT':            (['no',  'no',   'yes'], "mail_empty_content", r'^(yes|no)$'),
               'SYSLOG_WARN' :                  (['yes', 'yes',  'yes'], "syslog_warn", r'^(yes|no)$'),
               # security options
               'USER_UMASK':                    (['022', '022',  '077'], "set_user_umask", r'^(\d\d\d)$'),
               'ROOT_UMASK':                    (['022', '022',  '077'], "set_root_umask", r'^(\d\d\d)$'),
               'WIN_PARTS_UMASK':               (['no',  'no',   '0'  ], "set_win_parts_umask", r'^(no|\d\d?\d?)$'),
               'ACCEPT_BOGUS_ERROR_RESPONSES':  (['no',  'no',   'no' ], "accept_bogus_error_responses", r'^(yes|no)$'),
               'ACCEPT_BROADCASTED_ICMP_ECHO':  (['yes', 'yes',  'no' ], "accept_broadcasted_icmp_echo", r'^(yes|no)$'),
               'ACCEPT_ICMP_ECHO':              (['yes', 'yes',  'yes'], "accept_icmp_echo", r'^(yes|no)$'),
               'ALLOW_AUTOLOGIN':               (['yes', 'yes',  'no' ], "allow_autologin", r'^(yes|no)$'),
               'ALLOW_REBOOT':                  (['yes', 'yes',  'no' ], "allow_reboot", r'^(yes|no)$'),
               'ALLOW_REMOTE_ROOT_LOGIN':       (['yes', 'without_password', 'no' ], "allow_remote_root_login", r'^(yes|no|without_password)$'),
               'ALLOW_ROOT_LOGIN':              (['yes', 'yes',  'no' ], "allow_root_login", r'^(yes|no)$'),
               'ALLOW_USER_LIST':               (['yes', 'yes',  'no' ], "allow_user_list", r'^(yes|no)$'),
               'ALLOW_X_CONNECTIONS':           (['yes', 'local','no' ], "allow_x_connections", r'^(yes|no|local)$'),
               'ALLOW_XAUTH_FROM_ROOT':         (['yes', 'yes',  'no' ], "allow_xauth_from_root", r'^(yes|no)$'),
               'ALLOW_XSERVER_TO_LISTEN':       (['yes', 'no',   'no' ], "allow_xserver_to_listen", r'^(yes|no)$'),
               'AUTHORIZE_SERVICES':            (['yes', 'yes','local'], "authorize_services", r'^(yes|no)$'),
               'CREATE_SERVER_LINK':            (['no',  'default','secure'], "create_server_link", r'^(no|default|secure)$'),
               'ENABLE_AT_CRONTAB':             (['yes',  'yes',  'no' ], "enable_at_crontab", r'^(yes|no)$'),
               'ENABLE_CONSOLE_LOG':            (['yes', 'yes',  'no' ], "enable_console_log", r'^(yes|no)$'),
               'ENABLE_DNS_SPOOFING_PROTECTION':(['yes', 'yes',  'yes'], "enable_ip_spoofing_protection", r'^(yes|no)$'),
               'ENABLE_IP_SPOOFING_PROTECTION': (['yes', 'yes',  'yes'], "enable_dns_spoofing_protection", r'^(yes|no)$'),
               'ENABLE_LOG_STRANGE_PACKETS':    (['no',  'yes',  'yes'], "enable_log_strange_packets", r'^(yes|no)$'),
               'ENABLE_MSEC_CRON':              (['no',  'yes',  'yes'], "enable_msec_cron", r'^(yes|no)$'),
               'ENABLE_PAM_ROOT_FROM_WHEEL':    (['no',  'no',   'no' ], "enable_pam_root_from_wheel", r'^(yes|no)$'),
               'ENABLE_SUDO':                   (['yes',  'wheel','no'], "enable_sudo", r'^(yes|no|wheel)$'),
               'ENABLE_PAM_WHEEL_FOR_SU':       (['no',  'no',   'yes'], "enable_pam_wheel_for_su", r'^(yes|no)$'),
               'ENABLE_SULOGIN':                (['no',  'no',   'yes'], "enable_sulogin", r'^(yes|no)$'),
               'ENABLE_APPARMOR':               (['no',  'no',   'yes'], "enable_apparmor", r'^(yes|no)$'),
               'ENABLE_POLICYKIT':              (['no',  'yes', 'local'], "enable_policykit", r'^(yes|no)$'),
               # password stuff
               'ENABLE_PASSWORD':               (['yes', 'yes',  'yes'], "enable_password", r'^(yes|no)$'),
               'PASSWORD_HISTORY':              (['0',   '0',    '2'  ], "password_history", r'^(\d+)$'),
               #                                format: min length, num upper, num digits
               'PASSWORD_LENGTH':               (['0,0,0',  '4,0,0', '6,1,1'], "password_length", r'^(\d+,\d+,\d+)$'),
               'SHELL_HISTORY_SIZE':            (['-1',  '-1',   '100'], "set_shell_history_size", r'^(-?\d+)$'),
               'SHELL_TIMEOUT':                 (['0',   '0',    '600'], "set_shell_timeout", r'^(\d+)$'),
               }


# helper functions
def load_defaults(levelname):
    """Loads default configuration for given level"""
    if levelname not in SECURITY_LEVELS:
        print >>sys.stderr, _("Error: unknown level '%s'!") % levelname
        return None, None, None
    level = SECURITY_LEVELS[levelname]
    params = {}
    callbacks = {}
    values = {}
    for item in SETTINGS:
        levels, callback, value = SETTINGS[item]
        params[item] = levels[level]
        callbacks[item] = callback
        values[item] = value
    return params, callbacks, values

