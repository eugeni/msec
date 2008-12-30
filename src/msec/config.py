#!/usr/bin/python -O
# Mandriva Linux - MSEC - configuration

# security levels
SECURITY_LEVELS = {
            "none": 0,
            "default": 1,
            "secure": 2
        }
DEFAULT_LEVEL="default"

# default parameters
#                                                   security level
#               OPTION                           none   default secure  callback
SETTINGS =    {'CHECK_SECURITY' :               (['yes', 'yes',  'yes'], "check_security"),
               'CHECK_PERMS' :                  (['no',  'yes',  'yes'], "check_perms"),
               'CHECK_SUID_ROOT' :              (['yes', 'yes',  'yes'], "check_suid_root"),
               'CHECK_SUID_MD5' :               (['yes', 'yes',  'yes'], "check_suid_md5"),
               'CHECK_SGID' :                   (['yes', 'yes',  'yes'], "check_sgid"),
               'CHECK_WRITABLE' :               (['yes', 'yes',  'yes'], "check_writable"),
               'CHECK_UNOWNED' :                (['no',  'no',   'yes'], "check_unowned"),
               'CHECK_PROMISC' :                (['no',  'no',   'yes'], "check_promisc"),
               'CHECK_OPEN_PORT' :              (['no',  'yes',  'yes'], "check_open_port"),
               'CHECK_PASSWD' :                 (['no',  'yes',  'yes'], "check_passwd"),
               'CHECK_SHADOW' :                 (['no',  'yes',  'yes'], "check_shadow"),
               'CHECK_CHKROOTKIT' :             (['no',  'yes',  'yes'], "check_chkrootkit"), # was: CHKROOTKIT_CHECK
               'CHECK_RPM' :                    (['no',  'yes',  'yes'], "check_rpm"), # was: RPM_CHECK
               'CHECK_SHOSTS' :                 (['no',  'yes',  'yes'], "check_shosts"),
               'TTY_WARN' :                     (['no',  'no',   'yes'], "tty_warn"),
               'MAIL_WARN' :                    (['no',  'yes',  'yes'], "mail_warn"),
               'MAIL_EMPTY_CONTENT':            (['no',  'no',   'yes'], "mail_empty_content"),
               'SYSLOG_WARN' :                  (['yes', 'yes',  'yes'], "syslog_warn"),
               # security options
               'USER_UMASK':                    (['022', '022',  '077'], "set_user_umask"),
               'ROOT_UMASK':                    (['022', '022',  '077'], "set_root_umask"),
               'WIN_PARTS_UMASK':               (['no',  'no',   '0'  ], "set_win_parts_umask"),
               'ACCEPT_BOGUS_ERROR_RESPONSES':  (['no',  'no',   'no' ], "accept_bogus_error_responses"),
               'ACCEPT_BROADCASTED_ICMP_ECHO':  (['yes', 'yes',  'no' ], "accept_broadcasted_icmp_echo"),
               'ACCEPT_ICMP_ECHO':              (['yes', 'yes',  'yes'], "accept_icmp_echo"),
               'ALLOW_AUTOLOGIN':               (['yes', 'yes',  'no' ], "allow_autologin"),
               'ALLOW_ISSUES':                  (['yes', 'yes',  'yes'], "allow_issues"),
               'ALLOW_REBOOT':                  (['yes', 'yes',  'yes'], "allow_reboot"),
               'ALLOW_REMOTE_ROOT_LOGIN':       (['yes', 'without_password', 'no' ], "allow_remote_root_login"), # was: WITHOUT_PASSWORD
               'ALLOW_ROOT_LOGIN':              (['yes', 'yes',  'no' ], "allow_root_login"),
               'ALLOW_USER_LIST':               (['yes', 'yes',  'no' ], "allow_user_list"),
               'ALLOW_X_CONNECTIONS':           (['yes', 'LOCAL','no' ], "allow_x_connections"),
               'ALLOW_XAUTH_FROM_ROOT':         (['yes', 'yes',  'no' ], "allow_xauth_from_root"),
               'ALLOW_XSERVER_TO_LISTEN':       (['yes', 'no',   'no' ], "allow_xserver_to_listen"),
               'AUTHORIZE_SERVICES':            (['ALL', 'LOCAL','NONE'], "authorize_services"),
               'CREATE_SERVER_LINK':            (['no',  'no',   'yes'], "create_server_link"),
               'ENABLE_AT_CRONTAB':             (['no',  'yes',  'no' ], "enable_at_crontab"),
               'ENABLE_CONSOLE_LOG':            (['yes', 'yes',  'no' ], "enable_console_log"),
               'ENABLE_DNS_SPOOFING_PROTECTION':(['yes', 'yes',  'yes'], "enable_ip_spoofing_protection"),
               'ENABLE_IP_SPOOFING_PROTECTION': (['yes', 'yes',  'yes'], "enable_dns_spoofing_protection"),
               'ENABLE_LOG_STRANGE_PACKETS':    (['no',  'yes',  'yes'], "enable_log_strange_packets"),
               'ENABLE_MSEC_CRON':              (['no',  'yes',  'yes'], "enable_msec_cron"),
               'ENABLE_PAM_ROOT_FROM_WHEEL':    (['no',  'no',   'no' ], "enable_pam_root_from_wheel"),
               'ENABLE_PAM_WHEEL_FOR_SU':       (['no',  'no',   'yes'], "enable_pam_wheel_for_su"),
               'ENABLE_PASSWORD':               (['yes', 'yes',  'yes'], "enable_password"),
               'ENABLE_SULOGIN':                (['no',  'no',   'yes'], "enable_sulogin"),
               'ENABLE_APPARMOR':               (['no',  'no',   'yes'], "enable_apparmor"),
               # password aging - do we need that at all??
               'NO_PASSWORD_AGING_FOR':         (['no',  'no',   'no' ], "no_password_aging_for"),
               'PASSWORD_AGING':                (['99999',  '99999',   '60' ], "password_aging"),
               'PASSWORD_HISTORY':              (['no',  'no',   '2'  ], "password_history"),
               #                                format: min length, num upper, num digits
               'PASSWORD_LENGTH':               (['0,0,0',  '0,0,0', '6,1,1'], "password_length"),
               'SHELL_HISTORY_SIZE':            (['-1',  '-1',   '100'], "set_shell_history_size"),
               'SHELL_TIMEOUT':                 (['0',   '0',    '600'], "set_shell_timeout"),
               }

