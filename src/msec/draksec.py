#!/usr/bin/python -O
"""
This is graphical frontend to msec.
"""

import os
import sys
import string
import getopt
import gettext

# PyGTK
import gtk
#import gtk.glade
import pygtk
import gobject
import pango

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
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

# text strings
BASIC_SECURITY_TEXT=_("""Basic security options.

These options control the basic aspects of system security. You may select
a pre-defined profile, or customize the options.

The following security profiles are defined in this version:

  - <b>None</b>: this profile disables additional system security, and it should
    be used when you want to fine-tune the system on your own.

  - <b>Default</b>: this is the default profile, which configures a reasonably
    safe set of security features. It activates several periodic system checks,
    and mails their results daily to the selected email (by default, the local
    'root' account is used to receive such emails.

  - <b>Secure</b>: this profile is configure to provide maximum security, even
    at the cost of limiting the remote access to the system. It also runs a wider
    set of periodic checks, enforces the local password settings, and periodically
    checks if the system security settings, configured here, were modified.
""")

SYSTEM_SECURITY_TEXT=_("""System security options.

These options control the local security configuration, such as the login restrictions,
password configurations, integration with other security tools, and default file creation
permissions.
""")

NOTIFICATIONS_TEXT=_("""Security notifications.

This page allows to configure the different ways the security notifications can be
delivered.

It is possible to receive notifications by e-mail, using syslog, using an exclusive
log file, or using desktop environment notification system.
""")

class MsecGui:
    """Msec GUI"""
    # common columns
    (COLUMN_OPTION, COLUMN_DESCR, COLUMN_VALUE) = range(3)

    def __init__(self, log, msec, config):
        """Initializes gui"""
        self.log = log
        self.msec = msec
        self.config = config
        self.window = gtk.Window()
        self.window.set_default_size(640, 480)
        self.window.connect('destroy', self.quit)

        main_vbox = gtk.VBox(homogeneous=False, spacing=5)
        self.window.add(main_vbox)

        # main frame
        frame = gtk.Frame()
        main_vbox.pack_start(frame)

        # notebook
        self.notebook = gtk.Notebook()
        frame.add(self.notebook)

        self.notebook.append_page(self.basic_security_page(), gtk.Label(_("Basic security")))
        self.notebook.append_page(self.system_security_page(), gtk.Label(_("System security")))
        self.notebook.append_page(self.network_security_page(), gtk.Label(_("Network security")))
        self.notebook.append_page(self.periodic_security_page(), gtk.Label(_("Periodic checks")))
        self.notebook.append_page(self.notifications_page(), gtk.Label(_("Security notifications")))
        self.notebook.append_page(self.permissions_security_page(), gtk.Label(_("Permissions")))

        # control hbox
        hbox = gtk.HBox(homogeneous=False, spacing=10)
        main_vbox.pack_start(hbox, False, False)

        # control buttons
        # TODO: improve spacing
        cancel = gtk.Button(_("Cancel"))
        cancel.connect('clicked', self.cancel)
        hbox.pack_start(cancel, expand=True, fill=True)
        help = gtk.Button(_("Help"))
        help.connect('clicked', self.help)
        hbox.pack_start(help, expand=True, fill=True)
        ok = gtk.Button(_("Ok"))
        ok.connect('clicked', self.ok)
        hbox.pack_start(ok, expand=True, fill=True)

        self.window.show_all()

    def cancel(self, widget):
        """Cancel button"""
        print "Cancel clicked."
        self.quit(widget)

    def help(self, widget):
        """Help button"""
        print "Help clicked."

    def ok(self, widget):
        """Ok button"""
        print "Ok clicked."

    def create_treeview(self, options):
        """Creates a treeview from given list of options"""
        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)

        # list of options
        lstore = gtk.ListStore(
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING)

        # treeview
        treeview = gtk.TreeView(lstore)
        treeview.set_rules_hint(True)
        treeview.set_search_column(self.COLUMN_DESCR)

        treeview.connect('row-activated', self.option_changed, lstore)

        # configuring columns

        # column for option names
        column = gtk.TreeViewColumn(_('Security Option'), gtk.CellRendererText(), text=self.COLUMN_OPTION)
        column.set_sort_column_id(self.COLUMN_OPTION)
        treeview.append_column(column)

        # column for descriptions
        renderer = gtk.CellRendererText()
        renderer.set_property('wrap-width', 400)
        renderer.set_property('wrap-mode', pango.WRAP_WORD_CHAR)
        column = gtk.TreeViewColumn(_('Description'), renderer, text=self.COLUMN_DESCR)
        column.set_sort_column_id(self.COLUMN_DESCR)
        treeview.append_column(column)

        # column for values
        column = gtk.TreeViewColumn(_('Value'), gtk.CellRendererText(), text=self.COLUMN_VALUE)
        column.set_sort_column_id(self.COLUMN_VALUE)
        treeview.append_column(column)

        sw.add(treeview)

        for option in options:
            # retreiving option description
            print config.SETTINGS[option]
            if not config.SETTINGS.has_key(option):
                # invalid option
                self.log.error(_("Invalid option '%s'!") % option)
                continue
            # getting level settings, callback and valid params
            levels, callback, params = config.SETTINGS[option]
            # getting the function and description
            func = msec.get_action(callback)
            if func:
                doc = func.__doc__.strip()
            else:
                doc = callback

            # now for the value
            value = self.config.get(option)
            if not value:
                value = ""
            if '*' in params:
                entry = gtk.Entry()
                entry.set_text(value)
            else:
                entry = gtk.combo_box_new_text()
                for item in params:
                    entry.append_text(item)
                active = params.index(value)
                entry.set_active(active)

            # building the option
            iter = lstore.append()
            lstore.set(iter,
                    self.COLUMN_OPTION, option,
                    self.COLUMN_DESCR, doc,
                    self.COLUMN_VALUE, value,
                    )
        return sw

    def basic_security_page(self):
        """Builds the basic security page"""
        vbox = gtk.VBox(homogeneous=False)

        # security levels

        levels = config.SECURITY_LEVELS

        print levels

        entry = gtk.Label(BASIC_SECURITY_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        # basic security options
        options_view = self.create_treeview(["MAIL_WARN", "MAIL_USER", "MAIL_EMPTY_CONTENT"])
        vbox.pack_start(options_view)

        return vbox

    def notifications_page(self):
        """Builds the notifications page"""
        vbox = gtk.VBox(homogeneous=False)

        # security levels

        entry = gtk.Label(NOTIFICATIONS_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        # basic security options
        options_view = self.create_treeview(["TTY_WARN", "SYSLOG_WARN", "NOTIFY_WARN", "MAIL_WARN", "MAIL_USER", "MAIL_EMPTY_CONTENT"])
        vbox.pack_start(options_view)

        return vbox

    def system_security_page(self):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(SYSTEM_SECURITY_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        # system security options
        options_view = self.create_treeview(["ENABLE_APPARMOR", "ENABLE_POLICYKIT", "AUTHORIZE_SERVICES",
                                            "ENABLE_SUDO", "ENABLE_MSEC_CRON", "ENABLE_PAM_WHEEL_FOR_SU",
                                            "ENABLE_SULOGIN", "CREATE_SERVER_LINK", "ENABLE_AT_CRONTAB",
                                            "ALLOW_ROOT_LOGIN", "ALLOW_USER_LIST", "ENABLE_PASSWORD",
                                            "ENABLE_PAM_WHEEL_FOR_SU", "CREATE_SERVER_LINK", "ALLOW_XAUTH_FROM_ROOT",
                                            "ALLOW_REBOOT", "USER_UMASK", "ROOT_UMASK",
                                            ])
        vbox.pack_start(options_view)

        return vbox

    def network_security_page(self):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label("Hello world!")
        vbox.pack_start(entry, False, False)

        return vbox

    def periodic_security_page(self):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label("Hello world!")
        vbox.pack_start(entry, False, False)

        return vbox

    def permissions_security_page(self):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label("Hello world!")
        vbox.pack_start(entry, False, False)

        return vbox

    def option_changed(self, treeview, path, col, model):
        """Processes an option change"""
        print path
        iter = model.get_iter(path)
        param = model.get_value(iter, self.COLUMN_OPTION)
        value = model.get_value(iter, self.COLUMN_VALUE)

        print param

        new_value = "*" + value

        model.set(iter, self.COLUMN_VALUE, new_value)


    def quit(self, param):
        """Quits the application"""
        print "Leaving.."
        gtk.main_quit()


if __name__ == "__main__":
    log_level = logging.INFO

    # parse command line
    try:
        opt, args = getopt.getopt(sys.argv[1:], 'hd', ['help', 'debug'])
    except getopt.error:
        usage()
        sys.exit(1)
    for o in opt:
        # help
        if o[0] == '-h' or o[0] == '--help':
            usage()
            sys.exit(0)
        # list
        elif o[0] == '-d' or o[0] == '--debug':
            log_level = logging.DEBUG
        # check-only mode
        elif o[0] == '-p' or o[0] == '--pretend':
            commit = False

    # configuring logging
    interactive = sys.stdin.isatty()
    if interactive:
        # logs to file and to terminal
        #log = Log(log_path=config.SECURITYLOG, interactive=True, log_syslog=False, log_level=log_level)
        log = Log(interactive=True, log_syslog=False, log_file = False, log_level=log_level)
    else:
        log = Log(log_path=config.SECURITYLOG, interactive=False, log_level=log_level)

    # loading initial config
    msec_config = config.MsecConfig(log, config=config.SECURITYCONF)
    if not msec_config.load():
        log.info(_("Unable to load config, using default values"))

    # overriding defined parameters from config file
    params, callbacks, valid_values = config.load_defaults(config.DEFAULT_LEVEL)
    for opt in params:
            # only forcing new value when undefined
            msec_config.get(opt, params[opt])


    # creating an msec instance
    msec = MSEC(log)

    log.info("Starting gui..")

    gui = MsecGui(log, msec, msec_config)
    gtk.main()

