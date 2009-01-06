#!/usr/bin/python -O
"""
This is graphical frontend to msec.
"""

import os
import sys
import string
import getopt

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
import gettext
try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

# localized help
try:
    from help import HELP
except:
    HELP = {}

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

NETWORK_SECURITY_TEXT=_("""Network security options.

These options define the network security agains remote treats, unauthorized accesses,
and breakin attempts.
""")

PERIODIC_SECURITY_TEXT=_("""Periodic security checks.

These options configure the security checks that should be executed periodically.
""")

NOTIFICATIONS_TEXT=_("""Security notifications.

This page allows to configure the different ways the security notifications can be
delivered.

It is possible to receive notifications by e-mail, using syslog, using an exclusive
log file, or using desktop environment notification system.
""")

PERMISSIONS_SECURITY_TEXT=_("""File permissions.

These options allow to fine-tune system permissions for important files and directores.

The following permissions are checked periodically, and any change to the owner, group,
or current permission is reported. The permissions can be enforced, automatically
changing them to the specified values when a change is detected.
""")

class MsecGui:
    """Msec GUI"""
    # common columns
    (COLUMN_OPTION, COLUMN_DESCR, COLUMN_VALUE) = range(3)
    (COLUMN_PATH, COLUMN_USER, COLUMN_GROUP, COLUMN_PERM, COLUMN_FORCE) = range(5)

    def __init__(self, log, msec, config, perms):
        """Initializes gui"""
        self.log = log
        self.msec = msec
        self.config = config
        self.perms = perms
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
        cancel = gtk.Button(gtk.STOCK_CANCEL)
        cancel.set_use_stock(True)
        cancel.connect('clicked', self.cancel)
        hbox.pack_start(cancel, expand=True, fill=True)
        help = gtk.Button(gtk.STOCK_HELP)
        help.set_use_stock(True)
        help.connect('clicked', self.help)
        hbox.pack_start(help, expand=True, fill=True)
        ok = gtk.Button(gtk.STOCK_OK)
        ok.set_use_stock(True)
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
        # first, let's reset previous msec data
        self.msec.reset()
        # let's try to commit everything
        for opt in self.config.list_options():
            # Determines correspondent function
            action = None
            callback = config.find_callback(opt)
            valid_params = config.find_valid_params(opt)
            if callback:
                action = msec.get_action(callback)
            if not action:
                # The required functionality is not supported
                log.info(_("'%s' is not available in this version") % opt)
                continue
            log.debug("Processing action %s: %s(%s)" % (opt, callback, msec_config.get(opt)))
            # validating parameters
            param = msec_config.get(opt)
            if param not in valid_params and '*' not in valid_params:
                log.error(_("Invalid parameter for %s: '%s'. Valid parameters: '%s'.") % (opt,
                            param,
                            valid_values[opt]))
                continue
            action(msec_config.get(opt))
        # preview changes
        msec.commit(False)

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
            if not config.SETTINGS.has_key(option):
                # invalid option
                self.log.error(_("Invalid option '%s'!") % option)
                continue
            # getting level settings, callback and valid params
            callback, params = config.SETTINGS[option]
            # getting the function description
            if option in HELP:
                self.log.debug("found localized help for %s" % option)
                doc = HELP[option]
            else:
                # get description from function comments
                func = msec.get_action(callback)
                if func:
                    doc = func.__doc__.strip()
                else:
                    doc = callback

            # now for the value
            value = self.config.get(option)

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

        entry = gtk.Label(BASIC_SECURITY_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        # Are we enforcing a new security level
        entry = gtk.CheckButton(_("Enforce a new security level"))

        # security levels
        frame = gtk.Frame()
        frame.set_sensitive(False)
        levels_vbox = gtk.VBox()
        frame.add(levels_vbox)
        # none
        button = gtk.RadioButton(group=None, label=_("Pre-defined security level: NONE"))
        button.connect('clicked', self.force_level, 'none')
        levels_vbox.pack_start(button)
        # default
        button = gtk.RadioButton(group=button, label=_("Pre-defined security level: DEFAULT"))
        button.connect('clicked', self.force_level, 'default')
        button.set_active(True)
        levels_vbox.pack_start(button)
        # secure
        button = gtk.RadioButton(group=button, label=_("Pre-defined security level: SECURE"))
        button.connect('clicked', self.force_level, 'secure')
        levels_vbox.pack_start(button)

        # adding callback for enable button
        entry.connect('clicked', self.enforce_level, frame)
        vbox.pack_start(entry, False, False)
        # putting levels to vbox
        vbox.pack_start(frame)

        return vbox

    def enforce_level(self, widget, options):
        """Enforces a new security level"""
        frame = options
        if widget.get_active():
            frame.set_sensitive(True)
            # disable notebook pages
            npages = self.notebook.get_n_pages()
            for page in range(1, npages):
                curpage = self.notebook.get_nth_page(page)
                curpage.set_sensitive(False)
                label = self.notebook.get_tab_label(curpage)
                label.set_sensitive(False)
        else:
            frame.set_sensitive(False)
            # enable notebook pages
            npages = self.notebook.get_n_pages()
            for page in range(1, npages):
                curpage = self.notebook.get_nth_page(page)
                curpage.set_sensitive(True)
                label = self.notebook.get_tab_label(curpage)
                label.set_sensitive(True)

    def force_level(self, widget, level):
        """Defines a given security level"""
        if widget.get_active():
            print level

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
        options_view = self.create_treeview(["ENABLE_APPARMOR", "ENABLE_POLICYKIT",
                                            "ENABLE_SUDO", "ENABLE_MSEC_CRON", "ENABLE_PAM_WHEEL_FOR_SU",
                                            "ENABLE_SULOGIN", "CREATE_SERVER_LINK", "ENABLE_AT_CRONTAB",
                                            "ALLOW_ROOT_LOGIN", "ALLOW_USER_LIST", "ENABLE_PASSWORD",
                                            "ALLOW_AUTOLOGIN", "ENABLE_CONSOLE_LOG",
                                            "ENABLE_PAM_WHEEL_FOR_SU", "CREATE_SERVER_LINK", "ALLOW_XAUTH_FROM_ROOT",
                                            "ALLOW_REBOOT", "SHELL_HISTORY_SIZE", "SHELL_TIMEOUT", "PASSWORD_LENGTH",
                                            "PASSWORD_HISTORY", "USER_UMASK", "ROOT_UMASK",
                                            ])
        vbox.pack_start(options_view)

        return vbox

    def network_security_page(self):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(NETWORK_SECURITY_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        # network security options
        options_view = self.create_treeview(["ACCEPT_BOGUS_ERROR_RESPONSES", "ACCEPT_BROADCASTED_ICMP_ECHO",
                                            "ACCEPT_ICMP_ECHO", "ALLOW_REMOTE_ROOT_LOGIN",
                                            "ALLOW_X_CONNECTIONS", "ALLOW_XSERVER_TO_LISTEN",
                                            "AUTHORIZE_SERVICES", "ENABLE_DNS_SPOOFING_PROTECTION",
                                            "ENABLE_IP_SPOOFING_PROTECTION", "ENABLE_LOG_STRANGE_PACKETS",
                                            ])
        vbox.pack_start(options_view)

        return vbox

    def periodic_security_page(self):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(PERIODIC_SECURITY_TEXT)
        vbox.pack_start(entry, False, False)

        self.periodic_checks = gtk.CheckButton(_("Enable periodic security checks"))
        vbox.pack_start(self.periodic_checks, False, False)

        # network security options
        options_view = self.create_treeview(["CHECK_PERMS", "CHECK_SUID_ROOT", "CHECK_SUID_MD5",
                                            "CHECK_SGID", "CHECK_WRITABLE", "CHECK_UNOWNED",
                                            "CHECK_PROMISC", "CHECK_OPEN_PORT", "CHECK_PASSWD",
                                            "CHECK_SHADOW", "CHECK_CHKROOTKIT", "CHECK_RPM",
                                            "CHECK_SHOSTS"
                                            ])
        vbox.pack_start(options_view)

        # see if these tests are enabled
        self.periodic_checks.connect('clicked', self.periodic_tests, options_view)
        periodic_checks = self.config.get("CHECK_SECURITY")
        if periodic_checks == 'no':
            # disable all periodic tests
            options_view.set_sensitive(False)

        return vbox

    def periodic_tests(self, widget, options):
        '''Enables/disables periodic security tests.'''
        status = widget.get_active()
        if status:
            self.config.set("CHECK_SECURITY", "yes")
            options.set_sensitive(True)
        else:
            self.config.set("CHECK_SECURITY", "no")
            options.set_sensitive(False)

    def permissions_security_page(self):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(PERMISSIONS_SECURITY_TEXT)
        vbox.pack_start(entry, False, False)

        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)

        # list of options
        lstore = gtk.ListStore(
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_BOOLEAN)

        # treeview
        treeview = gtk.TreeView(lstore)
        treeview.set_rules_hint(True)
        treeview.set_search_column(self.COLUMN_DESCR)

        # TODO: fix
        treeview.connect('row-activated', self.option_changed, lstore)

        # configuring columns

        # column for path mask
        column = gtk.TreeViewColumn(_('Path'), gtk.CellRendererText(), text=self.COLUMN_PATH)
        column.set_sort_column_id(self.COLUMN_PATH)
        treeview.append_column(column)

        # column for user
        column = gtk.TreeViewColumn(_('User'), gtk.CellRendererText(), text=self.COLUMN_USER)
        column.set_sort_column_id(self.COLUMN_USER)
        treeview.append_column(column)

        # column for group
        column = gtk.TreeViewColumn(_('Group'), gtk.CellRendererText(), text=self.COLUMN_GROUP)
        column.set_sort_column_id(self.COLUMN_GROUP)
        treeview.append_column(column)

        # column for permissions
        column = gtk.TreeViewColumn(_('Permissions'), gtk.CellRendererText(), text=self.COLUMN_PERM)
        column.set_sort_column_id(self.COLUMN_VALUE)
        treeview.append_column(column)

        # column for force option
        renderer = gtk.CellRendererToggle()
        renderer.connect('toggled', self.toggle_enforced, lstore)
        column = gtk.TreeViewColumn(_('Enforce'), renderer, active=self.COLUMN_FORCE)
        column.set_sort_column_id(self.COLUMN_FORCE)
        column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        column.set_fixed_width(50)

        treeview.append_column(column)

        sw.add(treeview)

        for file in self.perms.list_options():
            user_s, group_s, perm_s, force = self.perms.get(file)

            # convert to boolean
            if force:
                force = True
            else:
                force = False

            # building the option
            iter = lstore.append()
            lstore.set(iter,
                    self.COLUMN_PATH, file,
                    self.COLUMN_USER, user_s,
                    self.COLUMN_GROUP, group_s,
                    self.COLUMN_PERM, perm_s,
                    self.COLUMN_FORCE, force,
                    )
        vbox.pack_start(sw)
        return vbox

    def toggle_enforced(self, cell, path, model):
        '''Toggles a forced permission on an item'''
        iter = model.get_iter((int(path),))
        fixed = model.get_value(iter, self.COLUMN_FORCE)

        # do something with the value
        fixed = not fixed

        # set new value
        model.set(iter, self.COLUMN_FORCE, fixed)

    def option_changed(self, treeview, path, col, model):
        """Processes an option change"""
        print path
        iter = model.get_iter(path)
        param = model.get_value(iter, self.COLUMN_OPTION)
        descr = model.get_value(iter, self.COLUMN_DESCR)
        value = model.get_value(iter, self.COLUMN_VALUE)

        callback, params = config.SETTINGS[param]

        # asks for new parameter value
        dialog = gtk.Dialog(_("Select new value for %s") % (param),
                self.window, 0,
                (gtk.STOCK_OK, gtk.RESPONSE_OK,
                gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))
        label = gtk.Label(_("Modifying <b>%s</b>.\n<i>%s</i>\nCurrent value: <b>%s</b>") % (param, descr, value))
        label.set_line_wrap(True)
        label.set_use_markup(True)
        dialog.vbox.pack_start(label)
        if '*' in params:
            # string parameter
            entry = gtk.Entry()
            entry.set_text(value)
            dialog.vbox.pack_start(entry)
        else:
            # combobox parameter
            entry = gtk.combo_box_new_text()
            for item in params:
                entry.append_text(item)
            if value not in params:
                entry.append_text(value)
                params.append(value)
            active = params.index(value)
            entry.set_active(active)
            dialog.vbox.pack_start(entry)

        dialog.show_all()
        response = dialog.run()
        if response != gtk.RESPONSE_OK:
            dialog.destroy()
            return

        # process new parameter
        if '*' in params:
            newval = entry.get_text()
        else:
            newval = entry.get_active_text()
        dialog.destroy()

        # update options
        self.config.set(param, newval)

        model.set(iter, self.COLUMN_VALUE, newval)


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

    # loading permissions config
    perm_conf = config.PermConfig(log, config=config.PERMCONF)
    if not perm_conf.load():
        log.info(_("Unable to load permissions, using default values"))

    # creating an msec instance
    msec = MSEC(log)

    log.info("Starting gui..")

    gui = MsecGui(log, msec, msec_config, perm_conf)
    gtk.main()

