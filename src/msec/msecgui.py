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
from libmsec import MSEC, PERMS, Log

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
    'root' account is used to receive such emails).

  - <b>Secure</b>: this profile is configured to provide maximum security, even
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

    def __init__(self, log, msec, perms, config, permconfig):
        """Initializes gui"""
        self.log = log
        self.msec = msec
        self.config = config
        self.perms = perms
        self.permconfig = permconfig
        # save original configuration
        self.oldconfig = {}
        for opt in config.list_options():
            self.oldconfig[opt] = config.get(opt)
        self.oldperms = {}
        for opt in permconfig.list_options():
            self.oldperms[opt] = permconfig.get(opt)

        self.window = gtk.Window()
        self.window.set_default_size(640, 480)
        self.window.connect('destroy', self.quit)

        # are we enforcing a level
        self.enforced_level = None
        self.enforcing_level = False

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
        help.set_sensitive(False)
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
        self.quit(widget)

    def help(self, widget):
        """Help button"""
        print "Help clicked."

    def ok(self, widget):
        """Ok button"""
        # first, let's reset previous msec data
        self.msec.reset()
        # start buffered logging
        self.log.start_buffer()
        # are we enforcing a level?
        if self.enforcing_level:
            self.log.debug(">> Enforcing level %s" % self.enforced_level)
            curconfig = config.load_defaults(self.log, self.enforced_level)
            curperms = config.load_default_perms(self.log, self.enforced_level)
        else:
            curconfig = self.config
            curperms = self.permconfig
        # apply config and preview changes
        self.msec.apply(curconfig)
        self.msec.commit(False)
        messages = self.log.get_buffer()

        # creating preview window
        dialog = gtk.Dialog(_("Preview changes"),
                self.window, 0,
                (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                gtk.STOCK_OK, gtk.RESPONSE_OK)
                )
        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        dialog.vbox.add(sw)

        vbox = gtk.VBox()
        dialog.vbox.set_size_request(640, 300)
        sw.add_with_viewport(vbox)
        label = gtk.Label(_("Click OK to commit changes, or CANCEL to leave current configuration unmodified."))
        vbox.pack_start(label, False, False)

        # informative label
        label = gtk.Label(_('<b>MSEC configuration:</b>'))
        label.set_use_markup(True)
        vbox.pack_start(label, False, False)

        # check for changed options
        opt_changes = []
        for opt in self.oldconfig:
            if curconfig.get(opt) != self.oldconfig[opt]:
                opt_changes.append(opt)

        if len(opt_changes) > 0:
            # some configuration parameters were changed
            label = gtk.Label(_('<b>MSEC option changed:</b> <i>%s</i>\n') % ", ".join(opt_changes))
            label.set_use_markup(True)
            label.set_line_wrap(True)
            vbox.pack_start(label, False, False)
        else:
            label = gtk.Label(_('<i>No changes in MSEC options.</i>'))
            label.set_use_markup(True)
            vbox.pack_start(label, False, False)

        # now checking for permission changes
        perm_changes = []
        for opt in self.oldperms:
            if curperms.get(opt) != self.oldperms[opt]:
                perm_changes.append(opt)

        if len(perm_changes) > 0:
            # some configuration parameters were changed
            label = gtk.Label(_('<b>System permissions changed:</b> <i>%s</i>\n') % ", ".join(perm_changes))
            label.set_use_markup(True)
            label.set_line_wrap(True)
            vbox.pack_start(label, False, False)
        else:
            label = gtk.Label(_('<i>No changes in system permissions.</i>'))
            label.set_use_markup(True)
            vbox.pack_start(label, False, False)

        # see if there were any changes to system files
        for msg in messages['info']:
            if msg.find(config.MODIFICATIONS_FOUND) != -1 or msg.find(config.MODIFICATIONS_NOT_FOUND) != -1:
                label = gtk.Label('<i>%s</i>' % msg)
                label.set_line_wrap(True)
                label.set_use_markup(True)
                vbox.pack_start(label, False, False)
                break

        # adding specific messages
        advanced = gtk.Expander(_("Details"))
        vbox_advanced = gtk.VBox()
        advanced.add(vbox_advanced)
        vbox.pack_start(advanced, False, False)
        for cat in ['info', 'critical', 'error', 'warn', 'debug']:
            msgs = messages[cat]
            expander = gtk.Expander(_('MSEC messages (%s): %d') % (cat, len(msgs)))
            textview = gtk.TextView()
            textview.set_wrap_mode(gtk.WRAP_WORD_CHAR)
            textview.set_editable(False)
            expander.add(textview)
            count = 1
            for msg in msgs:
                buffer = textview.get_buffer()
                end = buffer.get_end_iter()
                buffer.insert(end, "%d: %s\n" % (count, msg))
                count += 1
            vbox_advanced.pack_start(expander, False, False)

        dialog.show_all()
        response = dialog.run()
        if response != gtk.RESPONSE_OK:
            dialog.destroy()
            return
        dialog.destroy()

        # well, let's commit it!
        if self.enforcing_level:
            # rewriting configuration
            for opt in curconfig.list_options():
                self.config.set(opt, curconfig.get(opt))
            for perm in curperms.list_options():
                self.permconfig.set(perm, curperms.get(perm))
        # saving the configuration
        self.config.save()
        self.msec.apply(self.config)
        self.msec.commit(True)
        # saving permissions
        self.permconfig.save()
        # this is done periodically
        #self.perms.check_perms(self.permconfig)
        #self.perms.commit(True)
        self.quit(widget)

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
                func = self.msec.get_action(callback)
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
            # we are enforcing a level
            self.enforcing_level = True
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
            # disable level enforcing
            self.enforcing_level = False

    def force_level(self, widget, level):
        """Defines a given security level"""
        if widget.get_active():
            self.enforced_level = level

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
        if self.config.get("CHECK_SECURITY") == "yes":
            self.periodic_checks.set_active(True)
        vbox.pack_start(self.periodic_checks, False, False)

        # network security options
        options_view = self.create_treeview(["CHECK_PERMS", "CHECK_USER_FILES", "CHECK_SUID_ROOT", "CHECK_SUID_MD5",
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
        treeview.connect('row-activated', self.permission_changed, lstore)

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

        for file in self.permconfig.list_options():
            user_s, group_s, perm_s, force = self.permconfig.get(file)

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
        file = model.get_value(iter, self.COLUMN_PATH)
        fixed = model.get_value(iter, self.COLUMN_FORCE)

        user, group, perm, force = self.permconfig.get(file)

        # do something with the value
        fixed = not fixed

        # set new value
        model.set(iter, self.COLUMN_FORCE, fixed)
        if fixed:
            force = "force"
        else:
            force = ""
        self.permconfig.set(file, (user, group, perm, force))


    def permission_changed(self, treeview, path, col, model):
        """Processes a permission change"""
        iter = model.get_iter(path)
        file = model.get_value(iter, self.COLUMN_PATH)
        user = model.get_value(iter, self.COLUMN_USER)
        group = model.get_value(iter, self.COLUMN_GROUP)
        perm = model.get_value(iter, self.COLUMN_PERM)
        force = model.get_value(iter, self.COLUMN_FORCE)

        if not force:
            force = ""
        else:
            force = "force"

        # asks for new parameter value
        dialog = gtk.Dialog(_("Changing permissions for %s") % (file),
                self.window, 0,
                (gtk.STOCK_OK, gtk.RESPONSE_OK,
                gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))
        label = gtk.Label(_("Changing permissions on <b>%s</b>\nPlease specify new permissions, or use 'current' to keep current permissions.\n") % (file))
        label.set_line_wrap(True)
        label.set_use_markup(True)
        dialog.vbox.pack_start(label, False, False)

        # user
        hbox = gtk.HBox()
        hbox.pack_start(gtk.Label(_("User: ")))
        entry_user = gtk.Entry()
        entry_user.set_text(user)
        hbox.pack_start(entry_user)
        dialog.vbox.pack_start(hbox, False, False)

        # group
        hbox = gtk.HBox()
        hbox.pack_start(gtk.Label(_("Group: ")))
        entry_group = gtk.Entry()
        entry_group.set_text(group)
        hbox.pack_start(entry_group)
        dialog.vbox.pack_start(hbox, False, False)

        # perm
        hbox = gtk.HBox()
        hbox.pack_start(gtk.Label(_("Permissions: ")))
        entry_perm = gtk.Entry()
        entry_perm.set_text(perm)
        hbox.pack_start(entry_perm)
        dialog.vbox.pack_start(hbox, False, False)

        dialog.show_all()
        response = dialog.run()
        if response != gtk.RESPONSE_OK:
            dialog.destroy()
            return

        newuser = entry_user.get_text()
        newgroup = entry_group.get_text()
        newperm = entry_perm.get_text()
        dialog.destroy()

        self.permconfig.set(file, (newuser, newgroup, newperm, force))
        model.set(iter, self.COLUMN_USER, newuser)
        model.set(iter, self.COLUMN_GROUP, newgroup)
        model.set(iter, self.COLUMN_PERM, newperm)

    def option_changed(self, treeview, path, col, model):
        """Processes an option change"""
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


# {{{ usage
def usage():
    """Prints help message"""
    print """Msec: Mandriva Security Center (%s).

Arguments to msecgui:
    -h, --help              displays this helpful message.
    -d                      enable debugging messages.
""" % version
# }}}

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

    # configuring logging
    log = Log(interactive=True, log_syslog=False, log_file=True, log_level=log_level, log_path=config.SECURITYLOG)

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
    perms = PERMS(log)

    log.info("Starting gui..")

    gui = MsecGui(log, msec, perms, msec_config, perm_conf)
    gtk.main()
