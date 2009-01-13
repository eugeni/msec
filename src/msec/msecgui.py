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

# text strings
LEVEL_SECURITY_TEXT=_("""<big><b>Choose security level</b></big>

This application allows you to configure your system security. If you wish
to activate it, choose the appropriate security level:

  - <b>Default</b>: this is the default profile, which configures a reasonably
    safe set of security features. It activates several periodic system checks,
    and mails their results daily to the selected email (by default, the local
    'root' account is used to receive such emails).

  - <b>Secure</b>: this profile is configured to provide maximum security, even
    at the cost of limiting the remote access to the system. It also runs a wider
    set of periodic checks, enforces the local password settings, and periodically
    checks if the system security settings, configured here, were modified.
""")

AUTH_SECURITY_TEXT=_("""System authentication.

These options control the authentication for different Mandriva tools.
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

SAVE_SETTINGS_TEXT=_("""Save and apply new configuration?""")

class MsecGui:
    """Msec GUI"""
    # common columns
    (COLUMN_OPTION, COLUMN_DESCR, COLUMN_VALUE, COLUMN_CUSTOM) = range(4)
    (COLUMN_PATH, COLUMN_USER, COLUMN_GROUP, COLUMN_PERM, COLUMN_FORCE) = range(5)
    (COLUMN_APP, COLUMN_DESCR, COLUMN_AUTH) = range(3)

    def __init__(self, log, msec, perms, auth, msecconfig, permconfig, authconfig, embed=None):
        """Initializes gui"""
        self.log = log
        self.msec = msec
        self.perms = perms
        self.auth = auth
        # current configuration
        self.msecconfig = msecconfig
        self.authconfig = authconfig
        self.permconfig = permconfig
        # pre-defined default configurations
        self.defaults = {
                config.NONE_LEVEL: (
                    config.load_defaults(log, config.NONE_LEVEL),
                    config.load_default_perms(log, config.NONE_LEVEL)
                    ),
                config.DEFAULT_LEVEL: (
                    config.load_defaults(log, config.DEFAULT_LEVEL),
                    config.load_default_perms(log, config.DEFAULT_LEVEL)
                    ),
                config.SECURE_LEVEL: (
                    config.load_defaults(log, config.SECURE_LEVEL),
                    config.load_default_perms(log, config.SECURE_LEVEL)
                    )
                }

        # pre-load documentation for all possible options
        self.descriptions = {}
        for option in config.SETTINGS:
            # get documentation for item
            config.find_doc(msec, option, cached=self.descriptions)

        # saving old config
        self.oldconfig = {}
        for opt in msecconfig.list_options():
            self.oldconfig[opt] = msecconfig.get(opt)
        # permissions
        self.oldperms = {}
        for opt in permconfig.list_options():
            self.oldperms[opt] = permconfig.get(opt)
        # auth
        self.oldauth = {}
        for opt in authconfig.list_options():
            self.oldauth[opt] = authconfig.get(opt)

        # what level are we?
        level = msecconfig.get("BASE_LEVEL")
        if not level:
            self.log.info(_("No base msec level specified, using '%s'") % config.DEFAULT_LEVEL)
            self.base_level = config.DEFAULT_LEVEL
        elif level == config.NONE_LEVEL or level == config.DEFAULT_LEVEL or level == config.SECURE_LEVEL:
            self.log.info(_("Detected base msec level '%s'") % level)
            self.base_level = level
        else:
            # custom level?
            # TODO: notify user about this
            self.log.info(_("Custom base config level found. Will default to '%s'") % (level, config.DEFAULT_LEVEL))
            self.base_level = config.DEFAULT_LEVEL

        if embed:
            # embedding in MCC
            self.window = gtk.Plug(embed)
        else:
            # running standalone
            self.window = gtk.Window()
            self.window.set_default_size(640, 480)
        self.window.connect('destroy', self.quit)

        # are we enforcing a level
        self.enforced_level = None
        self.enforcing_level = False

        main_vbox = gtk.VBox(homogeneous=False, spacing=5)
        self.window.add(main_vbox)

        # menu
        menubar = gtk.MenuBar()
        main_vbox.pack_start(menubar, False, False)
        menus = [
                    (_("File"),
                    [
                        (_("Save configuration"), self.ok),
                        (None, None),
                        (_("Import configuration"), None),
                        (_("Export configuration"), None),
                        (None, None),
                        (_("Quit"), self.quit),
                    ]),
                    (_("Help"),
                    [
                        (_("Help"), None),
                        (_("About"), None),
                    ]),
                ]
        # building menus
        for topmenu, items in menus:
            # file menu
            filemenu = gtk.MenuItem(topmenu)
            menubar.add(filemenu)
            menu = gtk.Menu()
            filemenu.set_submenu(menu)
            group = None
            for submenu, callback in items:
                menuitem = gtk.MenuItem(submenu)
                if callback:
                    menuitem.connect('activate', callback)
                else:
                    menuitem.set_sensitive(False)
                menu.add(menuitem)

        # creating tabs
        self.notebook = gtk.Notebook()
        main_vbox.add(self.notebook)

        # tabs to create in the intrerface
        tabs = [
            (1, self.level_security_page, _("Basic security")),
            (2, self.auth_security_page, _("Authentication")),
            (3, self.system_security_page, _("System security")),
            (4, self.network_security_page, _("Network security")),
            (5, self.periodic_security_page, _("Periodic checks")),
            (6, self.notifications_page, _("Security notifications")),
            (7, self.permissions_security_page, _("Permissions")),
            ]
        # data to change the values
        self.current_options_view = {}
        for id, callback, label in tabs:
            self.notebook.append_page(callback(id), gtk.Label(label))

        # are we enabled?
        self.toggle_level(self.base_level)

        self.window.show_all()

    def recreate_tabs(self, notebook, tabs):
        """Creates tabs and initializes options values"""
        pass

    def cancel(self, widget):
        """Cancel button"""
        self.quit(widget)

    def help(self, widget):
        """Help button"""
        print "Help clicked."

    def ok(self, widget):
        """Ok button"""
        curconfig = self.msecconfig
        curperms = self.permconfig
        print curperms.list_options()
        # apply config and preview changes
        self.log.start_buffer()
        self.msec.apply(curconfig)
        self.msec.commit(False)
        messages = self.log.get_buffer()

        # creating preview window
        dialog = gtk.Dialog(_("Saving changes.."),
                self.window, gtk.DIALOG_MODAL,
                (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                gtk.STOCK_OK, gtk.RESPONSE_OK)
                )

        label = gtk.Label(SAVE_SETTINGS_TEXT)
        dialog.vbox.pack_start(label, False, False)

        dialog.set_resizable(False)

        # hide all information in an expander
        expander = gtk.Expander(_("Details.."))
        exp_vbox = gtk.VBox()
        expander.add(exp_vbox)
        dialog.vbox.pack_start(expander, False, False)


        # scrolledwindow
        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        exp_vbox.pack_start(sw)


        vbox = gtk.VBox()
        exp_vbox.set_size_request(640, 300)
        sw.add_with_viewport(vbox)

        # check for changed options
        for name, type, oldconf, curconf in [ (_("MSEC option changes"), _("option"), self.oldconfig, curconfig),
                                        (_("System permissions changes"), _("permission check"), self.oldperms, curperms),
                                        (_("System authentication changes"), _("authentication check"), self.oldauth, self.authconfig),
                                        ]:
            # check for changes
            opt_changes = []
            opt_adds = []
            opt_dels = []
            # changed options
            opt_changes = [opt for opt in oldconf if (curconf.get(opt) != oldconf.get(opt) and curconf.get(opt) != None and curconf.get(opt) != None)]
            if len(opt_changes) > 0:
                changes = "\n\t" + "\n\t".join([_("changed %s <b>%s</b> (%s -> %s)") % (type, param, oldconf.get(param), curconf.get(param)) for param in opt_changes])
            else:
                changes = _("no changes")
            # new options
            opt_adds = [opt for opt in curconf.list_options() if (opt not in oldconf and curconf.get(opt))]
            if len(opt_adds) > 0:
                changes += "\n\t" + "\n\t".join([_("added %s <b>%s</b> (%s)") % (type, param, curconf.get(param)) for param in opt_adds])
            # removed options
            opt_dels = [opt for opt in oldconf if (opt not in curconf.list_options() and oldconf.get(opt))]
            if len(opt_dels) > 0:
                changes += "\n\t" + "\n\t".join([_("removed %s <b>%s</b>") % (type, param) for param in opt_dels])
            # adding labels
            label = gtk.Label(_('<b>%s:</b> <i>%s</i>\n') % (name, changes))
            label.set_use_markup(True)
            label.set_property("xalign", 0.0)
            vbox.pack_start(label, False, False)

        # see if there were any changes to system files
        for msg in messages['info']:
            if msg.find(config.MODIFICATIONS_FOUND) != -1 or msg.find(config.MODIFICATIONS_NOT_FOUND) != -1:
                label = gtk.Label(_("<b>MSEC test run results:</b> <i>%s</i>") % msg)
                label.set_line_wrap(True)
                label.set_use_markup(True)
                label.set_property("xalign", 0.0)
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

        # new base level
        self.msecconfig.set("BASE_LEVEL", self.base_level)
        # saving the configuration
        self.msecconfig.save()
        self.msec.apply(self.msecconfig)
        self.msec.commit(True)

        # saving permissions
        self.permconfig.save()

        # saving authentication
        self.authconfig.save()
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
            gobject.TYPE_BOOLEAN)

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

        # column for custom settings
        column = gtk.TreeViewColumn(_('Customized'), gtk.CellRendererToggle(), active=self.COLUMN_CUSTOM)
        column.set_sort_column_id(self.COLUMN_CUSTOM)
        column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        column.set_fixed_width(50)
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

            # now for the value
            value = self.msecconfig.get(option)
            # check for disabled options
            if not value:
                value = config.OPTION_DISABLED

            # description
            doc = config.find_doc(self.msec, option, self.descriptions)

            # was it changed? if yes, change description to italic
            if self.option_is_changed(option, value):
                custom = True
            else:
                custom = False

            # building the option
            iter = lstore.append()
            lstore.set(iter,
                    self.COLUMN_OPTION, option,
                    self.COLUMN_DESCR, doc,
                    self.COLUMN_VALUE, value,
                    self.COLUMN_CUSTOM, custom,
                    )
        return sw, lstore

    def option_is_changed(self, option, value, level=None):
        """Checks if the option is different from one specified by base level"""
        if not level:
            level = self.base_level
        conf, perms = self.defaults[level]
        if conf.get(option) != value:
            # it was changed
            print value
            print conf.get(option)
            return True
        else:
            return False

    def create_auth_treeview(self, options):
        """Creates a treeview for authentication options"""
        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)

        # list of options
        lstore = gtk.TreeStore(
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING)

        # treeview
        treeview = gtk.TreeView(lstore)
        treeview.set_rules_hint(True)
        treeview.set_search_column(self.COLUMN_DESCR)
        treeview.connect('realize', lambda tv: tv.expand_all())

        treeview.connect('row-activated', self.auth_changed, lstore)

        # configuring columns

        # column for option names
        column = gtk.TreeViewColumn(_('Application'), gtk.CellRendererText(), text=self.COLUMN_APP)
        column.set_sort_column_id(self.COLUMN_APP)
        treeview.append_column(column)

        # column for descriptions
        renderer = gtk.CellRendererText()
        renderer.set_property('wrap-width', 400)
        renderer.set_property('wrap-mode', pango.WRAP_WORD_CHAR)
        column = gtk.TreeViewColumn(_('Description'), renderer, text=self.COLUMN_DESCR)
        column.set_sort_column_id(self.COLUMN_DESCR)
        treeview.append_column(column)

        # column for values
        column = gtk.TreeViewColumn(_('Auth'), gtk.CellRendererText(), text=self.COLUMN_AUTH)
        column.set_sort_column_id(self.COLUMN_AUTH)
        treeview.append_column(column)

        sw.add(treeview)

        for name, items in options:
            # building the option
            iter = lstore.append(None)
            lstore.set(iter,
                    self.COLUMN_APP, name,
                    self.COLUMN_DESCR, None,
                    self.COLUMN_AUTH, None,
                    )
            for option in items:
                # retreiving option description
                if not config.MANDRIVA_TOOLS.has_key(option):
                    # invalid option
                    self.log.error(_("Invalid option '%s'!") % option)
                    continue
                descr = config.MANDRIVA_TOOLS[option]
                value = self.authconfig.get(option)

                # building the option
                child_iter = lstore.append(iter)
                lstore.set(child_iter,
                        self.COLUMN_APP, option,
                        self.COLUMN_DESCR, descr,
                        self.COLUMN_AUTH, value,
                        )
        return sw, lstore


    def level_security_page(self, id):
        """Builds the basic security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(LEVEL_SECURITY_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        # security levels
        self.levels_frame = gtk.Frame(_("Base security level"))
        levels_vbox = gtk.VBox()
        self.levels_frame.add(levels_vbox)
        # none
        button = gtk.RadioButton(group=None, label=_("Disable MSEC"))
        button.connect('clicked', self.force_level, config.NONE_LEVEL)
        if self.base_level == config.NONE_LEVEL:
            button.set_active(True)
        levels_vbox.pack_start(button)
        # default
        button = gtk.RadioButton(group=button, label=_("Enable MSEC with DEFAULT security level"))
        button.connect('clicked', self.force_level, config.DEFAULT_LEVEL)
        if self.base_level == config.DEFAULT_LEVEL:
            button.set_active(True)
        levels_vbox.pack_start(button)
        # secure
        button = gtk.RadioButton(group=button, label=_("Enable MSEC with SECURE security level"))
        button.connect('clicked', self.force_level, config.SECURE_LEVEL)
        if self.base_level == config.SECURE_LEVEL:
            button.set_active(True)
        levels_vbox.pack_start(button)

        # putting levels to vbox
        vbox.pack_start(self.levels_frame)

        return vbox

    def auth_security_page(self, id):
        """Builds the authentication page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(AUTH_SECURITY_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)

        auth_vbox = gtk.VBox()

        # security levels
        sw.add_with_viewport(auth_vbox)
        vbox.add(sw)

        apps, model = self.create_auth_treeview(config.MANDRIVA_TOOL_GROUPS)
        auth_vbox.pack_start(apps)
        self.current_options_view[id] = (model, self.authconfig)

        return vbox

    def toggle_level(self, level, force=False):
        """Enables/disables graphical items for msec"""
        if level != config.NONE_LEVEL:
            enabled = True
        else:
            enabled = False

        # update notebook pages
        npages = self.notebook.get_n_pages()
        for page in range(1, npages):
            curpage = self.notebook.get_nth_page(page)
            curpage.set_sensitive(enabled)
            label = self.notebook.get_tab_label(curpage)
            label.set_sensitive(enabled)

        # what is the current level?
        defconfig, defperms = self.defaults[level]

        for z in self.current_options_view:
            print z
            options, curconfig = self.current_options_view[z]
            iter = options.get_iter_root()
            # what options are we changing
            if curconfig.__class__ == config.MsecConfig:
                # main msec options
                while iter:
                    option = options.get_value(iter, self.COLUMN_OPTION)
                    curvalue = options.get_value(iter, self.COLUMN_VALUE)
                    newvalue = defconfig.get(option)
                    if curvalue != newvalue:
                        # changing option
                        print "%s: %s -> %s" % (option, curvalue, newvalue)
                        options.set(iter, self.COLUMN_VALUE, newvalue)
                        curconfig.set(option, newvalue)
                    ## skip custom options
                    #print "Base level: %s" % self.base_level
                    #if self.option_is_changed(option, curvalue):
                    #    # custom option
                    #    print "Custom option detected: %s" % option
                    iter = options.iter_next(iter)
            elif curconfig.__class__ == config.PermConfig:
                # for now, just reset permissions for this level
                # TODO: custom permissions
                options.clear()
                for file in defperms.list_options():
                    user_s, group_s, perm_s, force_s = defperms.get(file)

                    # convert to boolean
                    if force_s:
                        force = True
                    else:
                        force = False

                    # building the option
                    iter = options.append()
                    options.set(iter,
                            self.COLUMN_PATH, file,
                            self.COLUMN_USER, user_s,
                            self.COLUMN_GROUP, group_s,
                            self.COLUMN_PERM, perm_s,
                            self.COLUMN_FORCE, force,
                            )
                    # changing back force value
                    curconfig.set(file, (user_s, group_s, perm_s, force))
            else:
                print curconfig.__class__
        # finally, change new base_level
        self.base_level = level

    def force_level(self, widget, level):
        """Defines a given security level"""
        if widget.get_active():
            #self.base_level = level
            # update everything
            print "Forcing level %s" % level
            self.toggle_level(level, force=True)

    def notifications_page(self, id):
        """Builds the notifications page"""
        vbox = gtk.VBox(homogeneous=False)

        # security levels

        entry = gtk.Label(NOTIFICATIONS_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        # basic security options
        options_view, model = self.create_treeview(["TTY_WARN", "SYSLOG_WARN", "NOTIFY_WARN", "MAIL_WARN", "MAIL_USER", "MAIL_EMPTY_CONTENT"])

        # save those options
        self.current_options_view[id] = (model, self.msecconfig)
        vbox.pack_start(options_view)

        return vbox

    def system_security_page(self, id):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(SYSTEM_SECURITY_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        # system security options
        options_view, model = self.create_treeview(["ENABLE_APPARMOR", "ENABLE_POLICYKIT",
                                            "ENABLE_SUDO", "ENABLE_MSEC_CRON", "ENABLE_PAM_WHEEL_FOR_SU",
                                            "ENABLE_SULOGIN", "CREATE_SERVER_LINK", "ENABLE_AT_CRONTAB",
                                            "ALLOW_ROOT_LOGIN", "ALLOW_USER_LIST", "ENABLE_PASSWORD",
                                            "ALLOW_AUTOLOGIN", "ENABLE_CONSOLE_LOG",
                                            "ENABLE_PAM_WHEEL_FOR_SU", "CREATE_SERVER_LINK", "ALLOW_XAUTH_FROM_ROOT",
                                            "ALLOW_REBOOT", "SHELL_HISTORY_SIZE", "SHELL_TIMEOUT", "PASSWORD_LENGTH",
                                            "PASSWORD_HISTORY", "USER_UMASK", "ROOT_UMASK",
                                            ])
        self.current_options_view[id] = (model, self.msecconfig)
        vbox.pack_start(options_view)

        return vbox

    def network_security_page(self, id):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(NETWORK_SECURITY_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        # network security options
        options_view, model = self.create_treeview(["ACCEPT_BOGUS_ERROR_RESPONSES", "ACCEPT_BROADCASTED_ICMP_ECHO",
                                            "ACCEPT_ICMP_ECHO", "ALLOW_REMOTE_ROOT_LOGIN",
                                            "ALLOW_X_CONNECTIONS", "ALLOW_XSERVER_TO_LISTEN",
                                            "AUTHORIZE_SERVICES", "ENABLE_DNS_SPOOFING_PROTECTION",
                                            "ENABLE_IP_SPOOFING_PROTECTION", "ENABLE_LOG_STRANGE_PACKETS",
                                            ])
        self.current_options_view[id] = (model, self.msecconfig)
        vbox.pack_start(options_view)

        return vbox

    def periodic_security_page(self, id):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(PERIODIC_SECURITY_TEXT)
        vbox.pack_start(entry, False, False)

        self.periodic_checks = gtk.CheckButton(_("Enable periodic security checks"))
        if self.msecconfig.get("CHECK_SECURITY") == "yes":
            self.periodic_checks.set_active(True)
        vbox.pack_start(self.periodic_checks, False, False)

        # network security options
        options_view, model = self.create_treeview(["CHECK_PERMS", "CHECK_USER_FILES", "CHECK_SUID_ROOT", "CHECK_SUID_MD5",
                                            "CHECK_SGID", "CHECK_WRITABLE", "CHECK_UNOWNED",
                                            "CHECK_PROMISC", "CHECK_OPEN_PORT", "CHECK_PASSWD",
                                            "CHECK_SHADOW", "CHECK_CHKROOTKIT", "CHECK_RPM",
                                            "CHECK_SHOSTS"
                                            ])
        vbox.pack_start(options_view)

        # see if these tests are enabled
        self.periodic_checks.connect('clicked', self.periodic_tests, options_view)
        periodic_checks = self.msecconfig.get("CHECK_SECURITY")
        if periodic_checks == 'no':
            # disable all periodic tests
            options_view.set_sensitive(False)
        # TODO: CHECK_SECURITY??
        self.current_options_view[id] = (model, self.msecconfig)

        return vbox

    def periodic_tests(self, widget, options):
        '''Enables/disables periodic security tests.'''
        status = widget.get_active()
        if status:
            self.msecconfig.set("CHECK_SECURITY", "yes")
            options.set_sensitive(True)
        else:
            self.msecconfig.set("CHECK_SECURITY", "no")
            options.set_sensitive(False)

    def permissions_security_page(self, id):
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
        self.current_options_view[id] = (lstore, self.permconfig)
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

        # option is disabled?
        if not value:
            value = config.OPTION_DISABLED

        callback, params = config.SETTINGS[param]
        conf_def, perms = self.defaults[config.DEFAULT_LEVEL]
        conf_sec, perms = self.defaults[config.SECURE_LEVEL]

        val_def = conf_def.get(param)
        val_sec = conf_sec.get(param)

        # asks for new parameter value
        dialog = gtk.Dialog(_("Select new value for %s") % (param),
                self.window, 0,
                (gtk.STOCK_OK, gtk.RESPONSE_OK,
                gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))
        # option title
        label = gtk.Label("<b>%s</b>\n" % param)
        label.set_use_markup(True)
        # description
        dialog.vbox.pack_start(label)
        label = gtk.Label(_("<i>%s</i>\n\n\tCurrent value: <b>%s</b>\n\tDefault level value: <b>%s</b>\n\tSecure level value: <b>%s</b>\n") % (descr, value, val_def, val_sec))
        label.set_line_wrap(True)
        label.set_use_markup(True)
        dialog.vbox.pack_start(label)
        dialog.vbox.pack_start(gtk.HSeparator())

        # new value
        hbox = gtk.HBox()
        hbox.pack_start(gtk.Label(_("New value:")))
        if '*' in params:
            # string parameter
            entry = gtk.Entry()
            entry.set_text(value)
        else:
            # combobox parameter
            entry = gtk.combo_box_new_text()
            # add an item to disable a check
            params.append(config.OPTION_DISABLED)
            for item in params:
                entry.append_text(item)
            if value not in params:
                entry.append_text(value)
                params.append(value)
            active = params.index(value)
            entry.set_active(active)
        hbox.pack_start(entry)
        dialog.vbox.pack_start(hbox)

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
        self.msecconfig.set(param, newval)

        # is it different from default? if yes, change description to italic
        doc = config.find_doc(self.msec, param, self.descriptions)
        if self.option_is_changed(param, newval):
            custom = True
        else:
            custom = False

        model.set(iter, self.COLUMN_VALUE, newval)
        model.set(iter, self.COLUMN_DESCR, doc)
        model.set(iter, self.COLUMN_CUSTOM, custom)


    def auth_changed(self, treeview, path, col, model):
        """Processes an option change"""
        iter = model.get_iter(path)
        param = model.get_value(iter, self.COLUMN_APP)
        descr = model.get_value(iter, self.COLUMN_DESCR)
        value = model.get_value(iter, self.COLUMN_AUTH)

        if len(path) < 2:
            # We are clicking on an option group
            return

        # asks for new parameter value
        dialog = gtk.Dialog(_("Specify new authentication for %s") % (param),
                self.window, 0,
                (gtk.STOCK_OK, gtk.RESPONSE_OK,
                gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))
        label = gtk.Label(_("Modifying <b>%s</b> authentication.\n<i>%s</i>\nCurrent value: <b>%s</b>") % (param, descr, value))
        label.set_line_wrap(True)
        label.set_use_markup(True)
        dialog.vbox.pack_start(label)
        # combobox parameter
        entry = gtk.combo_box_new_text()
        params = [config.AUTH_NO_PASSWD, config.AUTH_ROOT_PASSWD, config.AUTH_USER_PASSWD]
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
        newval = entry.get_active_text()
        dialog.destroy()

        # update options
        self.authconfig.set(param, newval)

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
    -e, --embedded <XID>    embed in MCC.
""" % version
# }}}

if __name__ == "__main__":
    log_level = logging.INFO
    PlugWindowID = None

    # parse command line
    try:
        opt, args = getopt.getopt(sys.argv[1:], 'hde:', ['help', 'debug', 'embedded='])
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
        elif o[0] == '-e' or o[0] == '--embedded':
            try:
                PlugWindowID = long(o[1])
            except:
                print >>sys.stderr, "Error: bad master window XID (%s)!" % o[1]
                sys.exit(1)

    # configuring logging
    log = Log(interactive=True, log_syslog=False, log_file=True, log_level=log_level, log_path=config.SECURITYLOG)

    # loading initial config
    msec_config = config.MsecConfig(log, config=config.SECURITYCONF)
    if not msec_config.load():
        log.info(_("Unable to load config."))

    # loading permissions config
    perm_conf = config.PermConfig(log, config=config.PERMCONF)
    if not perm_conf.load():
        log.info(_("Unable to load permissions."))

    # loading auth config
    auth_conf = config.AuthConfig(log)
    if not auth_conf.load():
        log.info(_("Unable to load auth config."))

    # creating an msec instance
    msec = MSEC(log)
    perms = PERMS(log)

    log.info("Starting gui..")

    gui = MsecGui(log, msec, perms, None, msec_config, perm_conf, auth_conf, embed=PlugWindowID)
    gtk.main()

