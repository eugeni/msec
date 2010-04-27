#!/usr/bin/python -O
"""
This is graphical frontend to msec.
"""

import os
import sys
import string
import getopt
import signal
import traceback
import Queue
from textwrap import wrap

# PyGTK
import warnings
warnings.filterwarnings('error', module='gtk')
try:
    import gtk
    import pygtk
    import gobject
    import pango
except Warning, e:
    print "ERROR: %s" % e
    print "Exiting.."
    sys.exit(1)
warnings.resetwarnings()

# config
import config
# helper tools
import tools

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
    gettext.install("msec")
except IOError:
    _ = str

# text strings
LEVEL_SECURITY_TEXT=_("""<big><b>Choose security level</b></big>
This application allows you to configure your system security. If you wish
to activate it, choose the appropriate security level: """)

# level descriptions
level_descriptions = {
        "standard": _("""This profile configures a reasonably safe set of security features. It is the suggested level for Desktop. If unsure which profile to use, use this one."""),
        "netbook": _("""This profile is focused on netbooks, laptops or low-end devices, which are only accessed by local users and run on batteries."""),

        "secure": _("""This profile is configured to provide maximum security, even at the cost of limiting the remote access to the system. This level is suggested for security-concerned systems and servers. """),

        "fileserver": _("""This profile is targeted on local network servers, which do not receive accesses from unauthorized Internet users."""),

        "webserver": _("""This profile is provided for servers which are intended to be accessed by unauthorized Internet users."""),
        "audit_daily": _("""This profile is intended for the users who do not rely on msec to change system settings, and use it for periodic checks only. It configures all periodic checks to run once a day."""),
        "audit_weekly": _("""This profile is similar to the 'audit_daily' profile, but it runs all checks weekly."""),
}

# level order. Levels will appear in this order, the unspecified levels will appear last
level_order = ["standard", "netbook", "fileserver", "webserver", "secure", "audit_daily", "audit_weekly"]

# description for level without description
DEFAULT_LEVEL_DESCRIPTION="\n".join(wrap(_("""Custom security level."""), 80))


SYSTEM_SECURITY_TEXT=_("""<big><b>System security options</b></big>
These options control the local security configuration, such as the login restrictions,
password configurations, integration with other security tools, and default file creation
permissions.  """)

NETWORK_SECURITY_TEXT=_("""<big><b>Network security options</b></big>
These options define the network security against remote threats, unauthorized accesses,
and breakin attempts.  """)

PERIODIC_SECURITY_TEXT=_("""<big><b>Periodic security checks</b></big>
These options configure the security checks that should be executed periodically.  """)

EXCEPTIONS_TEXT=_("""<big><b>Exceptions</b></big>
Here you can configure the allowed exceptions for msec periodic security
checks. For each supported test, you may add as many exceptions as you want
for each check. Note that each exception is parsed as a regexp.""")

PERMISSIONS_SECURITY_TEXT=_("""<big><b>File permissions</b></big>
These options allow to fine-tune system permissions for important files and directories.
The following permissions are checked periodically, and any change to the owner, group,
or current permission is reported. The permissions can be enforced, automatically
changing them to the specified values when a change is detected.  """)

SAVE_SETTINGS_TEXT=_("""Save and apply new configuration?""")

# gui-related settings
DEFAULT_SPACING=5
BANNER="msec.png"

class MsecGui:
    """Msec GUI"""
    # common columns
    (COLUMN_LEVEL, COLUMN_LEVEL_DESCR, COLUMN_LEVEL_CURRENT) = range(3)
    (COLUMN_OPTION, COLUMN_DESCR, COLUMN_VALUE, COLUMN_CUSTOM) = range(4)
    (COLUMN_PATH, COLUMN_USER, COLUMN_GROUP, COLUMN_PERM, COLUMN_FORCE, COLUMN_ACL) = range(6)
    (COLUMN_EXCEPTION, COLUMN_EXCEPTION_VALUE, COLUMN_POS) = range(3)

    def __init__(self, log, msec, perms, msecconfig, permconfig, exceptions, embed=None):
        """Initializes gui"""
        self.log = log
        self.msec = msec
        self.perms = perms

        # current configuration
        self.msecconfig = msecconfig
        self.permconfig = permconfig
        self.exceptions = exceptions

        # pre-defined standard configurations
        self.msec_defaults = {}
        self.perm_defaults = {}
        levels = config.list_available_levels(log, '')
        for z in levels:
            try:
                self.msec_defaults[z] = config.load_defaults(log, z)
            except:
                self.log.error(_("Unable to load configuration for level '%s'") % z)
                traceback.print_exc()
                continue
            try:
                self.perm_defaults[z] = config.load_default_perms(log, z)
            except:
                self.log.error(_("Unable to load permissions for level '%s'") % z)
                traceback.print_exc()
                continue

        # pre-load documentation for all possible options
        self.descriptions = {}
        for option in config.SETTINGS:
            # get documentation for item
            config.find_doc(msec, option, cached=self.descriptions)

        # loading the current config
        self.reload_config()

        if embed:
            # embedding in MCC
            self.window = gtk.Plug(embed)
        else:
            # running standalone
            self.window = gtk.Window()
            self.window.set_default_size(640, 440)
        self.window.connect('delete-event', self.quit)

        # are we enforcing a level
        self.enforced_level = None
        self.enforcing_level = False

        main_vbox = gtk.VBox(homogeneous=False, spacing=5)
        self.window.add(main_vbox)

        # menu
        menubar = gtk.MenuBar()
        main_vbox.pack_start(menubar, False, False)
        menus = [
                    (_("_File"),
                    [
                        (_("_Save configuration"), self.ok),
#                        (None, None),
#                        (_("_Import configuration"), None),
#                        (_("_Export configuration"), None),
#                        (None, None),
                        (_("_Quit"), self.quit),
                    ]),
                    (_("_Help"),
                    [
                        (_("_Help"), None),
                        (_("_About"), None),
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

        # show logo
        banner = gtk.HBox(homogeneous=False, spacing=10)
        try:
            # logo
            image = gtk.Image()
            pixbuf = gtk.gdk.pixbuf_new_from_file("%s/%s" % (config.MSEC_DIR, BANNER))
            image.set_from_pixbuf(pixbuf)
            banner.pack_start(image, False, False)
            label = gtk.Label(_("MSEC: System Security and Audit"))
            label.modify_font(pango.FontDescription("13"))
            banner.pack_start(label, False, False)
            main_vbox.pack_start(banner, False, False)
        except:
            print "Banner %s Not found" % ("%s/%s" % (config.MSEC_DIR, BANNER))

        # creating main UI
        self.main_notebook = gtk.Notebook()
        main_vbox.pack_start(self.main_notebook)

        # creating tabs
        self.notebook = gtk.Notebook()
        self.main_notebook.append_page(self.create_summary_ui(), gtk.Label(_("Overview")))
        self.main_notebook.append_page(self.notebook, gtk.Label(_("Security settings")))

        # data to change the values
        self.current_options_view = {}
        # checkboxes callbacks
        self.checkboxes_callbacks = {}

        # tabs to create in the intrerface
        tabs = [
            (1, self.level_security_page, _("Basic security")),
            (2, self.system_security_page, _("System security")),
            (3, self.network_security_page, _("Network security")),
            (4, self.periodic_security_page, _("Periodic checks")),
            (5, self.exceptions_page, _("Exceptions")),
            (6, self.permissions_security_page, _("Permissions")),
            ]
        for id, callback, label in tabs:
            self.notebook.append_page(callback(id), gtk.Label(label))

        # are we enabled?
        self.toggle_level(self.base_level)

        # pending signals
        self.signals = Queue.Queue()
        gobject.timeout_add(500, self.check_signals)

        self.window.show_all()

    def level_changed(self, treeview, path, col, model):
        """Switches to a new security level"""
        iter = model.get_iter(path)
        level = model.get_value(iter, self.COLUMN_LEVEL)
        print "Switching to %s" % level
        self.toggle_level(level, force=True)

    def check_signals(self):
        """Checks for received signals"""
        if not self.signals.empty():
            s = self.signals.get()
            if s == signal.SIGTERM:
                self.quit(self.window)
        gobject.timeout_add(500, self.check_signals)

    def check_for_changes(self, curconfig, curperms):
        """Checks for changes in configuration. Returns number of configuration
        changes, the description of changes, and results of msec dry run"""
        # apply config and preview changes
        self.log.start_buffer()
        self.msec.apply(curconfig)
        self.msec.commit(False)
        messages = self.log.get_buffer()
        # check for changed options
        num_changes = 0
        changes = []
        for name, type, oldconf, curconf in [ (_("MSEC option changes"), _("option"), self.oldconfig, curconfig),
                                        (_("System permissions changes"), _("permission check"), self.oldperms, curperms),
                                        ]:
            # check for changes
            opt_changes = []
            opt_adds = []
            opt_dels = []
            # changed options
            curchanges = ""
            opt_changes = [opt for opt in oldconf if (curconf.get(opt) != oldconf.get(opt) and curconf.get(opt) != None and curconf.get(opt) != None)]
            if len(opt_changes) > 0:
                curchanges += "\n\t" + "\n\t".join([_("changed %s <b>%s</b> (%s -> %s)") % (type, param, oldconf.get(param), curconf.get(param)) for param in opt_changes])
                num_changes += len(opt_changes)
            # new options
            opt_adds = [opt for opt in curconf.list_options() if (opt not in oldconf and curconf.get(opt))]
            if len(opt_adds) > 0:
                curchanges += "\n\t" + "\n\t".join([_("added %s <b>%s</b> (%s)") % (type, param, curconf.get(param)) for param in opt_adds])
                num_changes += len(opt_adds)
            # removed options
            opt_dels = [opt for opt in oldconf if ((opt not in curconf.list_options() or curconf.get(opt) == None) and oldconf.get(opt))]
            if len(opt_dels) > 0:
                curchanges += "\n\t" + "\n\t".join([_("removed %s <b>%s</b>") % (type, param) for param in opt_dels])
                num_changes += len(opt_dels)
            # adding labels
            if curchanges == "":
                curchanges = _("no changes")
            # store the current changes
            changes.append((name, curchanges))
        # return what we found
        return num_changes, changes, messages

    def ok(self, widget, ask_ignore=False):
        """Ok button"""
        curconfig = self.msecconfig
        curperms = self.permconfig

        # creating preview window
        if ask_ignore:
            dialog = gtk.Dialog(_("Saving changes.."),
                    self.window, gtk.DIALOG_MODAL,
                    (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                    _("Ignore and quit"), gtk.RESPONSE_REJECT,
                    gtk.STOCK_OK, gtk.RESPONSE_OK)
                    )
        else:
            dialog = gtk.Dialog(_("Saving changes.."),
                    self.window, gtk.DIALOG_MODAL,
                    (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                    gtk.STOCK_OK, gtk.RESPONSE_OK)
                    )

        dialog.set_default_size(640, 300)
        dialog.set_default_response(gtk.RESPONSE_OK)

        label = gtk.Label(SAVE_SETTINGS_TEXT)
        dialog.vbox.set_spacing(DEFAULT_SPACING)
        dialog.vbox.pack_start(label, False, False, padding=DEFAULT_SPACING)

        dialog.set_resizable(False)

        # detailed information
        exp_vbox = gtk.VBox()

        # scrolledwindow
        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        exp_vbox.pack_start(sw, padding=DEFAULT_SPACING)


        vbox = gtk.VBox()
        exp_vbox.set_size_request(640, 280)
        sw.add_with_viewport(vbox)

        # were there changes in configuration?
        num_changes, allchanges, messages = self.check_for_changes(curconfig, curperms)

        # TODO: FIX
        for name, changes in allchanges:
            label = gtk.Label(_('<b>%s:</b> <i>%s</i>\n') % (name, changes))
            label.set_use_markup(True)
            label.set_property("xalign", 0.0)
            vbox.pack_start(label, False, False, padding=DEFAULT_SPACING)
        # see if there were any changes to system files
        for msg in messages['info']:
            if msg.find(config.MODIFICATIONS_FOUND) != -1 or msg.find(config.MODIFICATIONS_NOT_FOUND) != -1:
                label = gtk.Label(_("<b>MSEC test run results:</b> <i>%s</i>") % msg)
                label.set_line_wrap(True)
                label.set_use_markup(True)
                label.set_property("xalign", 0.0)
                vbox.pack_start(label, False, False, padding=DEFAULT_SPACING)
                break

        # adding specific messages
        advanced = gtk.Expander(_("Details"))
        vbox_advanced = gtk.VBox()
        advanced.add(vbox_advanced)
        vbox.pack_start(advanced, False, False, padding=DEFAULT_SPACING)
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
            vbox_advanced.pack_start(expander, False, False, padding=DEFAULT_SPACING)

        # hide all information in an expander
        expander = gtk.Expander(_("Details (%d changes)..") % num_changes)
        expander.add(exp_vbox)
        dialog.vbox.pack_start(expander, False, False, padding=DEFAULT_SPACING)

        dialog.show_all()
        response = dialog.run()
        if response != gtk.RESPONSE_OK:
            dialog.destroy()
            return response
        dialog.destroy()

        # new base level
        self.msecconfig.set("BASE_LEVEL", self.base_level)
        levelconf = config.load_defaults(log, self.base_level)
        standard_permconf = config.load_default_perms(log, self.base_level)

        # saving the configuration
        self.msecconfig.save(levelconf)
        self.msec.apply(self.msecconfig)
        self.msec.commit(True)

        # saving permissions
        self.permconfig.save(standard_permconf)

        self.reload_config()

        return response

    def reload_config(self):
        """Reloads config files"""
        # msecconfig
        self.msecconfig.reset()
        self.msecconfig.load()
        config.merge_with_baselevel(log, self.msecconfig, self.msecconfig.get_base_level(), config.load_defaults, root='')
        # permconfig
        self.permconfig.reset()
        self.permconfig.load()
        config.merge_with_baselevel(log, self.permconfig, self.msecconfig.get_base_level(), config.load_default_perms, root='')
        # exceptions
        self.exceptions.reset()
        self.exceptions.load()
        # saving old config
        self.oldconfig = {}
        for opt in self.msecconfig.list_options():
            self.oldconfig[opt] = self.msecconfig.get(opt)
        # permissions
        self.oldperms = {}
        for opt in self.permconfig.list_options():
            self.oldperms[opt] = self.permconfig.get(opt)

        # what level are we?
        level = self.msecconfig.get("BASE_LEVEL")
        if not level:
            self.log.info(_("No base msec level specified, using '%s'") % config.STANDARD_LEVEL)
            self.base_level = config.STANDARD_LEVEL
        else:
            self.log.info(_("Detected base msec level '%s'") % level)
            self.base_level = level

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
            gobject.TYPE_INT)

        # treeview
        treeview = gtk.TreeView(lstore)
        treeview.set_rules_hint(True)
        treeview.set_search_column(self.COLUMN_DESCR)

        treeview.connect('row-activated', self.option_changed, lstore)

        # configuring columns

        # column for option names
        renderer = gtk.CellRendererText()
        renderer.set_property('width', 200)
        column = gtk.TreeViewColumn(_('Security Option'), renderer, text=self.COLUMN_OPTION, weight=self.COLUMN_CUSTOM)
        column.set_sort_column_id(self.COLUMN_OPTION)
        column.set_resizable(True)
        column.set_expand(True)
        treeview.append_column(column)

        # column for descriptions
        renderer = gtk.CellRendererText()
        renderer.set_property('wrap-width', 400)
        renderer.set_property('wrap-mode', pango.WRAP_WORD_CHAR)
        column = treeview.insert_column_with_attributes(-1, _('Description'), renderer, text=self.COLUMN_DESCR, weight=self.COLUMN_CUSTOM)
        column.set_expand(True)
        #treeview.append_column(column)

        # column for values
        column = gtk.TreeViewColumn(_('Value'), gtk.CellRendererText(), text=self.COLUMN_VALUE, weight=self.COLUMN_CUSTOM)
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

            # now for the value
            value = self.msecconfig.get(option)
            # check for disabled options
            if not value:
                value = config.OPTION_DISABLED

            # description
            doc = config.find_doc(self.msec, option, self.descriptions)

            # was it changed? if yes, change description to italic
            if self.option_is_changed(option, value):
                custom = pango.WEIGHT_BOLD
            else:
                custom = pango.WEIGHT_NORMAL

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
        conf = self.msec_defaults[level]
        if conf.get(option) != value:
            # it was changed
            return True
        else:
            return False

    def create_summary_ui(self):
        """Builds the security summary UI"""
        vbox = gtk.VBox(homogeneous=False, spacing=20)

        table = gtk.Table(4, 4, False)

        def create_security_item(table, row, text, icon=None):
            # show logo
            banner = gtk.HBox(homogeneous=False, spacing=10)
            if icon:
                try:
                    # logo
                    image = gtk.Image()
                    pixbuf = gtk.gdk.pixbuf_new_from_file(icon)
                    image.set_from_pixbuf(pixbuf)
                    banner.pack_start(image, False, False)
                    table.attach(banner, 0, 1, row, row+1, gtk.EXPAND | gtk.FILL, 0, 0, 0)
                except:
                    print "Unable to load icon %s: %s" % (icon, sys.exc_value)
            label = gtk.Label(text)
            label.set_property("xalign", 0.0)
            label.modify_font(pango.FontDescription("12"))
            label.set_property("xalign", 0.0)
            label.set_property("yalign", 0.5)

            table.attach(label, 1, 2, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)

        row = 0
        # firewall
        create_security_item(table, row, _("Firewall"), "/usr/share/mcc/themes/default/firewall-mdk.png")
        firewall_status = tools.find_firewall_info(log)
        label = gtk.Label(firewall_status)
        label.set_property("xalign", 0.0)
        label.set_property("yalign", 0.5)
        table.attach(label, 2, 3, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)

        button = gtk.Button(_("Configure"))
        button.connect('clicked', self.run_configure_app, tools.FIREWALL_CMD)
        table.attach(button, 3, 4, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)
        vbox.pack_start(table, False, False)

        row += 1

        # updates
        create_security_item(table, row, _("Updates"), "/usr/share/mcc/themes/default/mdkonline-mdk.png")
        updates = tools.get_updates_status(log)
        label = gtk.Label(updates)
        label.set_property("xalign", 0.0)
        label.set_property("yalign", 0.5)
        table.attach(label, 2, 3, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)
        button = gtk.Button(_("Update now"))
        button.connect('clicked', self.run_configure_app, tools.UPDATE_CMD)
        table.attach(button, 3, 4, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)

        row += 1

        # security
        create_security_item(table, row, _("Security"), "/usr/share/mcc/themes/default/security-mdk.png")
        baselevel = self.msecconfig.get("BASE_LEVEL")
        if baselevel == config.NONE_LEVEL:
            msec_status = [_("Msec is disabled")]
        else:
            msec_status = []
            msec_status.append(_("Msec is enabled"))
            msec_status.append(_("Base security level: '%s'") % baselevel)
            # find out custom settings
            custom_count = 0
            base_config = self.msec_defaults[baselevel]
            for o in self.msecconfig.list_options():
                if self.msecconfig.get(o) != base_config.get(o):
                    custom_count += 1
            if custom_count > 0:
                msec_status.append(_("Custom settings: %d") % custom_count)
        label = gtk.Label("\n".join(msec_status))
        label.set_property("xalign", 0.0)
        label.set_property("yalign", 0.5)
        table.attach(label, 2, 3, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)

        button = gtk.Button(_("Configure"))
        button.connect('clicked', lambda x: self.main_notebook.set_current_page(1))
        table.attach(button, 3, 4, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)

        row += 1

        # msec reports
        label = gtk.Label(_("Periodic checks"))
        label.set_property("xalign", 0.0)
        label.set_property("yalign", 0.5)
        label.modify_font(pango.FontDescription("11"))
        table.attach(label, 2, 3, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)
        row += 1
        for check, logfile, updated_n, updated in tools.periodic_check_status(log):
            if not updated:
                updated = _("Never")
            label = gtk.Label(_("Check: %s. Last run: %s") % (check, updated))
            label.set_property("xalign", 0.0)
            table.attach(label, 2, 3, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)

            button = gtk.Button(_("Run now"))
            button.connect('clicked', self.show_test_results, logfile)
            table.attach(button, 3, 4, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)
            row += 1

        return vbox

    def show_test_results(self, widget, logfile):
        """Shows results for the test"""

    def run_configure_app(self, widget, cmd):
        """Runs application-specific configuration"""
        os.system(cmd)
        self.reload_summary()

    def reload_summary(self):
        """Reloads summary tab"""
        pass

    def level_security_page(self, id):
        """Builds the basic security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(LEVEL_SECURITY_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        # none
        self.msec_enabled = gtk.CheckButton(label=_("Enable MSEC tool"))
        if self.base_level != config.NONE_LEVEL:
            self.msec_enabled.set_active(True)
        self.msec_enabled.connect('clicked', self.enable_disable_msec)
        vbox.pack_start(self.msec_enabled, False, False)

        # security levels
        self.levels_frame = gtk.Frame(_("Select the base security level"))
        levels_vbox = gtk.VBox(homogeneous=False)
        self.levels_frame.add(levels_vbox)
        # create the security level selection screen
        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)

        # list of levels
        lstore = gtk.ListStore(
                gobject.TYPE_STRING,
                gobject.TYPE_STRING,
                gobject.TYPE_INT)

        # treeview
        treeview = gtk.TreeView(lstore)
        treeview.set_rules_hint(True)
        treeview.set_search_column(self.COLUMN_LEVEL_DESCR)
        treeview.connect('row-activated', self.level_changed, lstore)

        # columns
        # column for level names
        renderer = gtk.CellRendererText()
        column = gtk.TreeViewColumn(_('Level name'), renderer, text=self.COLUMN_OPTION, weight=self.COLUMN_LEVEL_CURRENT)
        column.set_sort_column_id(self.COLUMN_LEVEL)
        column.set_resizable(True)
        column.set_expand(False)
        treeview.append_column(column)

        # column for descriptions
        renderer = gtk.CellRendererText()
        renderer.set_property('wrap-width', 600)
        renderer.set_property('wrap-mode', pango.WRAP_WORD_CHAR)
        column = treeview.insert_column_with_attributes(-1, _('Description'), renderer, text=self.COLUMN_DESCR, weight=self.COLUMN_LEVEL_CURRENT)
        column.set_expand(True)
        #treeview.append_column(column)

        sw.add(treeview)

        # first, add levels from level_order
        levels = []
        for level in level_order:
            if level in self.msec_defaults:
                levels.append(level)
        # then, add all other levels
        for level in self.msec_defaults:
            if level not in levels:
                levels.append(level)

        # now build the gui
        for level in levels:
            # skip NONE level, as it disables msec
            if level == "none":
                continue
            if level in level_descriptions:
                descr = level_descriptions[level]
            else:
                descr = DEFAULT_LEVEL_DESCRIPTION
            # TODO: mark current level as bold
            iter = lstore.append()
            if self.base_level == level:
                weight = pango.WEIGHT_BOLD
            else:
                weight = pango.WEIGHT_NORMAL
            lstore.set(iter,
                    self.COLUMN_LEVEL, level,
                    self.COLUMN_LEVEL_DESCR, descr,
                    self.COLUMN_LEVEL_CURRENT, weight)

        levels_vbox.pack_start(sw)
        vbox.pack_start(self.levels_frame)

        # save the list of levels
        self.level_list = lstore

        # putting levels to vbox

        # notifications by email
        hbox = gtk.HBox()
        self.notify_mail = gtk.CheckButton(_("Send security alerts by email to:"))
        if self.msecconfig.get("MAIL_WARN") == "yes":
            self.notify_mail.set_active(True)
        hbox.pack_start(self.notify_mail, False, False)

        # email address
        self.email_entry = gtk.Entry()
        email = self.msecconfig.get("MAIL_USER")
        if not email:
            email = ""
        self.email_entry.set_text(email)
        self.email_entry.connect('changed', self.change_email)
        hbox.pack_start(self.email_entry, False, False, 5)
        vbox.pack_start(hbox, False, False)

        # updating the mail address/checkbox relationship
        self.notify_mail.connect('clicked', self.notify_mail_changed, self.email_entry)
        self.checkboxes_callbacks["MAIL_WARN"] = (self.notify_mail_changed, self.notify_mail, hbox)

        self.notify_mail_changed(self.notify_mail, hbox)

        # notifications on desktop
        self.notify_desktop = gtk.CheckButton(_("Display security alerts on desktop"))
        if self.msecconfig.get("NOTIFY_WARN") == "yes":
            self.notify_desktop.set_active(True)
        self.notify_desktop.connect('clicked', self.notify_changed, None)
        vbox.pack_start(self.notify_desktop, False, False)
        self.checkboxes_callbacks["NOTIFY_WARN"] = (self.notify_changed, self.notify_desktop, None)

        return vbox

    def change_email(self, widget):
        """Email address was changed"""
        email = widget.get_text()
        self.msecconfig.set("MAIL_USER", email)

    def notify_mail_changed(self, widget, param):
        """Changes to mail notifications"""
        status = widget.get_active()
        if status:
            self.msecconfig.set("MAIL_WARN", "yes")
            param.set_sensitive(True)
        else:
            if self.msecconfig.get("MAIL_WARN"):
                self.msecconfig.set("MAIL_WARN", "no")
            param.set_sensitive(False)

    def notify_changed(self, widget, param):
        """Changes to mail notifications"""
        status = widget.get_active()
        if status:
            self.msecconfig.set("NOTIFY_WARN", "yes")
        else:
            self.msecconfig.set("NOTIFY_WARN", "no")

    def enable_disable_msec(self, widget):
        """Enables/disables msec tool"""
        newstatus = widget.get_active()
        if newstatus == False:
            self.toggle_level(config.NONE_LEVEL, force=True)
        else:
            # revert back to the selected level or switch to 'Standard' if none
            level = config.STANDARD_LEVEL
            iter = self.level_list.get_iter_root()
            while iter:
                list_level = self.level_list.get_value(iter, self.COLUMN_LEVEL)
                list_weight = self.level_list.get_value(iter, self.COLUMN_LEVEL_CURRENT)
                if list_weight == pango.WEIGHT_BOLD:
                    # found previous level
                    level = list_level
                    break
                iter = self.level_list.iter_next(iter)
            self.toggle_level(level, force=True)


    def toggle_level(self, level, force=False):
        """Enables/disables graphical items for msec"""

        if level != config.NONE_LEVEL:
            enabled = True
        else:
            enabled = False

        # update notebook pages
        npages = self.notebook.get_n_pages()
        self.levels_frame.set_sensitive(enabled)
        for page in range(1, npages):
            curpage = self.notebook.get_nth_page(page)
            curpage.set_sensitive(enabled)
            label = self.notebook.get_tab_label(curpage)
            label.set_sensitive(enabled)

        if level == self.base_level:
            # Not changing anything
            return

        # updating the markup of new current level unless switching to 'None' level
        # in this case, we'll still use current level in case user decides to switch back later
        if level != config.NONE_LEVEL:
            iter = self.level_list.get_iter_root()
            while iter:
                list_level = self.level_list.get_value(iter, self.COLUMN_LEVEL)
                if list_level != level:
                    # not current level, changing font weight
                    self.level_list.set(iter,
                            self.COLUMN_LEVEL_CURRENT, pango.WEIGHT_NORMAL)
                else:
                    # updating current level
                    self.level_list.set(iter,
                            self.COLUMN_LEVEL_CURRENT, pango.WEIGHT_BOLD)
                iter = self.level_list.iter_next(iter)

        # what is the current level?
        defconfig = self.msec_defaults[level]

        for z in self.current_options_view:
            options, curconfig = self.current_options_view[z]
            iter = options.get_iter_root()
            # what options are we changing
            if curconfig.__class__ == config.MsecConfig:
                # main msec options
                while iter:
                    option = options.get_value(iter, self.COLUMN_OPTION)
                    curvalue = options.get_value(iter, self.COLUMN_VALUE)
                    newvalue = defconfig.get(option)
                    # changing option
                    if force:
                        if curvalue != newvalue:
                            self.log.debug("%s: %s -> %s" % (option, curvalue, newvalue))
                            options.set(iter, self.COLUMN_VALUE, newvalue)
                            # reset customization
                            curconfig.set(option, newvalue)
                    # set option as normal
                    options.set(iter, self.COLUMN_CUSTOM, pango.WEIGHT_NORMAL)
                    ## skip custom options
                    #print "Base level: %s" % self.base_level
                    #if self.option_is_changed(option, curvalue):
                    #    # custom option
                    #    print "Custom option detected: %s" % option
                    iter = options.iter_next(iter)
            elif curconfig.__class__ == config.PermConfig:
                self.reset_permissions(None, options, level=level)
                pass
            else:
                #print curconfig.__class__
                pass
        # checkboxes
        for option in self.checkboxes_callbacks:
            if force:
                func, widget, callback = self.checkboxes_callbacks[option]
                if defconfig.get(option) == "yes":
                    widget.set_active(True)
                else:
                    widget.set_active(False)
                self.msecconfig.set(option, defconfig.get(option))
                func(widget, callback)
        # finally, change new base_level
        self.base_level = level

    def force_level(self, widget, level):
        """Defines a given security level"""
        if widget.get_active():
            #self.base_level = level
            # update everything
            self.toggle_level(level, force=True)

    def system_security_page(self, id):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(SYSTEM_SECURITY_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        # system security options
        options_view, model = self.create_treeview(config.SETTINGS_SYSTEM)
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
        options_view, model = self.create_treeview(config.SETTINGS_NETWORK)
        self.current_options_view[id] = (model, self.msecconfig)
        vbox.pack_start(options_view)

        return vbox

    def periodic_security_page(self, id):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(PERIODIC_SECURITY_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        periodic_checks = self.msecconfig.get("CHECK_SECURITY")

        self.periodic_checks = gtk.CheckButton(_("Enable periodic security checks"))
        if periodic_checks == "yes":
            self.periodic_checks.set_active(True)
        vbox.pack_start(self.periodic_checks, False, False)

        # network security options
        options_view, model = self.create_treeview(config.SETTINGS_PERIODIC)
        vbox.pack_start(options_view)

        # see if these tests are enabled
        self.periodic_checks.connect('clicked', self.periodic_tests, options_view)
        if periodic_checks == 'no':
            # disable all periodic tests
            options_view.set_sensitive(False)

        # save options
        self.current_options_view[id] = (model, self.msecconfig)

        # save the checkboxes
        self.checkboxes_callbacks["CHECK_SECURITY"] = (self.periodic_tests, self.periodic_checks, options_view)

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

    def exceptions_page(self, id):
        """Builds the exceptions page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(EXCEPTIONS_TEXT)
        entry.set_use_markup(True)
        vbox.pack_start(entry, False, False)

        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)

        # list of options
        lstore = gtk.ListStore(
            gobject.TYPE_STRING,
            gobject.TYPE_STRING
            )

        # treeview
        treeview = gtk.TreeView(lstore)
        treeview.set_rules_hint(True)
        treeview.set_search_column(self.COLUMN_EXCEPTION)

        # TODO: fix
        treeview.connect('row-activated', self.exception_changed, lstore)

        # configuring columns

        # column for exception position
        column = gtk.TreeViewColumn(_('Security check'), gtk.CellRendererText(), text=self.COLUMN_EXCEPTION)
        column.set_sort_column_id(self.COLUMN_EXCEPTION)
        column.set_expand(True)
        treeview.append_column(column)

        # column for check exception
        column = gtk.TreeViewColumn(_('Exception'), gtk.CellRendererText(), text=self.COLUMN_EXCEPTION_VALUE)
        column.set_sort_column_id(self.COLUMN_EXCEPTION_VALUE)
        column.set_expand(True)
        treeview.append_column(column)

        sw.add(treeview)

        for option, value in self.exceptions.list_options():
            # building the option
            iter = lstore.append()
            lstore.set(iter,
                    self.COLUMN_EXCEPTION, option,
                    self.COLUMN_EXCEPTION_VALUE, value,
                    )
        vbox.pack_start(sw)
        self.current_options_view[id] = (lstore, self.exceptions)

        # buttons hbox
        hbox = gtk.HBox(homogeneous=True, spacing=10)

        # add
        button = gtk.Button(_("Add a rule"))
        button.connect('clicked', self.add_exception, lstore)
        hbox.pack_start(button, False)

        # delete
        button = gtk.Button(_("Delete"))
        button.connect('clicked', self.remove_exception, treeview)
        hbox.pack_start(button, False)

        vbox.pack_start(hbox, False, False)

        return vbox

    def permissions_security_page(self, id):
        """Builds the network security page"""
        vbox = gtk.VBox(homogeneous=False)

        entry = gtk.Label(PERMISSIONS_SECURITY_TEXT)
        entry.set_use_markup(True)
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
            gobject.TYPE_BOOLEAN,
            gobject.TYPE_STRING)

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
        column.set_expand(True)
        treeview.append_column(column)

        # column for user
        column = gtk.TreeViewColumn(_('User'), gtk.CellRendererText(), text=self.COLUMN_USER)
        column.set_sort_column_id(self.COLUMN_USER)
        column.set_expand(True)
        treeview.append_column(column)

        # column for group
        column = gtk.TreeViewColumn(_('Group'), gtk.CellRendererText(), text=self.COLUMN_GROUP)
        column.set_sort_column_id(self.COLUMN_GROUP)
        column.set_expand(True)
        treeview.append_column(column)

        # column for permissions
        column = gtk.TreeViewColumn(_('Permissions'), gtk.CellRendererText(), text=self.COLUMN_PERM)
        column.set_sort_column_id(self.COLUMN_VALUE)
        column.set_expand(True)
        treeview.append_column(column)

        # column for force option
        renderer = gtk.CellRendererToggle()
        renderer.connect('toggled', self.toggle_enforced, lstore)
        column = gtk.TreeViewColumn(_('Enforce'), renderer, active=self.COLUMN_FORCE)
        column.set_sort_column_id(self.COLUMN_FORCE)
        column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        column.set_fixed_width(50)
        column.set_expand(True)
        treeview.append_column(column)

        # column for Acl
        column = gtk.TreeViewColumn(_('Acl'), gtk.CellRendererText(), text=self.COLUMN_ACL)
        column.set_sort_column_id(self.COLUMN_ACL)
        column.set_expand(True)
        treeview.append_column(column)

        sw.add(treeview)

        for file in self.permconfig.list_options():
            user_s, group_s, perm_s, force, acl = self.permconfig.get(file)

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
                    self.COLUMN_ACL, acl,
                    )
        vbox.pack_start(sw)
        self.current_options_view[id] = (lstore, self.permconfig)

        # buttons hbox
        hbox = gtk.HBox(homogeneous=True, spacing=10)

        # # up
        # button = gtk.Button(_("Up"))
        # button.connect('clicked', self.move_rule_up, lstore)
        # hbox.pack_start(button, False)

        # # down
        # button = gtk.Button(_("Down"))
        # button.connect('clicked', self.move_rule_up, lstore)
        # hbox.pack_start(button, False)

        # # default
        # button = gtk.Button(_("Reset to default level permissions"))
        # button.connect('clicked', self.reset_permissions, lstore)
        # hbox.pack_start(button, False)

        # add
        button = gtk.Button(_("Add a rule"))
        button.connect('clicked', self.add_permission_check, lstore)
        hbox.pack_start(button, False)

        # delete
        button = gtk.Button(_("Delete"))
        button.connect('clicked', self.remove_permission_check, treeview)
        hbox.pack_start(button, False)

        ## edit
        #button = gtk.Button(_("Edit"))
        #button.connect('clicked', self.move_rule_up, lstore)
        #hbox.pack_start(button, False)

        vbox.pack_start(hbox, False, False)

        return vbox

    def reset_permissions(self, widget, model, level=None):
        """Reset permissions to default specified by level"""
        model.clear()
        self.permconfig.reset()
        if not level:
            defperms = self.perm_defaults[self.base_level]
        else:
            defperms = self.perm_defaults[level]
        for file in defperms.list_options():
            user_s, group_s, perm_s, force_s, acls = defperms.get(file)

            # convert to boolean
            if force_s:
                force_val = True
            else:
                force_val = False

            # building the option
            iter = model.append()
            model.set(iter,
                    self.COLUMN_PATH, file,
                    self.COLUMN_USER, user_s,
                    self.COLUMN_GROUP, group_s,
                    self.COLUMN_PERM, perm_s,
                    self.COLUMN_FORCE, force_val,
                    self.COLUMN_ACL, acls,
                    )
            # changing back force value
            self.permconfig.set(file, (user_s, group_s, perm_s, force_s, acls))

    def remove_exception(self, widget, treeview):
        """Removes an exception from list"""
        model, iter = treeview.get_selection().get_selected()
        if not iter:
            # nothing selected
            return
        pos, = model.get_path(iter)
        self.exceptions.remove(pos)
        model.remove(iter)

        # save exceptions
        self.exceptions.save()

    def remove_permission_check(self, widget, treeview):
        """Removes a permission check for file"""
        model, iter = treeview.get_selection().get_selected()
        if not iter:
            # nothing selected
            return
        file = model.get_value(iter, self.COLUMN_PATH)
        self.permconfig.remove(file)
        model.remove(iter)

    def toggle_enforced(self, cell, path, model):
        '''Toggles a forced permission on an item'''
        iter = model.get_iter((int(path),))
        file = model.get_value(iter, self.COLUMN_PATH)
        fixed = model.get_value(iter, self.COLUMN_FORCE)

        user, group, perm, force, acl = self.permconfig.get(file)

        # do something with the value
        fixed = not fixed

        # set new value
        model.set(iter, self.COLUMN_FORCE, fixed)
        if fixed:
            force = "force"
        else:
            force = ""
        self.permconfig.set(file, (user, group, perm, force, acl))

    def add_permission_check(self, widget, model):
        """Adds a permission check"""
        return self.permission_changed(None, None, None, model)

    def add_exception(self, widget, model):
        """Adds a new exception"""
        return self.exception_changed(None, None, None, model)

    def exception_changed(self, treeview, path, col, model):
        """Processes an exception change. If path is None, adds a new item."""
        if path:
            iter = model.get_iter(path)
            exception_pos, = path
            module = model.get_value(iter, self.COLUMN_EXCEPTION)
            exception = model.get_value(iter, self.COLUMN_EXCEPTION_VALUE)
            title = _("Editing exception")
        else:
            exception_pos = -1
            module = ""
            exception = ""
            title = _("Adding new exception")

        # asks for new parameter value
        dialog = gtk.Dialog(title,
                self.window, 0,
                (gtk.STOCK_OK, gtk.RESPONSE_OK,
                gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))
        label = gtk.Label(_("Editing exception. Please select the correspondent msec check and exception value\n"))
        label.set_line_wrap(True)
        label.set_use_markup(True)
        dialog.vbox.pack_start(label, False, False)

        # module
        hbox = gtk.HBox()
        hbox.pack_start(gtk.Label(_("Check: ")))
        entry_module = gtk.combo_box_new_text()
        pos = 0
        for item in config.CHECKS_WITH_EXCEPTIONS:
            entry_module.append_text(item)
            if item == module:
                entry_module.set_active(pos)
            pos += 1
        if not module:
            entry_module.set_active(0)
        hbox.pack_start(entry_module)
        dialog.vbox.pack_start(hbox, False, False)

        # exception
        hbox = gtk.HBox()
        hbox.pack_start(gtk.Label(_("Exception: ")))
        entry_exception = gtk.Entry()
        entry_exception.set_text(exception)
        hbox.pack_start(entry_exception)
        dialog.vbox.pack_start(hbox, False, False)

        dialog.show_all()
        response = dialog.run()
        if response != gtk.RESPONSE_OK:
            dialog.destroy()
            return

        new_check = entry_module.get_active_text()
        new_exception = entry_exception.get_text()
        dialog.destroy()

        self.exceptions.set(exception_pos, (new_check, new_exception))
        if not path:
            # adding new entry
            iter = model.append()
        model.set(iter, self.COLUMN_EXCEPTION, new_check)
        model.set(iter, self.COLUMN_EXCEPTION_VALUE, new_exception)

        # save exceptions
        self.exceptions.save()

    def permission_changed(self, treeview, path, col, model):
        """Processes a permission change. If path is None, adds a new item."""
        if path:
            iter = model.get_iter(path)
            file = model.get_value(iter, self.COLUMN_PATH)
            user = model.get_value(iter, self.COLUMN_USER)
            group = model.get_value(iter, self.COLUMN_GROUP)
            perm = model.get_value(iter, self.COLUMN_PERM)
            force = model.get_value(iter, self.COLUMN_FORCE)
            acl = model.get_value(iter, self.COLUMN_ACL)
            title = _("Changing permissions for %s") % file
        else:
            file = ""
            user = ""
            group = ""
            perm = ""
            force = ""
            acl = ""
            title = _("Adding new permission check")

        if not force:
            force = ""
        else:
            force = "force"

        # asks for new parameter value
        dialog = gtk.Dialog(title,
                self.window, 0,
                (gtk.STOCK_OK, gtk.RESPONSE_OK,
                gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))
        label = gtk.Label(_("Changing permissions on <b>%s</b>") % (file or _("new file")))
        label.set_line_wrap(True)
        label.set_use_markup(True)
        dialog.vbox.pack_start(label, False, False, padding=5)

        # aligning entries
        sizegroup1 = gtk.SizeGroup(gtk.SIZE_GROUP_HORIZONTAL)
        sizegroup2 = gtk.SizeGroup(gtk.SIZE_GROUP_HORIZONTAL)

        if not path:
            # file
            hbox = gtk.HBox()
            label = gtk.Label(_("File: "))
            hbox.pack_start(label)
            entry_file = gtk.Entry()
            entry_file.set_text(file)
            hbox.pack_start(entry_file)
            sizegroup1.add_widget(label)
            sizegroup2.add_widget(entry_file)
            dialog.vbox.pack_start(hbox, False, False)

        label = gtk.Label(_("Please specify new file owner and permissions, or use 'current' to keep current settings."))
        label.set_line_wrap(True)
        label.set_use_markup(True)
        dialog.vbox.pack_start(label, False, False, padding=5)

        # user
        hbox = gtk.HBox()
        label = gtk.Label(_("User: "))
        hbox.pack_start(label)
        entry_user = gtk.Entry()
        entry_user.set_text(user)
        hbox.pack_start(entry_user)
        sizegroup1.add_widget(label)
        sizegroup2.add_widget(entry_user)
        dialog.vbox.pack_start(hbox, False, False)

        # group
        hbox = gtk.HBox()
        label = gtk.Label(_("Group: "))
        hbox.pack_start(label)
        entry_group = gtk.Entry()
        entry_group.set_text(group)
        hbox.pack_start(entry_group)
        sizegroup1.add_widget(label)
        sizegroup2.add_widget(entry_group)
        dialog.vbox.pack_start(hbox, False, False)

        # perm
        hbox = gtk.HBox()
        label = gtk.Label(_("Permissions: "))
        hbox.pack_start(label)
        entry_perm = gtk.Entry()
        entry_perm.set_text(perm)
        hbox.pack_start(entry_perm)
        sizegroup1.add_widget(label)
        sizegroup2.add_widget(entry_perm)
        dialog.vbox.pack_start(hbox, False, False)

        label = gtk.Label(_("To enforce additional ACL on file, specify them in the following format:\nuser1:acl,user2:acl\nRefer to 'man setfacl' for details."))
        label.set_line_wrap(True)
        label.set_use_markup(True)
        dialog.vbox.pack_start(label, False, False, padding=5)

        # acl
        hbox = gtk.HBox()
        label = gtk.Label(_("ACL: "))
        hbox.pack_start(label)
        entry_acl = gtk.Entry()
        entry_acl.set_text(acl)
        hbox.pack_start(entry_acl)
        sizegroup1.add_widget(label)
        sizegroup2.add_widget(entry_acl)
        dialog.vbox.pack_start(hbox, False, False)

        dialog.show_all()
        response = dialog.run()
        if response != gtk.RESPONSE_OK:
            dialog.destroy()
            return

        if not path:
            newfile = entry_file.get_text()
        else:
            newfile = file
        newuser = entry_user.get_text()
        newgroup = entry_group.get_text()
        newperm = entry_perm.get_text()
        newacl = entry_acl.get_text()
        dialog.destroy()

        # if acl is specified, the permissions will be enforced
        if newacl != "":
            force = "force"

        self.permconfig.set(newfile, (newuser, newgroup, newperm, force, newacl))
        if not path:
            # adding new entry
            iter = model.append()
        model.set(iter, self.COLUMN_PATH, newfile)
        model.set(iter, self.COLUMN_USER, newuser)
        model.set(iter, self.COLUMN_GROUP, newgroup)
        model.set(iter, self.COLUMN_PERM, newperm)
        model.set(iter, self.COLUMN_FORCE, True if force == "force" else False)
        model.set(iter, self.COLUMN_ACL, newacl)

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
        conf_def = self.msec_defaults[self.base_level]

        # Highlighting default options
        def_start=""
        def_end=""
        if self.base_level == config.STANDARD_LEVEL:
            def_start="<b>"
            def_end="</b>"
        elif self.base_level == config.SECURE_LEVEL:
            sec_start="<b>"
            sec_end="</b>"

        val_def = conf_def.get(param)

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
        label = gtk.Label(_("<i>%s</i>\n\n\tCurrent value:\t\t\t<i>%s</i>\n\t%sDefault level value:\t<i>%s</i>%s\n") %
                (descr, value,
                    def_start, val_def, def_end,))
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
            if config.OPTION_DISABLED not in params:
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
            custom = pango.WEIGHT_BOLD
        else:
            custom = pango.WEIGHT_NORMAL

        model.set(iter, self.COLUMN_VALUE, newval)
        model.set(iter, self.COLUMN_DESCR, doc)
        model.set(iter, self.COLUMN_CUSTOM, custom)

    def signal_quit(self, s):
        """Quits via a signal"""
        self.signals.put(s)
        return True

    def quit(self, widget, event=None):
        """Quits the application"""
        num_changes, allchanges, messages = self.check_for_changes(self.msecconfig, self.permconfig)

        if num_changes == 0:
            gtk.main_quit()
            return False
        else:
            ret = self.ok(widget, ask_ignore=True)
            if ret == gtk.RESPONSE_OK or ret == gtk.RESPONSE_REJECT:
                gtk.main_quit()
            else:
                return True


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

    # loading permissions config
    perm_conf = config.PermConfig(log, config=config.PERMCONF)

    # loading exceptions
    exceptions = config.ExceptionConfig(log, config=config.EXCEPTIONSCONF)

    # creating an msec instance
    msec = MSEC(log)
    perms = PERMS(log)

    log.info("Starting gui..")

    gui = MsecGui(log, msec, perms, msec_config, perm_conf, exceptions, embed=PlugWindowID)
    signal.signal(signal.SIGTERM, lambda s, f: gui.signal_quit(s))
    gtk.main()

