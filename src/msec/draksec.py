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

class MsecGui:
    """Msec GUI"""
    security_options = ["ENABLE_APPARMOR", "MAIL_WARN", "MAIL_USER", "MAIL_EMPTY_CONTENT"]
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

        # main frame
        self.frame = gtk.Frame()
        self.window.add(self.frame)

        # notebook
        self.notebook = gtk.Notebook()
        self.frame.add(self.notebook)

        self.notebook.append_page(self.security_page(), gtk.Label(_("Security level")))
        self.notebook.append_page(self.security_page(), gtk.Label(_("System security")))
        self.notebook.append_page(self.security_page(), gtk.Label(_("Network security")))
        self.notebook.append_page(self.security_page(), gtk.Label(_("Periodic checks")))
        self.notebook.append_page(self.security_page(), gtk.Label(_("Permissions")))

        self.window.show_all()

    def security_page(self):
        """Builds security page"""
        vbox = gtk.VBox(homogeneous=False)

        # security levels

        levels = config.SECURITY_LEVELS

        print levels

        entry = gtk.Label("Hello world!")
        vbox.pack_start(entry, False, False)

        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        vbox.pack_start(sw)

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
        column = gtk.TreeViewColumn(_('Description'), gtk.CellRendererText(), text=self.COLUMN_DESCR)
        column.set_sort_column_id(self.COLUMN_DESCR)
        treeview.append_column(column)

        # column for values
        column = gtk.TreeViewColumn(_('Value'), gtk.CellRendererText(), text=self.COLUMN_VALUE)
        column.set_sort_column_id(self.COLUMN_VALUE)
        treeview.append_column(column)

        sw.add(treeview)

        for option in self.security_options:
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
                print params
                print value
                active = params.index(value)
                entry.set_active(active)

            # building the option
            iter = lstore.append()
            lstore.set(iter,
                    self.COLUMN_OPTION, option,
                    self.COLUMN_DESCR, doc,
                    self.COLUMN_VALUE, value,
                    )

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

