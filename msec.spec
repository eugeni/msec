Summary:	Security Level & Program for the Mandrake Linux distribution
Name:		msec
Version:	0.40
Release:	1mdk
Url:		http://www.linux-mandrake.com/
Source0:	%{name}-%{version}.tar.bz2
Source1:    	msec.logrotate
Source2:    	msec.sh
Source3:    	msec.csh

License:	GPL
Group:		System/Base
BuildRoot:	%_tmppath/%name-%version-%release-root
BuildRequires:	python
Requires:	/bin/bash /bin/touch perl-base diffutils /usr/bin/python /usr/bin/chage gawk
Requires:	setup >= 2.2.0-21mdk
Requires:	chkconfig >= 1.2.24-3mdk
Requires:	coreutils
Requires:	iproute2
PreReq:		rpm-helper >= 0.4
Conflicts:	passwd < 0.67

%description
The Mandrake-Security package is designed to provide generic 
secure level to the Mandrake Linux users...
It will permit you to choose between level 0 to 5
for a less -> more secured distribution.
This packages includes several program that will be run periodically
in order to test the security of your system and alert you if needed.

%prep

%setup -q

%build
make CFLAGS="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
#make install RPM_BUILD_ROOT=$RPM_BUILD_ROOT

install -d $RPM_BUILD_ROOT/etc/security/msec
install -d $RPM_BUILD_ROOT/etc/sysconfig
install -d $RPM_BUILD_ROOT/usr/share/msec
install -d $RPM_BUILD_ROOT/var/lib/msec
install -d $RPM_BUILD_ROOT/usr/sbin $RPM_BUILD_ROOT/usr/bin
install -d $RPM_BUILD_ROOT/var/log/security
install -d $RPM_BUILD_ROOT%{_mandir}/man{3,8}

cp -p init-sh/cleanold.sh share/*.py share/*.pyo share/level.* cron-sh/*.sh $RPM_BUILD_ROOT/usr/share/msec
chmod 644 $RPM_BUILD_ROOT/usr/share/msec/{security,diff}_check.sh
install -m 755 share/msec $RPM_BUILD_ROOT/usr/sbin
install -m 644 conf/server.* $RPM_BUILD_ROOT/etc/security/msec
install -m 644 conf/perm.* $RPM_BUILD_ROOT/usr/share/msec
install -m 755 src/promisc_check/promisc_check src/msec_find/msec_find $RPM_BUILD_ROOT/usr/bin

install -m644 man/C/*8 $RPM_BUILD_ROOT%{_mandir}/man8/
install -m644 share/mseclib.man $RPM_BUILD_ROOT%{_mandir}/man3/mseclib.3

#
# for i in man/??* ; do \
# 	install -d $RPM_BUILD_ROOT%{_mandir}/`basename $i`/man8; \
#     install -m 644 $i/*.8 $RPM_BUILD_ROOT%{_mandir}/`basename $i`/man8; \
#     bzip2 -9f $RPM_BUILD_ROOT%{_mandir}/`basename $i`/man8/*8 ; \
# done;


touch $RPM_BUILD_ROOT/var/log/security.log $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/%{name}

mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/{logrotate.d,profile.d}
install -m 644 %{SOURCE1} $RPM_BUILD_ROOT/etc/logrotate.d/msec
install -m 755 %{SOURCE2} $RPM_BUILD_ROOT/etc/profile.d
install -m 755 %{SOURCE3} $RPM_BUILD_ROOT/etc/profile.d
touch $RPM_BUILD_ROOT/var/log/security.log

%pre
%_pre_groupadd xgrp
%_pre_groupadd ntools
%_pre_groupadd ctools

%post
touch /var/log/security.log

if [ $1 != 1 ]; then
	# manage spelling change
     for i in /etc/security/msec/level.local /etc/security/msec/security.conf /var/lib/msec/security.conf; do
		if [ -f $i ]; then
			perl -pi -e 's/CHECK_WRITEABLE/CHECK_WRITABLE/g;s/CHECK_SUID_GROUP/CHECK_SGID/g' $i
		fi
	done
	for ext in today yesterday diff; do
		if [ -f /var/log/security/writeable.$ext ]; then
			mv -f /var/log/security/writeable.$ext /var/log/security/writable.$ext
		fi
		if [ -f /var/log/security/suid_group.$ext ]; then
			mv -f /var/log/security/suid_group.$ext /var/log/security/sgid.$ext
		fi
	done

	# find secure level
	SL=$SECURE_LEVEL
 	[ ! -r /etc/sysconfig/msec ] || SL=`sed -n 's/SECURE_LEVEL=//p' < /etc/sysconfig/msec` || :

	# upgrade from old style msec or rerun the new msec
	if grep -q "# Mandrake-Security : if you remove this comment" /etc/profile; then
		[ -z "$SL" -a -r /etc/profile.d/msec.sh ] && SL=`sed -n 's/.*SECURE_LEVEL=//p' <  /etc/profile.d/msec.sh` || :
		/usr/share/msec/cleanold.sh || :
 		[ -n "$SL" ] && msec $SL < /dev/null || :
	else
		[ -n "$SL" ] && msec < /dev/null || :
	fi

	# remove the old way of doing the daily cron
	rm -f /etc/cron.d/msec
fi

%postun

if [ $1 = 0 ]; then
	# cleanup crontabs on package removal
	rm -f /etc/cron.d/msec /etc/cron.hourly/msec /etc/cron.daily/msec
fi

%_postun_groupdel xgrp
%_postun_groupdel ntools
%_postun_groupdel ctools

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc AUTHORS COPYING share/README share/CHANGES
%doc ChangeLog doc/*.txt
%_bindir/promisc_check
%_bindir/msec_find
%_sbindir/msec
%_datadir/msec
%_mandir/*/*

%dir /var/log/security
%dir /etc/security/msec
%dir /var/lib/msec

%config(noreplace) /etc/security/msec/*
%config(noreplace) /etc/logrotate.d/msec
%config(noreplace) /etc/profile.d/msec*
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}

%ghost /var/log/security.log

# MAKE THE CHANGES IN CVS: NO PATCH OR SOURCE ALLOWED

%changelog
* Wed Sep  3 2003 Frederic Lepied <flepied@mandrakesoft.com> 0.40-1mdk
- corrected strange permission settings in /var/log (bug #4854)
- allow set_shell_history_size(-1) in level.local (bug #4392)

* Fri Aug 22 2003 Frederic Lepied <flepied@mandrakesoft.com> 0.39-1mdk
- don't write True or False in sysctl.conf (bug #4629)
- don't use apply anymore (Olivier Blin) (bug #4632)
- better documentation for no_password_aging_for (bug #1629)
- support passing arg as a number in set_root_umask, set_user_umask (bug #3640)
- better support for symlinks

* Thu Jul 24 2003 Thierry Vignaud <tvignaud@mandrakesoft.com> 0.38-5mdk
- fix upgrade

* Fri Jun 06 2003 Per Øyvind Karlsen <peroyvind@sintrax.net> 0.38-4mdk
- use double %%'s in changelog

* Fri Mar  7 2003 Frederic Lepied <flepied@mandrakesoft.com> 0.38-3mdk
- report correct message in log (bug #748)

* Sun Feb  2 2003 Thierry Vignaud <tvignaud@mandrakesoft.com> 0.38-2mdk
- move security::help from msec to drakxtools so that it get
  translated

* Mon Jan 20 2003 Thierry Vignaud <tvignaud@mandrakesoft.com> 0.38-1mdk
- generate help for draksec

* Wed Nov 20 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.37-1mdk
- chage is l10n now so use LC_ALL=C before calling it

* Thu Nov 07 2002 Thierry Vignaud <tvignaud@mandrakesoft.com> 0.36-2mdk
- requires s/(sh-|text|file)utils/coreutils/

* Tue Sep 17 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.36-1mdk
- allow_user_list handles Selected in X-*-Greeter section of kdmrc
  when not changing security level.
- allow_reboot handles Root in X-:*-Core section of kdmrc when not
  changing security level.

* Sun Sep  8 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.35-1mdk
- when changing the aging expiry, change the date of last password
  change to today to avoid having accounts already expired.

* Fri Sep  6 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.34.5-2mdk
- fixed bad file name in find.c (David Relson)

* Thu Sep  5 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.34.5-1mdk
- correct allow_user_list with the new place for kdm3

* Thu Sep  5 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.34.4-2mdk
- removed debug message
- corrected credit in the changelog for sgid to David Walser

* Tue Sep  3 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.34.4-1mdk
- more spelling errors fixes thx to David Walser:
	o CHECK_SUID_GROUP => CHECK_SGID

* Fri Aug 30 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.34.3-1mdk
- fixed server symlink creation
- corrected spelling errors thx to David Relson

* Tue Aug 27 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.34.2-1mdk
- fixed /boot as suggested by Guillaume Rousse.

* Tue Aug 27 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.34.1-1mdk
- corrected permissions for /boot/kernel.h*
- corrected syntax error in cron (David Relson)

* Sun Aug 25 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.34-1mdk
- let hosts.{allow,deny} be readable by everyone (to allow all the
  daemons to access them).
- doc/security.txt: documented daily mailing of security checks
- allow_reboot: used section X-:0-Core instead of X-:*-Greeter for
  kdmrc.
- password_history: create /etc/security/opasswd if it doesn't exist.

* Mon Aug 19 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.33-1mdk
- reworked wording of mails

* Fri Aug  9 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.32-1mdk
- do not change permissions/groups/owners of remote files/directories.
- documented the command line options in the man page
- added password_history function (level 5)
- password_length uses system-auth pam file instead of passwd pam file
  (added Conflicts with the old passwd package)
- allow_remote_root_login handles the without_password argument (level 4)

* Wed Jul 31 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.31.1-1mdk
- handle again level.local

* Tue Jul 30 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.31-1mdk
- added level.* for draksec
- add needed groups in %%pre

* Mon Jul 29 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.30.2-1mdk
- fixed allow_root_login

* Sun Jul 28 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.30.1-1mdk
- corrected a bug when the variable doesn't exist before setting it.

* Sat Jul 27 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.30-1mdk
- integrated fixes and requests from David Harris.
- documentation fixes.
- don't lower the security when called without argument (by the hourly cron for example).
- splitted functions that worked at multiple levels:
  * splitted accept_broadcasted_icmp_echo from from accept_icmp_echo.
  * splitted enable_dns_spoofing_protection from enable_ip_spoofing_protection.
  * splitted allow_remote_root_login from allow_root_login.
  * splitted allow_xserver_to_listen from from allow_x_connections.

* Thu Jul  4 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.25-1mdk
- insert the change at the end of the file if no match is found for
  PermitRootLogin and logindefs.
- updated server.4 with MNF needs

* Thu Jun 27 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.24-1mdk
- don't lower access rights when not changing security level

* Thu May 30 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.23-1mdk
- check that only root can run msec
- added more complete error messages

* Wed May 29 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.22-1mdk
- corrected alias files loop (Jérôme UZEL).
- added no_password_aging_for function to mseclib
- server.4, server.5: added shorewall

* Tue Apr 16 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.21-1mdk
- applied patch from John Ehresman to exec the config file in the
  context of mseclib.

* Wed Mar 27 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.20-2mdk
- allow_reboot: only touch the shutdown, poweroff, reboot and halt
  files if they don't exist (reported by Jason Baker).

* Mon Mar 25 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.20-1mdk
- Maximum password aging can be -1 (David Relson)
- allow to pass ignore in function calls in
  /etc/security/msec/level.local to ask msec to do nothing with this
  feature.

* Fri Mar  8 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.19-8mdk
- /var/log/lp-errs must always be 600

* Fri Mar  8 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.19-7mdk
- fix permissions of /var/log/lp-errs for LPRng (Till)
- add yes and no as good values for mseclib
- some doc updates

* Tue Mar  5 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.19-6mdk
- protect scripts from beeing run twice

* Thu Feb 28 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.19-5mdk
- use 127.0.0.1 instead of localhost in hosts.deny
- msec.csh: "unhash" workaround for /usr/bin non-readable (msec 5)
  applied after modifying PATH (eurk!)

* Mon Feb 25 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.19-4mdk
- separate config files and other files in the rpmv check (idea of
  Michael Reinsch)
- don't restart network on sysctl.conf change
- doc/security.txt: resync with code.

* Fri Feb 22 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.19-3mdk
- security_check.sh: check uid and not gid ! (change of meaning of the
  -g option of ls).
- perm.*: do not manage lilo.conf.
- corrected missing security.conf migration from /etc/security/msec/
  to /var/lib/msec.
- don't handle libsafe (let the package do it's job)

* Wed Feb 20 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.19-2mdk
- implement no password in level 0
- X listens to tcp connections in level 3

* Tue Feb 19 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.19-1mdk
- corrected msec.sh and msec.csh problems.
- security.conf is now read from /var/lib/msec and can be overridden
  from /etc/security/msec/security.conf.
- enhanced mseclib man page.
- perm files are now in /usr/share/msec but the custom file stays in
  /etc/security/msec/perm.local.

* Fri Feb 15 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.18-6mdk
- promisc_check.sh: use complete path to the ip command
- correct upgrade when secure level isn't set
- enable_console_log support an arg to specify what to log

* Wed Feb 13 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.18-5mdk
- perm.5: /etc/sendmail.cf 640 for sendmail to work.
- set umask and . in path according to the secure level
- use the ip command to detect promiscuous mode with 2.4 kernel

* Tue Feb  5 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.18-4mdk
- password aging also enable delay to change
- correct gdm.conf modifications

* Mon Feb  4 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.18-3mdk
- in level > 2 X server doesn't listen on tcp connection.
- in level > 3 /etc/hosts.{allow,deny,equiv} readable by daemon group.
- don't report /tmp and /var/tmp as bogus world writable directories.
- security_check.sh: added .ssh/id_dsa .ssh/id_rsa to the list of files to check.
- corrected /etc/issue* moving.
- permissions settings part processes options like the rules part.
- add a man page for the mseclib python library.

* Mon Jan 28 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.18-2mdk
- do the daily cron through /etc/cron.daily to avoid heavy loads
- clean crontabs when removing the package (Dadou)
- 644 for /etc/rc.d/init.d/mandrake_consmap (Andrej)
- fix sendmail perms (Florin)
- symlink /etc/security/msec/server.<level> to
  /etc/security/msec/server for secure levels > 3 (used by chkconfig).
- password aging for the root account too.

* Sat Jan 26 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.18-1mdk
- corrected upgrade from 0.16 and older versions
- allow customization of level through /etc/security/msec/level.local

* Tue Jan 22 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.17-15mdk
- change Requires: from perl to perl-base.
- perm.*: corrected errors reported by Pierre Fortin's script.

* Mon Jan 21 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.17-14mdk
- perm.*: make mandrake_consmap 755 because it needs to be readable by everyone

* Sun Jan 20 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.17-13mdk
- diff_check.sh: mail even if the report is empty to show that the
  check was fine.
- the string "current" signifies to not change the permissions.
- perm.*: corrected mandrake_consmap permissions and ping path/permissions.
- /home is 711 in level 3.

* Thu Jan 17 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.17-12mdk
- report cron log to tty only on root ttys.
- better layout of rpm modified files report.

* Wed Jan  9 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.17-11mdk
- added hostname to the subject of the mail report for better
  information when you receive multiple reports
- really added rpm-va check to the mail report
- fix handling of the owner/group of subdirectories of /var/log in a
  generic manner.
- oops put back periodic filesystems check

* Mon Jan  7 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.17-10mdk
- corrected first invocation.

* Sun Jan  6 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.17-9mdk
- oops: corrected broken security.sh script

* Fri Jan  4 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.17-8mdk
- TMOUT is now a read only variable
- allow/forbid reboot/shutdown by [kg]dm

* Thu Jan  3 2002 Frederic Lepied <flepied@mandrakesoft.com> 0.17-7mdk
- rpm -qa check now logs install time too
- corrected the way we install the byte compiled python files to avoid
  false rpm -V warnings.
- added a CHANGES file to document what has changed between 0.16 and 0.17
- send complete rpm -va check to the main mail
- perm.*: added handling of /etc/rc.d/init.d/*
- changed the way /etc/security/msec/perm.local is used to avoid flip/flap changes
- reworked output in diff rpm check to be more coherent

* Sat Dec 29 2001 Frederic Lepied <flepied@mandrakesoft.com> 0.17-6mdk
- added doc of the features of the msec utility
- corrected enable_at_crontab

- password_aging only takes care of /etc/shadow users and avoid the
  users with a deactivated password.

* Fri Dec 28 2001 Frederic Lepied <flepied@mandrakesoft.com> 0.17-5mdk
- added rpm database checks
- added check of accounts with the 0 id that aren't root.

* Thu Dec 27 2001 Frederic Lepied <flepied@mandrakesoft.com> 0.17-4mdk
- disable root login in xdm,kdm,gdm the same way as in Bastille (via pam).
- manage password aging.
- manage crontab and at authorization.

* Thu Dec 27 2001 Frederic Lepied <flepied@mandrakesoft.com> 0.17-3mdk
- avoid changing permissions twice in the same run (to avoid unneeded logging).
- when run in non-interactive mode, the output goes to the auth facility.

* Fri Dec 14 2001 Frederic Lepied <flepied@mandrakesoft.com> 0.17-2mdk
- fixed sysctl.conf handling

* Thu Dec 13 2001 Frederic Lepied <flepied@mandrakesoft.com> 0.17-1mdk
- rewritten file modifications part in python

* Wed Dec 05 2001 Florin <florin@mandrakesoft.com> 0.16-4mdk
- oups, use %%{_sysconfdir}/sysconfig/%%{name} instead of %%{_sysconfdir}/%%{name}
- fix the msec.csh file (thks again to Konrad Bernlohr)

* Thu Nov 29 2001 Florin <florin@mandrakesoft.com> 0.16-3mdk
- remove the redundance related to umask and /etc/bashrc
- add the %%{_sysconfdir}/%%{name} file
- allow the ssh connexions in the snf security level
- sort of update the ChangeLog
- updated msec.csh to read %%{_sysconfdir}/%%{name} with sed black magic (Fred)
- added console timeout support (Fred)
- added command history disabling (Fred)
- added sysctl settings (Fred)
- changed perms of rpm progs in high security levels to prevent
  exposing what is installed (and access to /usr/share/doc too). (Fred)
- spoof protection for name resoluton (Fred)
- remove /etc/issue and /etc/issue.net according to level (Fred)

* Thu Nov 08 2001 Florin <florin@mandrakesoft.com> 0.16-2mdk
- oups forgot to create the needed links in post:
- create the /etc/security/msec/server
- the /usr/share/msec/current-level.sh and
- /etc/security/msec/current.perm files

* Thu Nov 08 2001 Florin <florin@mandrakesoft.com> 0.16-1mdk
- 0.16
- add requires on chkconfig >= 1.2.24-3mdk
- add the new link /etc/security/msec/server 
- fix permissions for monitoring in snf level
- deny root ssh access in snf level

* Wed Nov 07 2001 Florin <florin@mandrakesoft.com> 0.15-31mdk
- bring back the squid.squid permissions
- add some permissions for the naat servers
- add some authorized servers for naat-snf, cooker version
- add the snf security level
- make rpmlint happy with the distribution name
- add Url tag

* Wed Oct 03 2001 Florin <florin@mandrakesoft.com> 0.15-30mdk
- more things from /etc/profile to /etc/profile.d/msec.{sh|csh}
- update the doc path in the man pages
- add the msec*sh sources
- libsafe.so.2 in levels 4/5

* Thu Sep 20 2001 Florin <florin@mandrakesoft.com> 0.15-29mdk
- fix the /etc/profile.d/msec.{sh|csh} entries
- get rid of /etc/profile entries

* Thu Sep 20 2001 Florin <florin@mandrakesoft.com> 0.15-28mdk
- authorize the usb service in the 4/5 levels of security

* Wed Sep 19 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.15-27mdk

- Require /bin/touch.

* Wed Sep 19 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.15-26mdk

- Output in /etc/profile.d/msec.sh as only .sh extenssion files are read.
- Keep the output of the SECURE_LEVEL in /etc/profile and /etc/zprofile.

* Wed Sep 19 2001 florin <florin@mandrakesoft.com> 0.15-25mdk
- RootSshLogin in levels 4/5
- squidGuard entries

* Wed Sep 19 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.15-24mdk
- Fix manpages installation.
- Fix logrotate config installation.
- Fix issue with SECURE_LEVEL not updated if not exiting the console
  (this is a workaround for problems in several terminal programs).

* Mon Sep 17 2001 Daouda LO <daouda@mandrakesoft.com> 0.15-23mdk
- Resync with cvs (yoann sucks)
- real fix for kdm is in lib.sh (msec sux)

* Fri Sep 14 2001 Florin <florin@mandrakesoft.com> 0.15-21mdk
- conf/perm.*: /var/log/squid must be owned by nobody.nobody.
- add the %%post section for the ghost file

* Mon Sep 03 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.15-20mdk
- logrotate entry in %%install, not %%post

* Mon Sep 03 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.15-19mdk
- add logrotate entry

* Thu Aug  9 2001 Frederic Lepied <flepied@mandrakesoft.com> 0.15-18mdk
- added vc/[1-6] to securetty (devfs)
- merged back in cvs

* Mon Jul  9 2001 Frederic Crozat <fcrozat@mandrakesoft.com> 0.15-17mdk
- Patch 0: add suppport for usermode halt/reboot

* Thu May 10 2001 Stew Benedict <sbendict@mandrakesoft.com> 0.15-16mdk
- Check for drakx install environment before running "telinit u" - PPC hang

* Tue May 01 2001 David BAUDENS <baudens@mandrakesoft.com> 0.15-15mdk
- Use %%_tmppath for BuildRoot

* Tue Oct 10 2000 Yoann Vandoorselaere  <yoann@mandrakesoft.com> 0.15-14mdk
- call telinit after modifying inittab

* Tue Oct 10 2000 Yoann Vandoorselaere  <yoann@mandrakesoft.com> 0.15-13mdk
- Applied Warly patch to fix user list problem under kdm.
- User list option for gdm too.

* Tue Oct 10 2000 Warly <warly@mandrakesoft.com> 0.15-12mdk
- change the UserList method to not append at the end of kdmrc (in the wrong section)

* Mon Oct  9 2000 Pixel <pixel@mandrakesoft.com> 0.15-11mdk
- remove the fix for #760 (it needs real fixing!)

* Mon Oct 09 2000 Yoann Vandoorselaere  <yoann@mandrakesoft.com> 0.15-10mdk
- conf/server.[45]: add pcmcia

* Mon Oct 09 2000 Yoann Vandoorselaere  <yoann@mandrakesoft.com> 0.15-9mdk
- fix for #760 (kdm should not display the list of users for high security
  levels)

* Mon Oct 09 2000 Yoann Vandoorselaere  <yoann@mandrakesoft.com> 0.15-8mdk
- fix a typo in conf/perm.0

* Fri Oct 04 2000 Yoann Vandoorselaere  <yoann@mandrakesoft.com> 0.15-7mdk
- Autologin allowed in level 0, 1, 2.... I'm against this... but...

* Fri Oct 04 2000 Yoann Vandoorselaere  <yoann@mandrakesoft.com> 0.15-6mdk
- fix some entry in perm.*
- Autologin will only work in level 0

* Tue Oct 03 2000 Yoann Vandoorselaere  <yoann@mandrakesoft.com> 0.15-5mdk
    * init-sh/*.sh : instead of modifying Xsession,
    create the /etc/X11/xinit.d/msec file which can contain eventual
    rules appended by msec.

* Mon Oct 02 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.15-4mdk
- some fix.

* Mon Oct 02 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.15-3mdk
- init-sh/*.sh : modify /etc/X11/Xsession, not /etc/X11/xdm/Xsession
                 nor /etc/X11/xinit/xinitrc anymore, as they all load
                 /etc/X11/Xsession.

* Fri Sep 01 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.15-2mdk
- install manually
- use %%{_mandir} macros
- use %%config(noreplace) for /etc/msec and for logfile

* Tue Jul 18 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.15-1mdk
- cron-sh/security_check.sh : use -L in ls, 
  to dereference symbolic link  Chris Green <cmg@dok.org>
- conf/perm.*: /var/log/squid must be owned by squid.squid.
- cron-sh/security.sh: 
- init-sh/custom.sh: added patch from AG <darkimage@bigfoot.com>,
  if no user to mail security report to is availlable, send to root.
	
* Wed May 17 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.14-6mdk
- Handle new libsafe path.

* Wed May 17 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.14-5mdk
- corrected a wrong path.

* Wed May 03 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.14-4mdk
- LoaderUpdate() make a difference between an empty
  variable, and a non existing one.

* Fri Apr 25 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.14-3mdk
- Fix a bug with comment removed pointed out by Konrad Bernloehr.

* Mon Apr 24 2000 Pixel <pixel@mandrakesoft.com> 0.14-2mdk
- conf/perm.[0-4]: fix ugly disgusting fucking bloody buggy bug!
(remove bloody /usr/{bin,sbin}/* entries)

* Wed Apr 19 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.14-1mdk
- Bug fix.
- Support Grub as well as Lilo.

* Tue Apr 18 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.12-5mdk
- cron job at 4:00am, msec_find fix.

* Mon Apr 17 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.12-4mdk
- perm.5 : -e s'/ntool/ntools/' -e s'/ctool/ctools/'
- updated documentation.
- file_perm.sh : bug fix + output to /dev/null.
- include /var/tmp in perm.[0-5].
- Patch to msec_find from Thomas Poindessous.

* Fri Apr 14 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.12-1mdk
- Modify zprofile.
- use libsafe-1.3

* Thu Mar 16 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- security.sh : export *_TODAY variable to be used by msec_find.
- find.c      : removed a debuging printf.

* Tue Mar 09 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.10-1mdk
- custom.sh : added a patch from Havard Bell.
- custom.sh : check if libsafe is installed before asking if the user want to use it.
- Heavily modified msec_find.
- Added msec_find utility, written by Thierry Vignaud which will avoid us to
  find / 5 times :)
- Added support for libsafe stack overflow protection in level 4 / 5 /
  custom
- trap the sigint signal.
- use %%config for config file ( thanks to Frederic Lepied ).
- use /etc/security/msec for config file only.
- Renamed init.sh to msec, and install it in /usr/sbin.
- The other shell scripts are located in /usr/share/msec
- Included patch from Stefan Siegel.

* Tue Jan 18 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- custom.sh : fix a nasty typo.

* Tue Jan 06 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- security.sh : find are niced to (+19)
- Camille updated the documentation.
- Removed the "spawn a shell on boot" feature of level0 cause of a tty problem.
- shutdown.allow is 600 in level 4/5; 644 else.
- updated doc/security.txt
- updated init-sh/custom.sh
- level 0-3 -> ctrl-alt-del allowed for any local user.
- level 4-5 -> ctrl-alt-del allowed for root.

* Wed Dec 29 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Removing grpuser manpage, because : 
  1 - grpuser is not to be used by any user, ( and should not have a manpage so ).
  2 - manpage is obsolete

* Tue Dec 28 1999 Chmouel Boudjnah <chmouel@mandrakesoft.com>
- add man-pages from camille.

* Fri Dec 24 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Use the mail user variable.
- level[35]: also do a mail report.
- moved Syslog(), Ttylog(), Maillog() to security.sh
- security_check.sh & diff_check.sh now sourced from security.sh
- Typo / bug fix
- init-sh/perm[15]: files should be constant in their content.
  all entry should be in each perm file

* Tue Dec 21 1999 Pixel <pixel@mandrakesoft.com>
- init-sh/lib.sh (LiloUpdate): replace the -z ${LILO_PASSWORD} by
${LILO_PASSWORD+set} != set 
- init-sh/lib.sh (LiloUpdate): replace the call to AddRules to
AddBegRules (password= must in the beginning of lilo.conf)
- init-sh/lib.sh (AddBegRules): 1 \n instead of 2

* Mon Dec 20 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Use grpconv after modifying /etc/group.
- Add a message for level 5 saying that user who want X access
  should be in the xgrp group.

* Mon Dec 20 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- fixed a typo / variable pb.

* Mon Dec 20 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- init-sh/perm.[05]: Oops, /var/spool/mail is 771 not 755.
- init-sh/lib.sh: removed the failsafe for not a tty stdin (not efficient)
- init-sh/lib.sh: rewrote the perl script (now a one-liner :)
- Big cleanup.
- All work properly now.
- msec.spec: modify to take into account the Makefile modifying the .spec
- Makefile (VERSION): make it the same as the .spec

* Sat Dec 18 1999 Pixel  <pixel@mandrakesoft.com>
- init-sh/lib.sh: added failsafe for not a tty stdin

* Sat Dec 18 1999 Pixel <pixel@mandrakesoft.com>
- no interactive questions if not a tty

* Thu Dec 16 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Don't use msec parsing routine to hack inittab

* Thu Dec 16 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Fixed the last AddBegRules() problem.
- Indentation problem should be fixed.
- All debug finished, changing secure.tmp to a mktemp
  allocated tmpfile for symlink security.
- DRAKX_USER variable no longer needed.
- grpuser.sh take only one opt ( --refresh ),
  take group name from /etc/security/msec/group.conf
  and add user from /etc/security/msec/user.conf if secure level > 2
- level0.sh fixed inittab entry
- fix a typo
- As requested, direct shell access for level 0
- Fixed a little problem with the DRAKX_USERS variable
- removed chattr +a because of the problem it can cause to
  other system automated system task.

* Mon Dec 13 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- diff_check.sh : fix a typo.

* Thu Dec 10 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- custom.sh : Fix a typo & forgot to export path & secure level

* Thu Dec  9 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- More bugfix.
- Many bugfix, always trying to get a bugfree release :).
- Renamed some variable, added consistencie.
- security_cjheck.sh: print header at begining of the log.
- diff_check.sh: typo.

* Wed Dec  8 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- security_check.sh: remove /tmp stuff.
- security_check.sh: typo
- level[1-3].sh: Changed crontab call to file_check.sh
  from every hour to every midnight ( bug reported by axalon ).
- diff_check.sh: clean up.
- moved file_check.sh to diff_check.sh and changed
  what is related to cron call in level[15].sh
- Added missing configurations question in level custom.
- bug fix.

* Wed Dec  8 1999 Chmouel Boudjnah <chmouel@mandrakesoft.com>
- Various (Makefile|specfiles) clean-up.
- insert doc.

* Mon Dec  6 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Released 0.5
- Divided security check into 2 files :
  security_check.sh & file_check.sh, 
  the first do normal security check, the other watch at anormal change
  on the system...
- Bug fix again & again
- Updated perm files & fix a security problem ( thanks Axalon ).

* Wed Dec  1 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- DrakX compatibility.

* Wed Dec  1 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Add & delete of userlist from audio group ( level 1 & 2 ).
- Minor fix

* Wed Dec  1 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- We now preserve config file implementation.
- Minor fix to lib.sh
- export profile variable...

* Mon Nov 30 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Many cron security check added.
- Print more infos.

* Mon Nov 29 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Released 0.4 :
- Now have a custom mode, just answer the question.
- Msec print what it does.
- Bug fix in LiloUpdate().

* Mon Nov 29 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Fixed a few bugs in msec.

* Fri Nov 26 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- grpuser was not installed.

* Fri Nov 26 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Fix a bug in level3.sh
- level[12].sh Removed some unused code

* Thu Nov 25 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Call chkconfig with the new --msec option.

* Thu Nov 25 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Cleaned up tree.

* Thu Nov 25 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Removed touched file /-i

* Thu Nov 25 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Create rc.firewall to avoid error,
- Call grpuser with the good path,
- Call groupadd before usermod.

* Tue Nov 23 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- New release (0.3) :
  Now each security level has it's own set of permissions.
  Add "." at the end of $PATH for level 1.
  Corrected some grave bug, it should work properly now.

* Thu Nov 18 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- New release (0.2) :
  Fixed the path for promisc_check.sh :
  now /etc/security/msec/cron-sh/promisc_check.sh
  In level 1 & 2, user is now automagically added to the audio group. 

* Tue Nov 16 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- First packaging attempt :-).



