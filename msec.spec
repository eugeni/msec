Summary:	Security Level & Program for the Linux Mandrake distribution
Name:		msec
Version:	0.15
Release:	30mdk

Source:		%{name}-%{version}.tar.bz2
Source2:    	msec.logrotate

License:	GPL
Group:		System/Base
BuildRoot:	%_tmppath/%name-%version-%release-root
Requires:	/bin/bash /bin/touch setup chkconfig >= 0.9-6

%description
The Mandrake-Security package is designed to provide generic 
secure level to the Mandrake-Linux users...
It will permit you to choose between level 1 to 5 & custom
for a less -> more secured distribution.
This packages includes several program that will be run periodically
in order to test the security of your system and alert you if needed.

%prep

%setup -q

%build
make CFLAGS="$RPM_OPT_FLAGS"

%install
#make install RPM_BUILD_ROOT=$RPM_BUILD_ROOT

install -d $RPM_BUILD_ROOT/etc/security/msec
install -d $RPM_BUILD_ROOT/usr/share/msec
install -d $RPM_BUILD_ROOT/usr/sbin $RPM_BUILD_ROOT/usr/bin
install -d $RPM_BUILD_ROOT/var/log/security
install -d $RPM_BUILD_ROOT%{_mandir}/man8

install -m 755 init-sh/*.sh cron-sh/*.sh $RPM_BUILD_ROOT/usr/share/msec
install -m 755 init-sh/msec $RPM_BUILD_ROOT/usr/sbin
install -m 644 conf/perm.* conf/server.* $RPM_BUILD_ROOT/etc/security/msec
install -m 755 src/promisc_check/promisc_check src/msec_find/msec_find $RPM_BUILD_ROOT/usr/bin

install -m644 man/C/*8 $RPM_BUILD_ROOT%{_mandir}/man8/
bzip2 -9f $RPM_BUILD_ROOT%{_mandir}/man8/*8

for i in man/??* ; do \
	install -d $RPM_BUILD_ROOT%{_mandir}/`basename $i`/man8; \
    install -m 644 $i/*.8 $RPM_BUILD_ROOT%{_mandir}/`basename $i`/man8; \
    bzip2 -9f $RPM_BUILD_ROOT%{_mandir}/`basename $i`/man8/*8 ; \
done;


touch $RPM_BUILD_ROOT/etc/security/msec/security.conf $RPM_BUILD_ROOT/var/log/security.log

mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d
install -m 644 %{SOURCE2} $RPM_BUILD_ROOT/etc/logrotate.d/msec
touch $RPM_BUILD_ROOT/var/log/security.log

%post 
touch /var/log/security.log

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc AUTHORS COPYING Makefile README 
%doc doc/*txt ChangeLog doc/*ps
%_bindir/promisc_check
%_bindir/msec_find
%_sbindir/msec
%_datadir/msec
%_mandir/*/*

%config(noreplace) /var/log/security
%config(noreplace) /etc/security/msec
%config(noreplace) /etc/logrotate.d/msec

%ghost /var/log/security.log


# MAKE THE CHANGES IN CVS: NO PATCH OR SOURCE ALLOWED
%changelog
* Thu Sep 27 2001 Florin <florin@mandrakesoft.com> 0.15-30mdk
- more things from /etc/profile to /etc/profile.d/msec.{sh|csh}
- remove the "or print" in the perl line in CleanRules 
- update the doc path in the man pages

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
- add the %post section for the ghost file

* Mon Sep 03 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.15-20mdk
- logrotate entry in %install, not %post

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
- use %{_mandir} macros
- use %config(noreplace) for /etc/msec and for logfile

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
- use %config for config file ( thanks to Frederic Lepied ).
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



