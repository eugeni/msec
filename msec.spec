%define version 0.14
%define release 1mdk

Summary: Security Level & Program for the Linux Mandrake distribution
Name: msec
Version: %{version}
Release: %{release}
Source: %{name}-%{version}.tar.bz2
Copyright: GPL
Group: System/Base
BuildRoot: /var/tmp/msec
Requires: /bin/bash setup chkconfig >= 0.9-6

%description
The Mandrake-Security package is designed to provide generic 
secure level to the Mandrake-Linux users...
It will permit you to choose between level 1 to 5 & custom
for a less -> more secured distribution.
This packages includes several program that will be run periodically
in order to test the security of your system and alert you if needed.

%prep
%setup 

%build
make CFLAGS="$RPM_OPT_FLAGS"

%install
make install RPM_BUILD_ROOT=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc AUTHORS COPYING Makefile README 
%doc doc/*txt ChangeLog doc/*ps
/usr/bin/promisc_check
/usr/bin/msec_find
/usr/sbin/msec
/usr/share/msec
/var/log/security.log
/var/log/security
/usr/man/*/*

%config /etc/security/msec

%changelog
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



