Summary: Security Level & Program for the Linux Mandrake distribution
Name: msec
Version: 0.7
Release: 1mdk
Source: msec-0.7.tar.bz2
Copyright: GPL
Group: System Environment/Base
BuildRoot: /var/tmp/msec
Requires: /bin/bash setup chkconfig

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
make rpm_install RPM_BUILD_ROOT=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc AUTHORS COPYING Makefile README doc/*txt ChangeLog
/etc/security/msec
/usr/bin/promisc_check

%changelog
* Thu Dec  9 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
- Many bugfix, i'm trying to get a bugfree release before the freeze
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



