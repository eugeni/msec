#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : msec
# File            : msec.csh
# Version         : $Id$
# Author          : Yoann Vandoorselaere
# Created On      : Wed Feb 13 18:35:58 2002
# Purpose         : settings according to security level
#---------------------------------------------------------------

if ( -r /etc/sysconfig/msec ) then
	eval `sed -n 's/^\([^#]*\)=\([^#]*\)/set \1=\2;/p' < /etc/sysconfig/msec`
endif

if ( "`id -u`" >= 500 ) then
    if ( ${?UMASK_USER} ) then
	umask ${UMASK_USER}
    else
	umask 022
    endif
else
    if ( ${?UMASK_ROOT} ) then
	umask ${UMASK_ROOT}
    else
	umask 002
    endif
endif


# (pixel) tcsh doesn't handle directory in the PATH being non-readable
# in security high, /usr/bin is 751, aka non-readable
# using unhash *after modifying PATH* fixes the pb
# So while modifying the PATH, do not rely on the PATH until unhash is done

if ! { (echo "${PATH}" | /bin/grep -q /usr/X11R6/bin) } then
	setenv PATH "${PATH}:/usr/X11R6/bin"
endif

if ! { (echo "${PATH}" | /bin/grep -q /usr/games) } then
	setenv PATH "${PATH}:/usr/games"
endif

if ( ${?SECURE_LEVEL} && ${SECURE_LEVEL} <= 1 ) then
    if ! { (echo "${PATH}" | /bin/fgrep -q :.) } then
	setenv PATH "${PATH}:."
    endif
endif

# using unhash *after modifying PATH* (see above)
if (! -r /usr/bin) then
  unhash
endif


# translate sh variables from /etc/sysconfig/msec to their equivalent in csh
if ( ${?TMOUT} ) then
    set autologout=`expr $TMOUT / 60`
endif

if ( ${?HISTFILESIZE} ) then
    set history=$HISTFILESIZE
endif

setenv SECURE_LEVEL ${SECURE_LEVEL}

# msec.csh ends here
