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

if ( { id -u } >= 500 ) then
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

if ! { (echo "${PATH}" | grep -q /usr/X11R6/bin) } then
	setenv PATH "${PATH}:/usr/X11R6/bin"
endif

if ! { (echo "${PATH}" | grep -q /usr/games) } then
	setenv PATH "${PATH}:/usr/games"
endif

if ( ${?SECURE_LEVEL} && ${SECURE_LEVEL} <= 1 ) then
    if ! { (echo "${PATH}" | fgrep -q :.) } then
	setenv PATH "${PATH}:."
    endif
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
