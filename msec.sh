#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : msec
# File            : msec.sh
# Version         : $Id$
# Author          : Yoann Vandoorselaere
# Created On      : Wed Feb 13 18:35:58 2002
# Purpose         : settings according to security level
#---------------------------------------------------------------

if [ -r /etc/sysconfig/msec ]; then
	. /etc/sysconfig/msec
fi

if [ `id -u` -ge 500 ]; then
    if [ -n "$UMASK_USER" ]; then
	umask $UMASK_USER
    else
	umask 022
    fi
else
    if [ -n "$UMASK_ROOT" ]; then
	umask $UMASK_ROOT
    else
	umask 002
    fi
fi

if ! echo ${PATH} |grep -q /usr/X11R6/bin ; then
    export PATH=$PATH:/usr/X11R6/bin
fi

if ! echo ${PATH} |grep -q /usr/games ; then
    export PATH=$PATH:/usr/games
fi

if [ -n "$SECURE_LEVEL" -a "$SECURE_LEVEL" -le 1 ] && ! echo ${PATH} | fgrep -q :.; then
    export PATH=$PATH:.
fi

export SECURE_LEVEL

[ -n "$TMOUT" ] && typeset -r TMOUT

# msec.sh ends here
