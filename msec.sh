if [ -r /etc/sysconfig/msec ]; then
	. /etc/sysconfig/msec
fi

if ! echo ${PATH} |grep -q /usr/X11R6/bin ; then
	export PATH=$PATH:/usr/X11R6/bin
fi

if ! echo ${PATH} |grep -q /usr/games ; then
	export PATH=$PATH:/usr/games
fi

export SECURE_LEVEL=${SECURE_LEVEL}

[ -n "$TMOUT" ] && typeset -r TMOUT
