. /etc/sysconfig/msec

if ! echo ${PATH} |grep -q /usr/X11R6/bin ; then
	export PATH=$PATH:/usr/X11R6/bin
fi

if ! echo ${PATH} |grep -q /usr/games ; then
	export PATH=$PATH:/usr/games
fi
