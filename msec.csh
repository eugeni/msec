. /etc/sysconfig/msec

if ! { (echo "${PATH}" | grep -q /usr/X11R6/bin) } then
	setenv PATH "${PATH}:/usr/X11R6/bin"
endif

if ! { (echo "${PATH}" | grep -q /usr/games) } then
	setenv PATH "${PATH}:/usr/games"
endif
