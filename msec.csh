if ( -r /etc/sysconfig/msec ) then
	eval `sed -n 's/^\([^#]*\)=\([^#]*\)/set \1=\2;/p' < /etc/sysconfig/msec`
endif

if ! { (echo "${PATH}" | grep -q /usr/X11R6/bin) } then
	setenv PATH "${PATH}:/usr/X11R6/bin"
endif

if ! { (echo "${PATH}" | grep -q /usr/games) } then
	setenv PATH "${PATH}:/usr/games"
endif

# translate sh variables from /etc/sysconfig/msec to their equivalent in csh
if ( -n "$TMOUT" ) then
	set autologout=`expr $TMOUT / 60`
endif

if ( -n "$HISTFILESIZE" ) then
	set history=$HISTFILESIZE
endif

setenv SECURE_LEVEL ${SECURE_LEVEL}
