# shell security options

if [ -r /etc/security/shell ]; then
	. /etc/security/shell
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
	umask 022
    fi
fi

if [ -n "$SECURE_LEVEL" ]; then
    if [ "$SECURE_LEVEL" -le 1 ] && ! echo ${PATH} | fgrep -q :.; then
	export PATH=$PATH:.
    fi
fi

export SECURE_LEVEL

[ -n "$TMOUT" ] && type typeset > /dev/null 2>&1 && typeset -r TMOUT

# msec.sh ends here
