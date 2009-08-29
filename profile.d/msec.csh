# shell security options

if ( -r /etc/security/shell ) then
	eval `sed -n 's/^\([^#]*\)=\([^#]*\)/set \1=\2;/p' < /etc/security/shell`
endif

if ( $uid >= 500 ) then
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

if ( ${?ALLOW_CURDIR_IN_PATH} == 'yes' ) then
    if ! { (echo "${PATH}" | /bin/fgrep -q :.) } then
        setenv PATH "${PATH}:."
    endif
endif

# using unhash *after modifying PATH* (see above)
if (! -r /usr/bin) then
  unhash
endif


# translate sh variables from /etc/security/shell to their equivalent in csh
if ( ${?TMOUT} ) then
    set autologout=`expr $TMOUT / 60`
endif

if ( ${?HISTFILESIZE} ) then
    set history=$HISTFILESIZE
endif

if ( ${?SECURE_LEVEL} ) then
    setenv SECURE_LEVEL ${SECURE_LEVEL}
endif

# msec.csh ends here
