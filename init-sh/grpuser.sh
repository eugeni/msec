#!/bin/sh

#
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
# Thanks to Francis Galiegue.
#

file="group"
group_line=""
new_group_line=""
group_name=$2
user_name=$3

Usage() {
	echo "Usage :"
	echo "  --clean      ---> Remove all group change."
	echo "  --refresh    ---> Read group name in /etc/security/msec/group.conf"
	echo "                    and add each user in /etc/security/msec/user.conf"  
	echo "                    in these groups ( if security level is <= 2 )" 
}

ModifyFile() {
    tmpfile=`mktemp /tmp/grpuser.XXXXXX`
    cp /etc/${file} ${tmpfile}

    head -$((group_line_number - 1)) ${tmpfile} > /etc/${file}
    echo "${new_group_line}" >> /etc/${file}
    tail +$((group_line_number + 1)) ${tmpfile} >> /etc/${file}

    rm -f ${tmpfile}
}

RemoveUserFromGroup() {
    new_group_line=${group}`echo ${group_users} | 
	sed -e s/,${user_name}$//g -e s/${user_name},//g -e s/${user_name}$//g`
}

AppendUserToGroup() {
    if [[ -z ${group_users} ]]; then
	new_group_line=${group_line}${user_name}
    else
	new_group_line=${group_line}",${user_name}"
    fi
}

IsUserAlreadyInGroup() {
    if echo ${group_users} | grep -qw "${user_name}"; then
	return 0
    fi
    
    return 1
}

IsGroupExisting() {
    group_line=""
    group_line_number=""
    
    # We get some group infos as well, will be used later
    tmp=`grep -n "^${group_name}:" /etc/${file} | tr -d " "`
    
    group_line_number=`echo ${tmp} | awk -F: '{print $1}'`
    group=`echo ${tmp} | awk -F: '{print $2":"$3":"$4":"}'`
    group_users=`echo ${tmp} | awk -F: '{print $5}'`
    group_line=`echo ${tmp} | awk -F: '{print $2":"$3":"$4":"$5}'`

    [ -z "${tmp}" ] && return 1
    
    return 0
}

IsUserExisting() {
	grep -qn "^${user_name}:" /etc/passwd
	if [[ $? == 0 ]]; then
		return 0;
	fi

	return 1;
}

RefreshAdd() {
    if [[ ${SECURE_LEVEL} > 2 ]]; then
	echo "You are in a secure level > 2, in this level you need to add group user by yourself."
	echo "Use the command : usermod -G group_name user_name"
	exit 1;
    fi

    cat /etc/security/msec/group.conf | grep -v "^$" | while read group_name; do
	IsGroupExisting;
	if [[ $? != 0 ]]; then
	    echo "Group \"${group_name}\" doesn't exist. skiping it."
	else
	    cat /etc/security/msec/user.conf | grep -v "^$" | while read user_name; do
		IsUserExisting; 
		if [[ $? != 0 ]]; then
		    # user doesn't exist
		    echo "Can't add user \"${user_name}\" to group \"${group_name}\" user doesn't exist. skiping."
		    IsUserAlreadyInGroup;
		    if [[ $? == 0 ]]; then
			#User doesn't exist but is in a group... delete user from this group.
			IsGroupExisting;
			RemoveUserFromGroup;
			ModifyFile;
		    fi
		else
		    echo "Adding user \"${user_name}\" to group \"${group_name}\"."
		    IsGroupExisting;
		    AppendUserToGroup;
		    ModifyFile;
		fi
	    done
	fi
    done
}

RefreshDel() {
    cat /etc/security/msec/group.conf | grep -v "^$" | while read group_name; do
	IsGroupExisting;
	if [[ $? != 0 ]]; then
	    echo "Group \"${group_name}\" doesn't exist. skiping it."
        else
	    cat /etc/security/msec/user.conf | grep -v "^$" | while read user_name; do
		IsGroupExisting; # We need some variable at each turn.
		IsUserAlreadyInGroup;
		if [[ $? == 0 ]]; then
		    echo "Removing \"${user_name}\" from group \"${group_name}\"."
		    RemoveUserFromGroup;
		    ModifyFile;
		fi
	    done
	fi
    done
}



Perm() {
	if [[ ${UID} != 0 ]]; then
	    echo "You need root access to use this tool."
	    echo "And this script shouldn't be used by users."
	    exit 1
	fi

	if [[ ! -w /etc/${file} ]]; then
	    echo "You're not allowed to write to /etc/group..." 
	    exit 1
	fi

	if [[ ! -f /etc/security/msec/group.conf ]]; then
	    echo "/etc/security/msec/group.conf doesn't exist..."
	    exit 1
	fi
       
	if [[ ! -f /etc/security/msec/user.conf ]]; then
	    echo "/etc/security/msec/user.conf doesn't exist..."
	    exit 1
	fi
}

if [[ $# == 1 ]]; then
	case $1 in
		"--refresh")
			Perm;
			RefreshAdd;
			exit 0
			;;
		"--clean")
			Perm;
			RefreshDel;
			exit 0
			;;
		esac
			Usage;
			exit 0
else
    Usage;
fi
















