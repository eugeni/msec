#!/bin/bash

IFS="
"

for line in `cat /$1`; do
	file=`echo ${line} | awk '{print $1}'`
	owner=`echo ${line} | awk '{print $2}'`
	perm=`echo ${line} | awk '{print $3}'` 
	
	if [ -a "${file}" ]; then
		if [ ${owner} != "current" ]; then
			chown ${owner} ${file}
		fi
		chmod ${perm} ${file}
	fi
done
		
	
