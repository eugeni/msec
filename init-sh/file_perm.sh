#!/bin/bash

IFS="
"

echo -n "Setting files permissions : "

cat $1 | while read file owner perm; do
	if [ -a "${file}" ]; then
		if [ ${owner} != "current" ]; then
			chown ${owner} ${file}
		fi
		chmod ${perm} ${file}
	fi
done

echo "done."
		
	
