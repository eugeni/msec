#!/bin/bash

if [[ ! -s $1 ]]; then
	echo "I need a msec permfile in argument".
	exit 1
fi

echo -n "Setting files permissions : "

grep -v "^#" $1 | while read file owner perm; do
	if [[ -a ${file} ]]; then
		if [[ ${owner} != current ]]; then
			chown ${owner} ${file}
		fi
		chmod ${perm} ${file}
	fi
done

echo "done."
		
