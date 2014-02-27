#!/bin/bash

source tests/init.sh

errlog=$(mktemp)
trap "rm -f $errlog" EXIT

function check_options(){
	local caplen=$1
	shift;

	if ! out=$(./capfilter --caplen $caplen --frame-num=1 -p1 $traces/t2.cap 2> $errlog | ./capshow 2>> $errlog); then
		cat $errlog
		exit 1
	fi

	if echo $out | grep -q "invalid"; then
		echo $out
		exit 1
	fi

	for x in "$@"; do
		args="-v"
		if [[ ${x::1} != '!' ]]; then
			args=""
		fi
		if ! echo $out | grep -q $args $x; then
			echo $out
			if [[ ${x::1} != '!' ]]; then
				echo "$x isn't present when it should be"
			else
				echo "$x present when it shouldn't be"
			fi
			exit 1
		fi
	done
}

# ensure all expected options is present in original trace
check_options 74 MSS SAC TSS NOP WS

# truncate files and check which options is now present
check_options 73 MSS SAC TSS NOP !WS
check_options 72 MSS SAC TSS NOP !WS
check_options 71 MSS SAC TSS NOP !WS
check_options 70 MSS SAC TSS !NOP !WS
check_options 69 MSS SAC !TSS !NOP !WS
check_options 60 MSS SAC !TSS !NOP !WS
check_options 59 MSS !SAC !TSS !NOP !WS
check_options 58 MSS !SAC !TSS !NOP !WS
check_options 57 !MSS !SAC !TSS !NOP !WS
