#!/bin/bash

IFACE=$1;
cd $2
shift 2
STREAM=$*;

function handle_signal {
    echo `date +'%F %T'` "stopping dumper" >> /var/log/dumper.log
    exit 0
}

ulimit -c unlimited
trap handle_signal SIGINT SIGTERM

while true; do
    echo `date +'%F %T'` "Starting capdump on ${IFACE} for ${STREAM}." >> /var/log/dumper.log
    /usr/local/bin/capdump \
		--marker 4000 --marker-format "%f-%x-%r.%e" --marker-mode a \
		--progress -o trace.cap --iface ${IFACE} ${STREAM} \
		2>> /var/log/dumper.log
    RET=$?
    echo `date +'%F %T'` "capdump exited with code $RET." >> /var/log/dumper.log
    if [[ -e core ]]; then
				corefile=core-`date +'%F-%T'`
				mv core $corefile
				echo `date +'%F %T'` "a corefile was created at $corefile" >> /var/log/dumper.log
    fi
done
