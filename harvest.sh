#!/bin/bash

classa=$1
classb=$2


file="$classa.$classb.txt"

for classc in {0..255}
do
    DATE_WITH_TIME=`date "+%Y-%m-%d-%H:%M:%S"`
    ip="$classa.$classb.$classc.0"
    echo $DATE_WITH_TIME - $ip
    for classd in {0..255}
    do
    ip="$classa.$classb.$classc.$classd"

    if [[ $classa -eq 10 || $classa -eq 172 && $classb -eq 16 || $classa -eq 192 && $classb -eq 168 ]] ; then
        # skip RFC 1918
        # 10.0.0.0 – 10.255.255.255  (10/8 prefix)
        # 172.16.0.0 – 172.31.255.255  (172.16/12 prefix)
        # 192.168.0.0 – 192.168.255.255 (192.168/16 prefix)
        :
    elif [[ $classa -eq 127 ]] ; then
        # skip local
        # 127.0.0.0–127.255.255.255 
        # 240.0.0.0–255.255.255.254 
        :
    elif [[ $classa -ge 224 ]] ; then
        # skip reserved
        # 224.0.0.0–239.255.255.255 
        # 240.0.0.0–255.255.255.254 
        :
    else
        ping -c 1 -q -W 1 $ip 2>/dev/null 1>/dev/null
        rc=$?

        if [[ $rc -eq 0 ]] ; then
            # good ping
            echo $ip,true >> $file
        else
            # bad ping
            echo $ip,false >> $file
        fi
    fi
    done
done
