#!/bin/sh

case "$1" in

    start)
    if [ -x /usr/local/bin/kmd ] ; then
    echo "start..."
    /usr/local/bin/kmd $0 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11&
    fi
    ;;

    stop)
    echo "kill... " 
    kill -9 `cat /var/run/kmd.pid`
    rm /var/run/kmd.pid
    ;;

	restart)
	echo "restart...."
	kill -9 `cat /var/run/kmd.pid`
	rm /var/run/kmd.pid
	if [ -x /usr/local/bin/kmd ] ; then
    /usr/local/bin/kmd $0 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11&
    fi
	;;
	
	help)
	if [ -x /usr/local/bin/kmd ] ; then
    /usr/local/bin/kmd $0 -h
    fi
    ;;
	
    *)
    echo "usage: $0 { start | stop | restart | help}" >&2
    exit 1
    ;;

esac
