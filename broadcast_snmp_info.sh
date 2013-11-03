#! /bin/sh

if [ $# -ne 1 ]; then
	echo "usage: $0 <scanner ip or hostname>"
	exit 1
fi

snmpget -v1 -c public "$1" 1.3.6.1.4.1.2435.2.3.9.1.1.7.0 1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.2.2.1.6.1 1.3.6.1.4.1.2435.2.4.3.1240.1.3.0 1.3.6.1.2.1.1.1.0

# snmpwalk -v1 -c public "$1"
