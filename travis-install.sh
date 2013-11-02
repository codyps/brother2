

sudo apt-get install libsane-dev

## We need a newer version of net-snmp than ubuntu 12.04 has.
## Ubuntu has 5.4.3, we need at v5.5+ release for
## netsnmp_indexed_addr_pair.

PN=net-snmp
PV=5.7.2
P=$PN-$PV

wget http://sourceforge.net/projects/net-snmp/files/$PN/$PV/{$P}.tar.gz &&
tar xf ${P}.tar.gz &&
cd ${P} &&
./configure && make && sudo make install

