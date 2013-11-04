
## clang 3.2 (used by travis-ci) is broken, need to find a ppa with 3.3
# clang version 3.2 (tags/RELEASE_32/final)
#/usr/bin/ld: /usr/local/clang/bin/../lib/LLVMgold.so: error loading plugin
#/usr/bin/ld: /usr/local/clang/bin/../lib/LLVMgold.so: error in plugin cleanup (ignored)
#clang: error: linker command failed with exit code 1 (use -v to see invocation)
sudo add-apt-repository ppa:xorg-edgers/ppa

sudo apt-get update
sudo apt-get install libsane-dev libev-dev clang-3.3

## We need a newer version of net-snmp than ubuntu 12.04 has.
## Ubuntu has 5.4.3, we need at v5.5+ release for
## netsnmp_indexed_addr_pair.

PN=net-snmp
PV=5.7.2
P=$PN-$PV

mkdir -p /tmp/$P &&
cd /tmp/$P &&

wget http://sourceforge.net/projects/net-snmp/files/$PN/$PV/${P}.tar.gz &&
tar xf ${P}.tar.gz &&
cd ${P} &&

./configure  --disable-agent --disable-embedded-perl --disable-mibs --disable-applications --disable-manuals --disable-scripts --with-defaults &&
make && sudo make install

