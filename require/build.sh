#!/bin/sh

# Install required package
apk update
apk add --no-cache perl-net-ssleay perl-crypt-ssleay perl-libwww perl-lwp-useragent-determined perl-lwp-protocol-https pcre libpcap libdnet libtirpc libressl zlib perl supervisor bash py3-pip
apk add --no-cache build-base alpine-sdk linux-headers libpcap-dev libdnet-dev musl-dev pcre-dev bison flex net-tools wget zlib-dev python3-dev sed tar libtirpc-dev libressl-dev cmake make g++

# Symlink libtirpc
ln -s /usr/include/tirpc/rpc /usr/include/rpc
ln -s /usr/include/tirpc/netconfig.h /usr/include/netconfig.h

# Install required python packages
pip3 install --no-cache-dir -r /root/requirements.txt

# Create source code directory
mkdir -p /root/snort_src
mkdir -p /root/daq_src
mkdir -p /root/pulledpork_src

# Snort download
wget https://www.snort.org/downloads/snort/snort-2.9.19.tar.gz -O /root/snort.tar.gz
tar -xvzf /root/snort.tar.gz --strip-components=1 -C /root/snort_src
rm /root/snort.tar.gz

# DAQ download
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz -O /root/daq.tar.gz
tar -xvzf /root/daq.tar.gz --strip-components=1 -C /root/daq_src
rm /root/daq.tar.gz

# Compile DAQ source code
cd /root/daq_src || exit
echo "#include <unistd.h>" > /usr/include/sys/unistd.h
./configure
make
make install

# Compile Snort source code
cd /root/snort_src || exit
./configure --enable-sourcefire --disable-open-appid
make
make install
ln -s /usr/local/bin/snort /usr/sbin/snort

# Create snort user and group
addgroup -S snort
adduser -S snort -g snort

# Create Snort required directories
mkdir /etc/snort
mkdir /etc/snort/rules
mkdir /etc/snort/rules/iplists
mkdir /etc/snort/preproc_rules
mkdir /etc/snort/so_rules
mkdir /var/log/snort
mkdir /var/log/snort/archived_logs
mkdir /usr/local/lib/snort_dynamicrules
mkdir /tmp/snort
touch /etc/snort/rules/iplists/white_list.rules /etc/snort/rules/iplists/black_list.rules /etc/snort/rules/local.rules /etc/snort/sid-msg.map
chmod -R 5775 /etc/snort
chmod -R 5775 /var/log/snort
chmod -R 5775 /var/log/snort/archived_logs
chmod -R 5775 /usr/local/lib/snort_dynamicrules
chown -R snort:snort /etc/snort
chown -R snort:snort /var/log/snort
chown -R snort:snort /usr/local/lib/snort_dynamicrules
cp /root/snort_src/etc/*.conf* /etc/snort
cp /root/snort_src/etc/*.map /etc/snort
cp /root/snort_src/etc/*.dtd /etc/snort
cp /root/snort_src/src/dynamic-preprocessors/build/usr/local/lib/snort_dynamicpreprocessor/* /usr/local/lib/snort_dynamicpreprocessor/

# Install pulledpork
wget https://github.com/mata-elang-stable/pulledpork/archive/v0.7.3.tar.gz -O /root/pulledpork.tar.gz
tar -xvzf /root/pulledpork.tar.gz --strip-components=1 -C /root/pulledpork_src
rm /root/pulledpork.tar.gz
cp /root/pulledpork_src/pulledpork.pl /usr/local/bin
chmod +x /usr/local/bin/pulledpork.pl
cp /root/pulledpork_src/etc/*.conf /etc/snort
mv /root/pulledpork.conf /etc/snort/

# Cleaning up
rm -rf /root/snort_src /root/daq_src /root/pulledpork_src /root/requirements.txt /root/requirements-test.txt /root/build.sh
apk del build-base alpine-sdk linux-headers libpcap-dev libdnet-dev musl-dev pcre-dev bison flex net-tools wget zlib-dev python3-dev tar libtirpc-dev libressl-dev cmake make g++

# Configuring
sed -i \
    -e 's@^var RULE_PATH.*@var RULE_PATH /etc/snort/rules@' \
    -e 's@^var SO_RULE_PATH.*@var SO_RULE_PATH /etc/snort/so_rules@' \
    -e 's@^var PREPROC_RULE_PATH.*@var PREPROCRULE_PATH /etc/snort/preproc_rules@' \
    -e 's@^var WHITE_LIST_PATH.*@var WHITE_LIST_PATH /etc/snort/rules/iplists@' \
    -e 's@^var BLACK_LIST_PATH.*@var BLACK_LIST_PATH /etc/snort/rules/iplists@' \
    -e 's@^\(include $.*\)@# \1@' \
    -e "s@\# include \$RULE\_PATH\/local\.rules@include \/etc\/snort\/rules\/local\.rules@" \
    -e '/include \/etc\/snort\/rules\/local\.rules/a include \/etc\/snort\/rules\/snort\.rules' \
    /etc/snort/snort.conf