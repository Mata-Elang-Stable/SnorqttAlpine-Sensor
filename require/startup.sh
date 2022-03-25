#!/bin/sh

# Setup snort.conf
sed -i \
-e 's@^ipvar HOME_NET.*@ipvar HOME_NET '"${PROTECTED_SUBNET}"'@' \
-e 's@^ipvar EXTERNAL_NET.*@ipvar EXTERNAL_NET '"${EXTERNAL_SUBNET}"'@' \
/etc/snort/snort.conf

# Setup Rule using pulledpork
/usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -l

# Verify Snort configurations and rules
snort -T -c /etc/snort/snort.conf

# Change import to use snortunsock.alert on snort listener
sed -i '/import alert/c\import snortunsock.alert as alert' /usr/lib/python3.7/site-packages/snortunsock/snort_listener.py

# Cleaning temporary
rm -rf /tmp/snort/*

# Start service
/usr/bin/supervisord -c /root/libs/super_snort.conf