#!/bin/sh
# Add your startup script
/usr/sbin/chroot --userspec=1000:1000 /home/ctf ./memcached -vvv

# DO NOT DELETE
sleep infinity;
