#!/bin/sh

./partclone.extfs -c -M -p 1 -m vmdk -O /root/a.img -s /dev/sdb1 -F -d0 -a0
