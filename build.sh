#!/bin/sh
# main.c partclone.c progress.c checksum.c torrent_helper.c partclone.h progress.h gettext.h checksum.h torrent_helper.h bitmap.h
apt-get install libext2fs-dev libfuse-dev reiserfsprogs jfsutils ntfs-3g-dev

./configure --enable-fuse --enable-extfs --enable-xfs --enable-hfsp --enable-apfs --enable-fat --enable-exfat --enable-f2fs --enable-btrfs --enable-ncursesw --enable-static --enable-mtrace --enable-fs-test

