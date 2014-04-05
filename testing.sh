
umount /tmp
cd /
rmmod wrapfs
cd /usr/src/hw3-cse506g07
make
make modules
make modules_install install
mount -t wrapfs /n/scratch/ /tmp -o mmap
