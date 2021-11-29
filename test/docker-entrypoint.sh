#!/bin/sh

ssh-keygen -A

/etc/init.d/sshd start

tail -f /dev/null