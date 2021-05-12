#!/bin/sh

defaultInterface=$(route | grep default | awk '{print $(NF)}')
myIP=$(ifconfig $defaultInterface | grep 'inet addr:' | cut -d: -f2 |  awk '{ print $1}')
echo "Configuring jool for $myIP"

sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

sudo /sbin/modprobe jool
sudo jool instance add "example" --netfilter --pool6 64:ff9b::/96
