#!/bin/bash
sudo add-apt-repository ppa:chris-lea/libsodium;
sudo echo "deb http://ppa.launchpad.net/chris-lea/libsodium/ubuntu trusty main" >> /etc/apt/sources.list;
sudo echo "deb-src http://ppa.launchpad.net/chris-lea/libsodium/ubuntu trusty main" >> /etc/apt/sources.list;
sudo apt-get update && sudo apt-get install libsodium;