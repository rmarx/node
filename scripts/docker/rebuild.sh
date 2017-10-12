#!/bin/bash

# go to node folder
cd /node

# get changes from repo
git pull

# configure
./configure

# build node
make -j2

# run tests
make test

# install node
make install