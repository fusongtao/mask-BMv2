#!/bin/bash

if [ ! -d "c-ares-1.15.0" ]; then
    wget https://c-ares.haxx.se/download/c-ares-1.15.0.tar.gz
    tar -zxvf c-ares-1.15.0.tar.gz
    rm c-ares-1.15.0.tar.gz 
    cd c-ares-1.15.0
    ./configure
    make
    sudo make install
    sudo ldconfig

    cd ..
else
    echo "c-areas installed"
fi
