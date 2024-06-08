#!/usr/bin/bash

name=$1
gdb --pid=$(pidof "$name")
