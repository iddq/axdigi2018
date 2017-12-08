#!/bin/bash

WORK_DIR="/usr/src/axdigi2018"
BIN="axdigi2018"
LOG="/var/log/axdigi2018.log"

cd $WORK_DIR
pkill -x $BIN
ulimit -c 10000 # 10MB

while true; do
  ./$BIN >>$LOG 2>&1
  sleep 1
done;
