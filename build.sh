#!/bin/sh

RC=0

export RTE_SDK=$(pwd)
echo "RTE_SDK is $RTE_SDK"

APP_PATH=$RTE_SDK/daemon

#make -j 8 install T=arm64-armv8a-linux-gcc MAKE_PAUSE=n

RC=$((RC+$?))

if [ $RC -ne 0 ]; then
	echo "DPDK failed"
	exit $RC
fi

cd $APP_PATH

echo "Build daemon at $APP_PATH"

make -j 8

RC=$((RC+$?))

if [ $RC -ne 0 ]; then
	echo "Daemon failed"
	exit $RC
fi
