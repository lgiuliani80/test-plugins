#!/bin/bash

FILESIZE_MB=500

# Create a [FILESIZE_MB] MB file (of random data)
dd if=/dev/urandom of=/tmp/big.bin bs=1M count=$FILESIZE_MB

# Measure the time taken by each SHA-1 implementation
for i in basic asm-x64 intrinsics-sse dotnet_wrapper; do
    if [ -f ./sha1$i.so ] ; then
        time ./my_sha1 ./sha1$i.so /tmp/big.bin
    else
        echo "-> Variant $i not available" 1>&2
    fi
done

rm /tmp/big.bin
