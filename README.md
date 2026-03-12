# Performance comparison of SHA-1 implemented in different ways

## Building

Linux:

```bash
cmake .
cmake --build . --config Release
```

Windows:

```powershell
cmake -G "Visual Studio 17 2022" .
cmake --build . --config Release
```

## Running

```bash
# Create a 500 MB file
dd if=/dev/urandom of=/tmp/big.bin bs=1M count=500

# Measure the time taken by each SHA-1 implementation
time ./my_sha1 ./sha1basic.so /tmp/big.bin && time ./my_sha1 ./sha1asm-x64.so /tmp/big.bin && time ./my_sha1 ./sha1intrinsics-sse.so /tmp/big.bin

rm /tmp/big.bin
```
