# Performance comparison of SHA-1 implemented in different ways

## Prerequisites

- CMake 3.15 or later
- A C compiler that supports C11 (e.g., GCC, Clang, MSVC)
- NASM (for assembling the x64 version)
- A Linux or Windows environment (the code is cross-platform)
- 

## Building

```bash
cmake .
cmake --build . --config Release

# TODO: integrate the .NET and Rust build steps into the CMake build process
dotnet build dotnet/src/sha1dotnet.csproj -c Release
cp dotnet/src/bin/Release/net8.0/sha1dotnet.dll ./
cd dotnet/rust-wrapper
cargo build --release
# Linux
cp target/release/libsha1dotnet_wrapper.so ../sha1dotnet_wrapper.so
# Windows
cp target/release/sha1dotnet_wrapper.dll ../sha1dotnet_wrapper.dll
cd ../..
```

## Running

Linux:

```bash
# Create a 500 MB file (of random data)
dd if=/dev/urandom of=/tmp/big.bin bs=1M count=500

# Measure the time taken by each SHA-1 implementation
for i in basic asm-x64 intrinsics-sse dotnet_wrapper; do
    time ./my_sha1 ./sha1$i.so /tmp/big.bin
done

rm /tmp/big.bin
```

Windows:

```powershell
# Create a 500 MB file (of random data)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$fs  = [System.IO.File]::OpenWrite("$Env:TEMP\big.bin")
$buf = New-Object byte[] (1MB)
1..500 | ForEach-Object { $rng.GetBytes($buf); $fs.Write($buf, 0, $buf.Length) }
$fs.Close()

# Measure the time taken by each SHA-1 implementation
"basic","asm-x64","intrinsics-sse","dotnet_wrapper" | ForEach-Object { 
    "Time taken: {0,6:N3} s" -f (Measure-Command { .\my_sha1 sha1$($_).dll $Env:TEMP\big.bin | Out-Default }).TotalSeconds
}

rm $Env:TEMP\big.bin
```
