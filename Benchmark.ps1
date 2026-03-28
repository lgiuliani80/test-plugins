$fileSizeMB = 500

# Create a [fileSizeMB] MB file (of random data)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$fs  = [System.IO.File]::OpenWrite("$Env:TEMP\big.bin")
$buf = New-Object byte[] (1MB)
1..$fileSizeMB | ForEach-Object { $rng.GetBytes($buf); $fs.Write($buf, 0, $buf.Length) }
$fs.Close()

# Measure the time taken by each SHA-1 implementation
"basic","asm-x64","intrinsics-sse","dotnet_wrapper" | ForEach-Object { 
    if (Test-Path sha1$($_).dll) {
        "Time taken: {0,6:N3} s" -f (Measure-Command { .\my_sha1 sha1$($_).dll $Env:TEMP\big.bin | Out-Default }).TotalSeconds
    } else {
        Write-Warning "Variant $_ not available on this system."
    }
}

rm $Env:TEMP\big.bin
