# Invokes cargo with the WinLibs mingw-w64 toolchain prepended to PATH.
# Needed because a stale 32-bit C:\MinGW is earlier on the system PATH and
# rustc's dlltool/gcc discovery picks it up otherwise.
$mingw = "C:\Users\Jhon\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin"
if (Test-Path $mingw) { $env:PATH = "$mingw;$env:PATH" }
& "$env:USERPROFILE\.cargo\bin\cargo.exe" @args
exit $LASTEXITCODE
