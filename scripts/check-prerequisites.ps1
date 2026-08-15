$ErrorActionPreference = 'Stop'

function Test-Command($Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Missing required command: $Name"
    }
}

Test-Command node
Test-Command npm
Test-Command rustc
Test-Command cargo
Test-Command winget

$linker = Get-Command link.exe -ErrorAction SilentlyContinue
if (-not $linker) {
    Write-Warning 'MSVC link.exe not found. Install Visual Studio Build Tools: Desktop development with C++.'
}

[pscustomobject]@{
    Node = node --version
    Npm = npm --version
    Rust = rustc --version
    Cargo = cargo --version
    Winget = winget --version
    MsvcLinker = [bool]$linker
}

