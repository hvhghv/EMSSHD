param(
    [string]$ServerExe = '',
    [ValidateSet('publickey', 'hostkey')]
    [string]$Mode = 'publickey'
)

$ErrorActionPreference = 'Stop'

if ($ServerExe -eq '') {
    throw 'ServerExe is required'
}
if (-not (Test-Path $ServerExe)) {
    throw "missing server executable: $ServerExe"
}

$output = & $ServerExe '--probe-ed25519' $Mode 2>&1
$exitCode = $LASTEXITCODE
$text = ($output | Out-String).Trim()

if ($exitCode -ne 0 -and $exitCode -ne 1) {
    throw "unexpected probe exit code: $exitCode; output: $text"
}

if ($Mode -eq 'publickey') {
    if ($exitCode -eq 0 -and $text -notmatch '^ed25519 publickey verify supported$') {
        throw "unexpected probe output for supported publickey mode: $text"
    }
    if ($exitCode -eq 1 -and $text -notmatch '^ed25519 publickey verify unsupported$') {
        throw "unexpected probe output for unsupported publickey mode: $text"
    }
} else {
    if ($exitCode -eq 0 -and $text -notmatch '^ed25519 hostkey supported$') {
        throw "unexpected probe output for supported hostkey mode: $text"
    }
    if ($exitCode -eq 1 -and $text -notmatch '^ed25519 hostkey unsupported$') {
        throw "unexpected probe output for unsupported hostkey mode: $text"
    }
}

Write-Output "ed25519 probe contract passed ($Mode): $text"
