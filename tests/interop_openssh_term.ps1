param(
    [int]$Port = 22266,
    [string]$ServerExe = '',
    [ValidateSet('shell', 'exec')]
    [string]$SessionType = 'shell'
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
if ($ServerExe -eq '') {
    $ServerExe = Join-Path $repo 'cmake-build\Debug\emssh_embedded_posix_socket_stdio_openssl_server.exe'
}

$sshCmd = Get-Command ssh -ErrorAction Stop
$sshExe = $sshCmd.Source
$root = Join-Path $repo 'interop_root_term'
$passwdFile = Join-Path $repo 'interop_term_passwd'
$known = Join-Path $repo 'interop_term_known_hosts'
$serverOut = Join-Path $repo 'interop_term_server.out'
$serverErr = Join-Path $repo 'interop_term_server.err'
$sshOut = Join-Path $repo 'interop_term_ssh.out'
$sshErr = Join-Path $repo 'interop_term_ssh.err'
$sshIn = Join-Path $repo 'interop_term_ssh.in'
$askpass = Join-Path $repo 'interop_term_askpass.cmd'

if (-not (Test-Path $ServerExe)) {
    throw "missing server executable: $ServerExe"
}

Get-Process emssh_embedded_posix_socket_stdio_openssl_server -ErrorAction SilentlyContinue | Stop-Process -Force
New-Item -ItemType Directory -Force -Path $root | Out-Null
Remove-Item -LiteralPath $known,$serverOut,$serverErr,$sshOut,$sshErr,$sshIn,$askpass,$passwdFile -ErrorAction SilentlyContinue

# password is literal "secret"
$passwdLine = 'emssh:$6$emssh$wuksbYtxU8iezhLCAQIx3O21RVoNk4wlJFMv/kMPRKtb79/ryocMMFb.snS.AnbtzBQVbk6S5.38YW8Lt1u.M.:1000:1000:emssh:/tmp:/bin/sh'
Set-Content -LiteralPath $passwdFile -Value $passwdLine -Encoding ASCII
Set-Content -LiteralPath $askpass -Value @('@echo off', 'echo secret') -Encoding ASCII

$serverArgs = @(
    [string]$Port,
    $root,
    '--passwd-file', $passwdFile,
    '--mode', 'term'
)

$server = Start-Process -FilePath $ServerExe `
    -ArgumentList $serverArgs `
    -RedirectStandardOutput $serverOut `
    -RedirectStandardError $serverErr `
    -WindowStyle Hidden `
    -PassThru

$oldAskpass = $env:SSH_ASKPASS
$oldAskpassRequire = $env:SSH_ASKPASS_REQUIRE
$oldDisplay = $env:DISPLAY

try {
    Start-Sleep -Milliseconds 700
    $server.Refresh()
    if ($server.HasExited) {
        $serverErrText = if (Test-Path $serverErr) { Get-Content -LiteralPath $serverErr -Raw } else { '' }
        if ($serverErrText -match 'requires EMSSH_BUILD_POSIX_TERM=ON' -or
            $serverErrText -match 'posix runtime init failed: unsupported' -or
            $serverErrText -match 'posix net init failed: unsupported' -or
            $serverErrText -match 'posix term init failed: unsupported' -or
            $serverErrText -match 'posix passwd auth init failed: unsupported') {
            Write-Output 'OpenSSH terminal interop skipped (platform/runtime does not support required posix term/passwd stack)'
            return
        }
        if ($serverErrText -eq '') {
            throw 'terminal server exited before client started'
        }
        throw "terminal server exited before client started: $serverErrText"
    }

    $env:SSH_ASKPASS = $askpass
    $env:SSH_ASKPASS_REQUIRE = 'force'
    $env:DISPLAY = 'emssh'

    $sshArgs = @(
        '-p', [string]$Port,
        '-o', 'BatchMode=no',
        '-o', 'PreferredAuthentications=password',
        '-o', 'PubkeyAuthentication=no',
        '-o', 'NumberOfPasswordPrompts=1',
        '-o', 'StrictHostKeyChecking=no',
        '-o', "UserKnownHostsFile=$known"
    )

    if ($SessionType -eq 'shell') {
        @(
            'echo term-shell-ok',
            'exit 23'
        ) | Set-Content -LiteralPath $sshIn -Encoding ASCII
        $sshArgs += @('-tt', 'emssh@127.0.0.1')
        $client = Start-Process -FilePath $sshExe `
            -ArgumentList $sshArgs `
            -RedirectStandardInput $sshIn `
            -RedirectStandardOutput $sshOut `
            -RedirectStandardError $sshErr `
            -WindowStyle Hidden `
            -PassThru
        if (-not $client.WaitForExit(20000)) {
            Stop-Process -Id $client.Id -Force
            throw 'ssh shell interop timed out'
        }
        $client.Refresh()
        if ($client.ExitCode -ne 23) {
            $stderrText = if (Test-Path $sshErr) { Get-Content -LiteralPath $sshErr -Raw } else { '' }
            throw "ssh shell exit status mismatch: expected 23, got $($client.ExitCode). stderr: $stderrText"
        }
        $stdoutText = if (Test-Path $sshOut) { Get-Content -LiteralPath $sshOut -Raw } else { '' }
        if ($stdoutText -notmatch 'term-shell-ok') {
            throw "ssh shell output mismatch: $stdoutText"
        }
        Write-Output 'OpenSSH terminal shell interop passed'
    } else {
        $sshArgs += @('emssh@127.0.0.1', 'printf term-exec-ok; exit 7')
        $client = Start-Process -FilePath $sshExe `
            -ArgumentList $sshArgs `
            -RedirectStandardOutput $sshOut `
            -RedirectStandardError $sshErr `
            -WindowStyle Hidden `
            -PassThru
        if (-not $client.WaitForExit(20000)) {
            Stop-Process -Id $client.Id -Force
            throw 'ssh exec interop timed out'
        }
        $client.Refresh()
        if ($client.ExitCode -ne 7) {
            $stderrText = if (Test-Path $sshErr) { Get-Content -LiteralPath $sshErr -Raw } else { '' }
            throw "ssh exec exit status mismatch: expected 7, got $($client.ExitCode). stderr: $stderrText"
        }
        $stdoutText = if (Test-Path $sshOut) { Get-Content -LiteralPath $sshOut -Raw } else { '' }
        if ($stdoutText -notmatch 'term-exec-ok') {
            throw "ssh exec output mismatch: $stdoutText"
        }
        Write-Output 'OpenSSH terminal exec interop passed'
    }
} finally {
    $env:SSH_ASKPASS = $oldAskpass
    $env:SSH_ASKPASS_REQUIRE = $oldAskpassRequire
    $env:DISPLAY = $oldDisplay

    if ($server -and -not $server.HasExited) {
        if (-not $server.WaitForExit(2000)) {
            Stop-Process -Id $server.Id -Force
        }
    }
}
