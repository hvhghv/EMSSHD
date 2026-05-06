param(
    [int]$Port = 22265,
    [string]$ServerExe = '',
    [int]$ParallelClients = 2,
    [int]$ServerMaxWorkers = 2,
    [int]$TimeoutMs = 30000
)

$ErrorActionPreference = 'Stop'

if ($ParallelClients -lt 2) {
    throw 'ParallelClients must be >= 2'
}
if ($ServerMaxWorkers -lt 1) {
    throw 'ServerMaxWorkers must be >= 1'
}
if ($TimeoutMs -lt 1000) {
    throw 'TimeoutMs must be >= 1000'
}

$repo = Split-Path -Parent $PSScriptRoot
if ($ServerExe -eq '') {
    $ServerExe = Join-Path $repo 'cmake-build\Debug\emssh_concurrent_server.exe'
}
if (-not (Test-Path $ServerExe)) {
    throw "missing concurrent server executable: $ServerExe"
}

$root = Join-Path $repo 'interop_root_concurrent'
$hostKey = Join-Path $repo 'interop_hostkey_concurrent_ecdsa.raw'
$known = Join-Path $repo 'interop_concurrent_known_hosts'
$serverOut = Join-Path $repo 'interop_concurrent_server.out'
$serverErr = Join-Path $repo 'interop_concurrent_server.err'
$askpass = Join-Path $repo 'interop_concurrent_askpass.cmd'

Get-Process emssh_concurrent_server -ErrorAction SilentlyContinue | Stop-Process -Force
New-Item -ItemType Directory -Force -Path $root | Out-Null
Remove-Item -LiteralPath $known,$serverOut,$serverErr,$askpass -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root '*') -Force -ErrorAction SilentlyContinue

$uploads = @()
$downloads = @()
$batches = @()
for ($i = 1; $i -le $ParallelClients; $i++) {
    $upload = Join-Path $repo ("interop_concurrent_upload_{0}.txt" -f $i)
    $download = Join-Path $repo ("interop_concurrent_download_{0}.txt" -f $i)
    $batch = Join-Path $repo ("interop_concurrent_batch_{0}.txt" -f $i)

    $uploads += $upload
    $downloads += $download
    $batches += $batch

    Remove-Item -LiteralPath $upload,$download,$batch -ErrorAction SilentlyContinue
    Set-Content -LiteralPath $upload -Value ("emssh-concurrent-sftp-client-{0}" -f $i) -NoNewline -Encoding ASCII

    @(
        'pwd',
        "put `"$upload`" uploaded_$i.txt",
        "get uploaded_$i.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
}

$serverArgs = @(
    [string]$Port,
    $root,
    'alice',
    'secret',
    $hostKey,
    '--max-workers', [string]$ServerMaxWorkers,
    '--max-connections', [string]$ParallelClients,
    '--timeout-ms', [string]$TimeoutMs,
    '--hostkey-algorithm', 'ecdsa-p256'
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
    Start-Sleep -Milliseconds 500
    $server.Refresh()
    if ($server.HasExited) {
        $serverErrText = if (Test-Path $serverErr) { Get-Content -LiteralPath $serverErr -Raw } else { '' }
        if ($serverErrText -eq '') {
            throw 'concurrent server exited before clients started'
        }
        throw "concurrent server exited before clients started: $serverErrText"
    }

    Set-Content -LiteralPath $askpass -Value @('@echo off', 'echo secret') -Encoding ASCII
    $env:SSH_ASKPASS = $askpass
    $env:SSH_ASKPASS_REQUIRE = 'force'
    $env:DISPLAY = 'emssh'

    $clients = @()
    for ($i = 1; $i -le $ParallelClients; $i++) {
        $clientOut = Join-Path $repo ("interop_concurrent_sftp_{0}.out" -f $i)
        $clientErr = Join-Path $repo ("interop_concurrent_sftp_{0}.err" -f $i)
        Remove-Item -LiteralPath $clientOut,$clientErr -ErrorAction SilentlyContinue

        $sftpArgs = @(
            '-P', [string]$Port,
            '-o', 'BatchMode=no',
            '-o', 'PreferredAuthentications=password',
            '-o', 'PubkeyAuthentication=no',
            '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'StrictHostKeyChecking=no',
            '-o', "UserKnownHostsFile=$known",
            '-b', $batches[$i - 1],
            'alice@127.0.0.1'
        )

        $client = Start-Process -FilePath 'sftp.exe' `
            -ArgumentList $sftpArgs `
            -RedirectStandardOutput $clientOut `
            -RedirectStandardError $clientErr `
            -WindowStyle Hidden `
            -PassThru

        $clients += [PSCustomObject]@{
            Index = $i
            Process = $client
            OutPath = $clientOut
            ErrPath = $clientErr
        }
    }

    foreach ($clientInfo in $clients) {
        if (-not $clientInfo.Process.WaitForExit(20000)) {
            Stop-Process -Id $clientInfo.Process.Id -Force
            throw "sftp client $($clientInfo.Index) timed out"
        }
        $clientInfo.Process.Refresh()
        if ($null -ne $clientInfo.Process.ExitCode -and $clientInfo.Process.ExitCode -ne 0) {
            $errText = if (Test-Path $clientInfo.ErrPath) { Get-Content -LiteralPath $clientInfo.ErrPath -Raw } else { '' }
            throw "sftp client $($clientInfo.Index) failed with exit code $($clientInfo.Process.ExitCode): $errText"
        }
    }

    for ($i = 1; $i -le $ParallelClients; $i++) {
        $upload = $uploads[$i - 1]
        $download = $downloads[$i - 1]
        $uploadedOnServer = Join-Path $root ("uploaded_{0}.txt" -f $i)
        if (-not (Test-Path $download)) {
            throw "client $i download file missing"
        }
        if (-not (Test-Path $uploadedOnServer)) {
            throw "server-side uploaded file missing for client $i"
        }
        $uploadText = Get-Content -LiteralPath $upload -Raw
        $downloadText = Get-Content -LiteralPath $download -Raw
        if ($uploadText -ne $downloadText) {
            throw "client $i download content mismatch"
        }
    }

    Write-Output "OpenSSH SFTP concurrent interop passed ($ParallelClients clients)"
}
finally {
    if ($null -ne $server) {
        try {
            $server.Refresh()
            if (-not $server.HasExited) {
                Stop-Process -Id $server.Id -Force
            }
        } catch {
        }
    }
    $env:SSH_ASKPASS = $oldAskpass
    $env:SSH_ASKPASS_REQUIRE = $oldAskpassRequire
    $env:DISPLAY = $oldDisplay
}
