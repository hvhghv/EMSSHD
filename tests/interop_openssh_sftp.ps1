param(
    [int]$Port = 22226,
    [string]$ServerExe = '',
    [ValidateSet('ecdsa-p256', 'ed25519')]
    [string]$ServerHostKeyAlgorithm = 'ecdsa-p256',
    [ValidateSet('ecdsa', 'rsa', 'ed25519')]
    [string]$KeyType = 'ecdsa',
    [ValidateSet('publickey', 'password')]
    [string]$AuthMode = 'publickey',
    [string]$FromPattern = '',
    [string]$PathPrefix = '',
    [string]$MaxReadEnd = '',
    [string]$MaxWriteEnd = '',
    [int]$RepeatCount = 1,
    [int]$ServerMaxConnections = 1,
    [switch]$ReadOnly,
    [switch]$DenyFrom,
    [switch]$DenyNonSftpChannel,
    [switch]$DenyRename,
    [switch]$DenyDelete,
    [switch]$DenySetstat,
    [switch]$DenyCreate,
    [switch]$DenyHardlink,
    [switch]$DenyRemove,
    [switch]$DenyRmdir,
    [switch]$DenyMkdir,
    [switch]$DenyOpenCreate,
    [switch]$DenyOpenTrunc,
    [switch]$DenyOpenAppend,
    [switch]$DenyOpenWrite,
    [switch]$DenyOpenRead,
    [switch]$DenyRead,
    [switch]$DenyRealpath,
    [switch]$DenyStat,
    [switch]$DenyFstat,
    [switch]$DenyFsetstat,
    [switch]$DenyFsync,
    [switch]$DenyStatvfs,
    [switch]$DenyOpendir,
    [switch]$DenyReaddir,
    [switch]$DenyWrite,
    [switch]$ForceSshRsaSha1
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
if ($ServerExe -eq '') {
    $ServerExe = Join-Path $repo 'cmake-build\Debug\emssh_minimal_server.exe'
}
$root = Join-Path $repo 'interop_root'
$hostKey = Join-Path $repo "interop_hostkey_$ServerHostKeyAlgorithm.raw"
$clientKey = Join-Path $repo "interop_client_$KeyType"
$clientPub = "$clientKey.pub"
$decoyKey = Join-Path $repo "interop_decoy_$KeyType"
$decoyPub = "$decoyKey.pub"
$authorizedKeys = Join-Path $repo "interop_authorized_$KeyType.keys"
$known = Join-Path $repo 'interop_known_hosts'
$serverOut = Join-Path $repo 'interop_server.out'
$serverErr = Join-Path $repo 'interop_server.err'
$sftpOut = Join-Path $repo 'interop_sftp.out'
$sftpErr = Join-Path $repo 'interop_sftp.err'
$sshOut = Join-Path $repo 'interop_ssh.out'
$sshErr = Join-Path $repo 'interop_ssh.err'
$batch = Join-Path $repo 'interop_sftp_batch.txt'
$upload = Join-Path $repo 'interop_upload.txt'
$download = Join-Path $repo 'interop_download.txt'
$downloadLarge = Join-Path $repo 'interop_download_large.txt'
$askpass = Join-Path $repo 'interop_askpass.cmd'
$pathPrefixList = @()

if (-not (Test-Path $ServerExe)) {
    throw "missing server executable: $ServerExe"
}
if ($DenyFrom -and $AuthMode -ne 'publickey') {
    throw 'DenyFrom requires publickey auth mode'
}
if ($ReadOnly -and $AuthMode -ne 'publickey') {
    throw 'ReadOnly requires publickey auth mode'
}
if ($FromPattern -ne '' -and $AuthMode -ne 'publickey') {
    throw 'FromPattern requires publickey auth mode'
}
if ($PathPrefix -ne '' -and $AuthMode -ne 'publickey') {
    throw 'PathPrefix requires publickey auth mode'
}
if ($MaxReadEnd -ne '' -and $AuthMode -ne 'publickey') {
    throw 'MaxReadEnd requires publickey auth mode'
}
if ($MaxWriteEnd -ne '' -and $AuthMode -ne 'publickey') {
    throw 'MaxWriteEnd requires publickey auth mode'
}
if ($DenyNonSftpChannel -and $AuthMode -ne 'publickey') {
    throw 'DenyNonSftpChannel requires publickey auth mode'
}
if ($DenyRename -and $AuthMode -ne 'publickey') {
    throw 'DenyRename requires publickey auth mode'
}
if ($DenyDelete -and $AuthMode -ne 'publickey') {
    throw 'DenyDelete requires publickey auth mode'
}
if ($DenySetstat -and $AuthMode -ne 'publickey') {
    throw 'DenySetstat requires publickey auth mode'
}
if ($DenyCreate -and $AuthMode -ne 'publickey') {
    throw 'DenyCreate requires publickey auth mode'
}
if ($DenyHardlink -and $AuthMode -ne 'publickey') {
    throw 'DenyHardlink requires publickey auth mode'
}
if ($DenyRemove -and $AuthMode -ne 'publickey') {
    throw 'DenyRemove requires publickey auth mode'
}
if ($DenyRmdir -and $AuthMode -ne 'publickey') {
    throw 'DenyRmdir requires publickey auth mode'
}
if ($DenyMkdir -and $AuthMode -ne 'publickey') {
    throw 'DenyMkdir requires publickey auth mode'
}
if ($DenyOpenCreate -and $AuthMode -ne 'publickey') {
    throw 'DenyOpenCreate requires publickey auth mode'
}
if ($DenyOpenTrunc -and $AuthMode -ne 'publickey') {
    throw 'DenyOpenTrunc requires publickey auth mode'
}
if ($DenyOpenAppend -and $AuthMode -ne 'publickey') {
    throw 'DenyOpenAppend requires publickey auth mode'
}
if ($DenyOpenWrite -and $AuthMode -ne 'publickey') {
    throw 'DenyOpenWrite requires publickey auth mode'
}
if ($DenyOpenRead -and $AuthMode -ne 'publickey') {
    throw 'DenyOpenRead requires publickey auth mode'
}
if ($DenyRead -and $AuthMode -ne 'publickey') {
    throw 'DenyRead requires publickey auth mode'
}
if ($DenyRealpath -and $AuthMode -ne 'publickey') {
    throw 'DenyRealpath requires publickey auth mode'
}
if ($DenyStat -and $AuthMode -ne 'publickey') {
    throw 'DenyStat requires publickey auth mode'
}
if ($DenyFstat -and $AuthMode -ne 'publickey') {
    throw 'DenyFstat requires publickey auth mode'
}
if ($DenyFsetstat -and $AuthMode -ne 'publickey') {
    throw 'DenyFsetstat requires publickey auth mode'
}
if ($DenyFsync -and $AuthMode -ne 'publickey') {
    throw 'DenyFsync requires publickey auth mode'
}
if ($DenyStatvfs -and $AuthMode -ne 'publickey') {
    throw 'DenyStatvfs requires publickey auth mode'
}
if ($DenyOpendir -and $AuthMode -ne 'publickey') {
    throw 'DenyOpendir requires publickey auth mode'
}
if ($DenyReaddir -and $AuthMode -ne 'publickey') {
    throw 'DenyReaddir requires publickey auth mode'
}
if ($DenyWrite -and $AuthMode -ne 'publickey') {
    throw 'DenyWrite requires publickey auth mode'
}
if ($ForceSshRsaSha1) {
    if ($AuthMode -ne 'publickey') {
        throw 'ForceSshRsaSha1 requires publickey auth mode'
    }
    if ($KeyType -ne 'rsa') {
        throw 'ForceSshRsaSha1 requires KeyType=rsa'
    }
}
if ($RepeatCount -lt 1) {
    throw 'RepeatCount must be >= 1'
}
if ($ServerMaxConnections -lt 1) {
    throw 'ServerMaxConnections must be >= 1'
}
$requiredConnections = if ($DenyNonSftpChannel) { $RepeatCount * 2 } else { $RepeatCount }
if ($ServerMaxConnections -lt $requiredConnections) {
    throw "ServerMaxConnections must be >= $requiredConnections for current scenario"
}

$hostkeyProbe = $null
$publickeyProbe = $null

function Get-Ed25519ProbeSupport {
    param(
        [string]$Mode
    )

    try {
        & $ServerExe '--probe-ed25519' $Mode *> $null
        $exitCode = $LASTEXITCODE
    } catch {
        return $null
    }

    if ($exitCode -eq 0) {
        return $true
    }
    if ($exitCode -eq 1) {
        return $false
    }
    return $null
}

if ($ServerHostKeyAlgorithm -eq 'ed25519') {
    $hostkeyProbe = Get-Ed25519ProbeSupport -Mode 'hostkey'
    if ($hostkeyProbe -eq $false) {
        Write-Output 'OpenSSH SFTP ed25519 hostkey interop skipped (platform does not support Ed25519 hostkey)'
        return
    }
}
if ($AuthMode -eq 'publickey' -and $KeyType -eq 'ed25519') {
    $publickeyProbe = Get-Ed25519ProbeSupport -Mode 'publickey'
    if ($publickeyProbe -eq $false) {
        Write-Output 'OpenSSH SFTP ed25519 publickey interop skipped (platform does not support Ed25519 publickey verify)'
        return
    }
}

Get-Process emssh_minimal_server -ErrorAction SilentlyContinue | Stop-Process -Force
New-Item -ItemType Directory -Force -Path $root | Out-Null
Remove-Item -LiteralPath $known,$serverOut,$serverErr,$sftpOut,$sftpErr,$sshOut,$sshErr,$batch,$upload,$download,$downloadLarge,$askpass,$authorizedKeys,(Join-Path $root 'uploaded.txt'),(Join-Path $root 'readonly.txt') -ErrorAction SilentlyContinue
Remove-Item -Path "$download.*" -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'max_write_limited.txt'),(Join-Path $root 'max_write_fixture.txt') -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'max_read_source.txt') -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'rename_source.txt'),(Join-Path $root 'rename_target.txt') -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'delete_source.txt'),(Join-Path $root 'delete_dir') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'setstat_source.txt') -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'create_denied.txt'),(Join-Path $root 'create_dir'),(Join-Path $root 'create_fixture.txt') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'hardlink_source.txt'),(Join-Path $root 'hardlink_target.txt') -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'remove_source.txt') -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'rmdir_source.txt'),(Join-Path $root 'rmdir_dir') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'mkdir_source.txt'),(Join-Path $root 'mkdir_denied_dir') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'open_create_denied.txt'),(Join-Path $root 'open_create_allowed_dir'),(Join-Path $root 'open_create_fixture.txt') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'open_trunc_target.txt'),(Join-Path $root 'open_trunc_allowed_dir') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'open_append_target.txt'),(Join-Path $root 'open_append_allowed_dir') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'open_write_denied.txt'),(Join-Path $root 'open_write_allowed_dir'),(Join-Path $root 'open_write_fixture.txt') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'open_read_allowed.txt'),(Join-Path $root 'open_read_allowed_dir'),(Join-Path $root 'open_read_fixture.txt') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'read_op_uploaded.txt'),(Join-Path $root 'read_op_allowed_dir'),(Join-Path $root 'read_op_fixture.txt') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'stat_op_source.txt'),(Join-Path $root 'stat_op_allowed_dir') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'fstat_op_source.txt'),(Join-Path $root 'fstat_op_allowed_dir') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'fsetstat_op_target.txt'),(Join-Path $root 'fsetstat_op_fixture.txt'),(Join-Path $root 'fsetstat_op_allowed_dir') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'fsync_op_target.txt'),(Join-Path $root 'fsync_op_fixture.txt'),(Join-Path $root 'fsync_op_allowed_dir') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'statvfs_op_source.txt'),(Join-Path $root 'statvfs_op_allowed_dir') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'opendir_op_source.txt') -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'readdir_op_source.txt') -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $root 'write_op_denied.txt'),(Join-Path $root 'write_op_allowed_dir'),(Join-Path $root 'write_op_fixture.txt') -Recurse -Force -ErrorAction SilentlyContinue

function New-InteropKey {
    param(
        [string]$Path,
        [string]$Type
    )

    if (Test-Path $Path) {
        return
    }

    if ($Type -eq 'rsa') {
        $cmd = 'ssh-keygen.exe -q -t rsa -b 2048 -N "" -f "' + $Path + '"'
    } elseif ($Type -eq 'ed25519') {
        $cmd = 'ssh-keygen.exe -q -t ed25519 -N "" -f "' + $Path + '"'
    } else {
        $cmd = 'ssh-keygen.exe -q -t ecdsa -b 256 -N "" -f "' + $Path + '"'
    }
    cmd.exe /c $cmd
    if ($LASTEXITCODE -ne 0) {
        throw "ssh-keygen failed with exit code $LASTEXITCODE"
    }
}

if ($AuthMode -eq 'publickey') {
    New-InteropKey -Path $clientKey -Type $KeyType
    New-InteropKey -Path $decoyKey -Type $KeyType

    $decoyPubLine = [string](Get-Content -LiteralPath $decoyPub | Select-Object -First 1)
    $clientPubLine = [string](Get-Content -LiteralPath $clientPub | Select-Object -First 1)
    if ($FromPattern -eq '') {
        $FromPattern = if ($DenyFrom) { '*,!127.0.0.1' } else { '127.0.0.1' }
    }
    $authorizedOptions = @('no-port-forwarding', 'no-agent-forwarding')
    if ($ReadOnly) {
        $authorizedOptions += 'emssh-readonly'
    }
    if ($PathPrefix -ne '') {
        $pathPrefixList = @(
            $PathPrefix.Split(',') |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne '' }
        )
        if ($pathPrefixList.Count -eq 0) {
            throw 'PathPrefix list must contain at least one non-empty entry'
        }
        $authorizedOptions += "emssh-path-prefix=`"$PathPrefix`""
    }
    if ($MaxWriteEnd -ne '') {
        $authorizedOptions += "emssh-max-write-end=$MaxWriteEnd"
    }
    if ($MaxReadEnd -ne '') {
        $authorizedOptions += "emssh-max-read-end=$MaxReadEnd"
    }
    if ($DenyNonSftpChannel) {
        $authorizedOptions += 'emssh-deny-non-sftp-channel'
    }
    if ($DenyRename) {
        $authorizedOptions += 'emssh-deny-rename'
    }
    if ($DenyDelete) {
        $authorizedOptions += 'emssh-deny-delete'
    }
    if ($DenySetstat) {
        $authorizedOptions += 'emssh-deny-setstat'
    }
    if ($DenyCreate) {
        $authorizedOptions += 'emssh-deny-create'
    }
    if ($DenyHardlink) {
        $authorizedOptions += 'emssh-deny-hardlink'
    }
    if ($DenyRemove) {
        $authorizedOptions += 'emssh-deny-remove'
    }
    if ($DenyRmdir) {
        $authorizedOptions += 'emssh-deny-rmdir'
    }
    if ($DenyMkdir) {
        $authorizedOptions += 'emssh-deny-mkdir'
    }
    if ($DenyOpenCreate) {
        $authorizedOptions += 'emssh-deny-open-create'
    }
    if ($DenyOpenTrunc) {
        $authorizedOptions += 'emssh-deny-open-trunc'
    }
    if ($DenyOpenAppend) {
        $authorizedOptions += 'emssh-deny-open-append'
    }
    if ($DenyOpenWrite) {
        $authorizedOptions += 'emssh-deny-open-write'
    }
    if ($DenyOpenRead) {
        $authorizedOptions += 'emssh-deny-open-read'
    }
    if ($DenyRead) {
        $authorizedOptions += 'emssh-deny-read'
    }
    if ($DenyRealpath) {
        $authorizedOptions += 'emssh-deny-realpath'
    }
    if ($DenyStat) {
        $authorizedOptions += 'emssh-deny-stat'
    }
    if ($DenyFstat) {
        $authorizedOptions += 'emssh-deny-fstat'
    }
    if ($DenyFsetstat) {
        $authorizedOptions += 'emssh-deny-fsetstat'
    }
    if ($DenyFsync) {
        $authorizedOptions += 'emssh-deny-fsync'
    }
    if ($DenyStatvfs) {
        $authorizedOptions += 'emssh-deny-statvfs'
    }
    if ($DenyOpendir) {
        $authorizedOptions += 'emssh-deny-opendir'
    }
    if ($DenyReaddir) {
        $authorizedOptions += 'emssh-deny-readdir'
    }
    if ($DenyWrite) {
        $authorizedOptions += 'emssh-deny-write'
    }
    $authorizedOptions += "from=`"$FromPattern`""
    @(
        '# authorized_keys parser coverage: comment line',
        '',
        "$decoyPubLine decoy-key",
        '   # indented comment line',
        "$($authorizedOptions -join ',') $clientPubLine actual-key-with-options"
    ) | Set-Content -LiteralPath $authorizedKeys -Encoding ASCII
}

Set-Content -LiteralPath $upload -Value "emssh-openssh-sftp-$AuthMode-interop" -NoNewline -Encoding ASCII
if ($ReadOnly) {
    Set-Content -LiteralPath (Join-Path $root 'readonly.txt') -Value 'emssh-readonly-fixture' -NoNewline -Encoding ASCII
    @(
        'pwd',
        'ls',
        "-put `"$upload`" uploaded.txt",
        'ls',
        "get readonly.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($PathPrefix -ne '') {
    $batchLines = @("-put `"$upload`" uploaded.txt")
    for ($i = 0; $i -lt $pathPrefixList.Count; $i++) {
        $prefix = $pathPrefixList[$i]
        $allowedDir = Join-Path $root $prefix
        $remoteName = "$prefix/uploaded_$i.txt"
        $localDownload = if ($i -eq 0) { $download } else { "$download.$i" }
        New-Item -ItemType Directory -Force -Path $allowedDir | Out-Null
        $batchLines += "put `"$upload`" $remoteName"
        $batchLines += "get $remoteName `"$localDownload`""
    }
    $batchLines += 'bye'
    $batchLines | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($MaxWriteEnd -ne '') {
    Set-Content -LiteralPath (Join-Path $root 'max_write_fixture.txt') -Value 'emssh-max-write-fixture' -NoNewline -Encoding ASCII
    @(
        "-put `"$upload`" max_write_limited.txt",
        "get max_write_fixture.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($MaxReadEnd -ne '') {
    $maxReadSourcePath = Join-Path $root 'max_read_source.txt'
    $maxReadSourceContent = [string]::new('A', 9000)
    Set-Content -LiteralPath $maxReadSourcePath -Value $maxReadSourceContent -NoNewline -Encoding ASCII
    @(
        "-get max_read_source.txt `"$downloadLarge`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyRename) {
    @(
        "put `"$upload`" rename_source.txt",
        "-rename rename_source.txt rename_target.txt",
        "get rename_source.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyDelete) {
    @(
        "put `"$upload`" delete_source.txt",
        "mkdir delete_dir",
        "-rm delete_source.txt",
        "-rmdir delete_dir",
        "get delete_source.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenySetstat) {
    @(
        "put `"$upload`" setstat_source.txt",
        "-chmod 600 setstat_source.txt",
        "get setstat_source.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyCreate) {
    Set-Content -LiteralPath (Join-Path $root 'create_fixture.txt') -Value 'create-fixture' -NoNewline -Encoding ASCII
    @(
        "-put `"$upload`" create_denied.txt",
        "-mkdir create_dir",
        "get create_fixture.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyHardlink) {
    @(
        "put `"$upload`" hardlink_source.txt",
        "-ln hardlink_source.txt hardlink_target.txt",
        "get hardlink_source.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyRemove) {
    @(
        "put `"$upload`" remove_source.txt",
        "-rm remove_source.txt",
        "get remove_source.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyRmdir) {
    @(
        "put `"$upload`" rmdir_source.txt",
        "mkdir rmdir_dir",
        "-rmdir rmdir_dir",
        "get rmdir_source.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyMkdir) {
    @(
        "put `"$upload`" mkdir_source.txt",
        "-mkdir mkdir_denied_dir",
        "get mkdir_source.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyOpenCreate) {
    Set-Content -LiteralPath (Join-Path $root 'open_create_fixture.txt') -Value 'open-create-fixture' -NoNewline -Encoding ASCII
    @(
        "-put `"$upload`" open_create_denied.txt",
        "mkdir open_create_allowed_dir",
        "get open_create_fixture.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyOpenTrunc) {
    Set-Content -LiteralPath (Join-Path $root 'open_trunc_target.txt') -Value 'open-trunc-fixture' -NoNewline -Encoding ASCII
    @(
        "-put `"$upload`" open_trunc_target.txt",
        "mkdir open_trunc_allowed_dir",
        "get open_trunc_target.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyOpenAppend) {
    Set-Content -LiteralPath (Join-Path $root 'open_append_target.txt') -Value 'open-append-fixture' -NoNewline -Encoding ASCII
    @(
        "-put -a `"$upload`" open_append_target.txt",
        "mkdir open_append_allowed_dir",
        "get open_append_target.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyOpenWrite) {
    Set-Content -LiteralPath (Join-Path $root 'open_write_fixture.txt') -Value 'open-write-fixture' -NoNewline -Encoding ASCII
    @(
        "-put `"$upload`" open_write_denied.txt",
        "mkdir open_write_allowed_dir",
        "get open_write_fixture.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyOpenRead) {
    Set-Content -LiteralPath (Join-Path $root 'open_read_fixture.txt') -Value 'open-read-fixture' -NoNewline -Encoding ASCII
    @(
        "put `"$upload`" open_read_allowed.txt",
        "-get open_read_fixture.txt `"$download`"",
        "mkdir open_read_allowed_dir",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyRead) {
    Set-Content -LiteralPath (Join-Path $root 'read_op_fixture.txt') -Value 'read-op-fixture' -NoNewline -Encoding ASCII
    @(
        "put `"$upload`" read_op_uploaded.txt",
        "-get read_op_fixture.txt `"$download`"",
        "mkdir read_op_allowed_dir",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyRealpath) {
    @(
        '-pwd',
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyStat) {
    @(
        "put `"$upload`" stat_op_source.txt",
        "-ls stat_op_source.txt",
        "mkdir stat_op_allowed_dir",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyFstat) {
    @(
        "put `"$upload`" fstat_op_source.txt",
        "-get fstat_op_source.txt `"$download`"",
        "mkdir fstat_op_allowed_dir",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyFsetstat) {
    Set-Content -LiteralPath (Join-Path $root 'fsetstat_op_fixture.txt') -Value 'fsetstat-op-fixture' -NoNewline -Encoding ASCII
    @(
        "-put -P `"$upload`" fsetstat_op_target.txt",
        "mkdir fsetstat_op_allowed_dir",
        "get fsetstat_op_fixture.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyFsync) {
    Set-Content -LiteralPath (Join-Path $root 'fsync_op_fixture.txt') -Value 'fsync-op-fixture' -NoNewline -Encoding ASCII
    @(
        "-put -f `"$upload`" fsync_op_target.txt",
        "mkdir fsync_op_allowed_dir",
        "get fsync_op_fixture.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyStatvfs) {
    @(
        "put `"$upload`" statvfs_op_source.txt",
        '-df .',
        "mkdir statvfs_op_allowed_dir",
        "get statvfs_op_source.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyOpendir) {
    @(
        "put `"$upload`" opendir_op_source.txt",
        '-ls',
        "get opendir_op_source.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyReaddir) {
    @(
        "put `"$upload`" readdir_op_source.txt",
        '-ls',
        "get readdir_op_source.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} elseif ($DenyWrite) {
    Set-Content -LiteralPath (Join-Path $root 'write_op_fixture.txt') -Value 'write-op-fixture' -NoNewline -Encoding ASCII
    @(
        "-put `"$upload`" write_op_denied.txt",
        "mkdir write_op_allowed_dir",
        "get write_op_fixture.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
} else {
    @(
        'pwd',
        'ls',
        "put `"$upload`" uploaded.txt",
        'ls',
        "get uploaded.txt `"$download`"",
        'bye'
    ) | Set-Content -LiteralPath $batch -Encoding ASCII
}

$serverArgs = @($Port, $root, 'alice', 'secret', $hostKey)
if ($AuthMode -eq 'publickey') {
    $serverArgs += $authorizedKeys
}
if ($ServerMaxConnections -ne 1) {
    $serverArgs += @('--max-connections', [string]$ServerMaxConnections)
}
$serverArgs += @('--hostkey-algorithm', $ServerHostKeyAlgorithm)

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
        if ($ServerHostKeyAlgorithm -eq 'ed25519' -and $hostkeyProbe -eq $null -and $serverErrText -match 'hostkey setup failed: (unsupported|platform error)') {
            Write-Output 'OpenSSH SFTP ed25519 hostkey interop skipped (platform does not support Ed25519 hostkey)'
            return
        }
        if ($serverErrText -eq '') {
            throw 'server exited before client started'
        }
        throw "server exited before client started: $serverErrText"
    }
    if ($AuthMode -eq 'publickey' -and $KeyType -eq 'ed25519') {
        $serverErrText = if (Test-Path $serverErr) { Get-Content -LiteralPath $serverErr -Raw } else { '' }
        if ($publickeyProbe -eq $null -and $serverErrText -match 'ed25519 publickey verify unsupported on this crypto backend') {
            Write-Output 'OpenSSH SFTP ed25519 publickey interop skipped (platform does not support Ed25519 publickey verify)'
            return
        }
    }
    if ($AuthMode -eq 'password') {
        Set-Content -LiteralPath $askpass -Value @('@echo off', 'echo secret') -Encoding ASCII
        $env:SSH_ASKPASS = $askpass
        $env:SSH_ASKPASS_REQUIRE = 'force'
        $env:DISPLAY = 'emssh'
    }

    for ($round = 1; $round -le $RepeatCount; $round++) {
        Remove-Item -LiteralPath $download,$downloadLarge,(Join-Path $root 'uploaded.txt') -ErrorAction SilentlyContinue
        Remove-Item -Path "$download.*" -ErrorAction SilentlyContinue
        Set-Content -LiteralPath $upload -Value "emssh-openssh-sftp-$AuthMode-interop-$round" -NoNewline -Encoding ASCII

        if ($DenyNonSftpChannel) {
            $sshArgs = @(
                '-p', [string]$Port,
                '-i', $clientKey,
                '-o', 'BatchMode=yes',
                '-o', 'PreferredAuthentications=publickey',
                '-o', 'PasswordAuthentication=no',
                '-o', 'StrictHostKeyChecking=no',
                '-o', "UserKnownHostsFile=$known",
                'alice@127.0.0.1',
                'echo non-sftp-request'
            )
            $ssh = Start-Process -FilePath 'ssh.exe' `
                -ArgumentList $sshArgs `
                -RedirectStandardOutput $sshOut `
                -RedirectStandardError $sshErr `
                -WindowStyle Hidden `
                -PassThru
            if (-not $ssh.WaitForExit(10000)) {
                Stop-Process -Id $ssh.Id -Force
                throw 'ssh non-sftp request timed out'
            }
            $ssh.Refresh()
            if ($null -ne $ssh.ExitCode -and $ssh.ExitCode -eq 0) {
                throw 'non-sftp channel request unexpectedly succeeded'
            }
        }

        $sftpArgs = @('-P', [string]$Port)
        if ($AuthMode -eq 'publickey') {
            $sftpArgs += @(
                '-i', $clientKey,
                '-o', 'BatchMode=yes',
                '-o', 'PreferredAuthentications=publickey',
                '-o', 'PasswordAuthentication=no'
            )
            if ($ForceSshRsaSha1) {
                $sftpArgs += @(
                    '-o', 'PubkeyAcceptedAlgorithms=ssh-rsa'
                )
            }
        } else {
            $sftpArgs += @(
                '-o', 'BatchMode=no',
                '-o', 'PreferredAuthentications=password',
                '-o', 'PubkeyAuthentication=no',
                '-o', 'NumberOfPasswordPrompts=1'
            )
        }
        $sftpArgs += @(
            '-o', 'StrictHostKeyChecking=no',
            '-o', "UserKnownHostsFile=$known",
            '-b', $batch,
            'alice@127.0.0.1'
        )
        $client = Start-Process -FilePath 'sftp.exe' `
            -ArgumentList $sftpArgs `
            -RedirectStandardOutput $sftpOut `
            -RedirectStandardError $sftpErr `
            -WindowStyle Hidden `
            -PassThru

        if (-not $client.WaitForExit(20000)) {
            Stop-Process -Id $client.Id -Force
            throw 'sftp timed out'
        }
        $client.Refresh()
        if ($DenyFrom) {
            if (Test-Path $download) {
                throw 'sftp unexpectedly transferred data with denied from= option'
            }
            Write-Output 'OpenSSH SFTP publickey from= deny interop passed'
            return
        }
        $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
        $serverErrText = if (Test-Path $serverErr) { Get-Content -LiteralPath $serverErr -Raw } else { '' }
        if ($AuthMode -eq 'publickey' -and $KeyType -eq 'ed25519' -and
            $publickeyProbe -eq $null -and
            -not (Test-Path $download) -and
            $sftpErrText -match 'Permission denied \(publickey,password\)' -and
            $serverErrText -match '(ed25519 publickey verify unsupported|platform error|unsupported|not support)') {
            Write-Output 'OpenSSH SFTP ed25519 publickey interop skipped (platform does not support Ed25519 publickey verify)'
            return
        }
        if ($ForceSshRsaSha1) {
            if ($null -ne $client.ExitCode -and $client.ExitCode -eq 0) {
                throw 'ssh-rsa(SHA-1) publickey auth unexpectedly succeeded'
            }
            if ($sftpErrText -notmatch 'Permission denied \(publickey,password\)' -and
                $sftpErrText -notmatch 'no mutual signature algorithm' -and
                $sftpErrText -notmatch 'no mutual signature supported') {
                throw "unexpected ssh-rsa(SHA-1) failure text: $sftpErrText"
            }
            Write-Output 'OpenSSH SFTP publickey ssh-rsa(signature=SHA-1) denied interop passed'
            return
        }
        if ($null -ne $client.ExitCode -and $client.ExitCode -ne 0) {
            throw "sftp failed with exit code $($client.ExitCode)"
        }

        if ($ReadOnly) {
            $readonlyServerFile = Join-Path $root 'readonly.txt'
            if (Test-Path (Join-Path $root 'uploaded.txt')) {
                throw 'read-only session unexpectedly created uploaded.txt'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $readonlyServerFile).Hash -ne (Get-FileHash $download).Hash) {
                throw 'read-only download hash mismatch'
            }
        } elseif ($PathPrefix -ne '') {
            if (Test-Path (Join-Path $root 'uploaded.txt')) {
                throw 'path-prefix session unexpectedly created uploaded.txt'
            }
            for ($i = 0; $i -lt $pathPrefixList.Count; $i++) {
                $prefix = $pathPrefixList[$i]
                $remotePath = Join-Path $root "$prefix/uploaded_$i.txt"
                $localDownload = if ($i -eq 0) { $download } else { "$download.$i" }
                if (-not (Test-Path $remotePath)) {
                    throw "path-prefix session missing allowed uploaded file at $prefix"
                }
                if (-not (Test-Path $localDownload)) {
                    throw "path-prefix session missing downloaded file for $prefix"
                }
                if ((Get-FileHash $upload).Hash -ne (Get-FileHash $localDownload).Hash) {
                    throw "path-prefix download hash mismatch for $prefix"
                }
            }
        } elseif ($MaxWriteEnd -ne '') {
            $fixture = Join-Path $root 'max_write_fixture.txt'
            $limited = Join-Path $root 'max_write_limited.txt'
            [UInt64]$limit = [UInt64]$MaxWriteEnd
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $fixture).Hash -ne (Get-FileHash $download).Hash) {
                throw 'max-write fixture download hash mismatch'
            }
            if (Test-Path $limited) {
                $limitedLen = [UInt64](Get-Item $limited).Length
                if ($limitedLen -gt $limit) {
                    throw "max-write policy not enforced: file size $limitedLen exceeds limit $limit"
                }
            }
        } elseif ($MaxReadEnd -ne '') {
            $source = Join-Path $root 'max_read_source.txt'
            [UInt64]$limit = [UInt64]$MaxReadEnd
            if (-not (Test-Path $source)) {
                throw 'max-read source file missing'
            }
            $sourceLen = [UInt64](Get-Item $source).Length
            if ($sourceLen -le $limit) {
                throw "max-read test source is too small: $sourceLen <= $limit"
            }
            if (Test-Path $downloadLarge) {
                $largeLen = [UInt64](Get-Item $downloadLarge).Length
                if ($largeLen -gt $limit) {
                    throw "max-read policy not enforced: downloaded size $largeLen exceeds limit $limit"
                }
            }
        } elseif ($DenyRename) {
            $source = Join-Path $root 'rename_source.txt'
            $target = Join-Path $root 'rename_target.txt'
            if (-not (Test-Path $source)) {
                throw 'deny-rename session missing source file after rename attempt'
            }
            if (Test-Path $target) {
                throw 'deny-rename session unexpectedly created rename target file'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-rename download hash mismatch'
            }
        } elseif ($DenyDelete) {
            $source = Join-Path $root 'delete_source.txt'
            $dir = Join-Path $root 'delete_dir'
            if (-not (Test-Path $source)) {
                throw 'deny-delete session unexpectedly removed source file'
            }
            if (-not (Test-Path $dir)) {
                throw 'deny-delete session unexpectedly removed directory'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-delete download hash mismatch'
            }
        } elseif ($DenySetstat) {
            $source = Join-Path $root 'setstat_source.txt'
            if (-not (Test-Path $source)) {
                throw 'deny-setstat session missing source file'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-setstat download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-setstat scenario did not observe permission-denied error'
            }
        } elseif ($DenyCreate) {
            $fixture = Join-Path $root 'create_fixture.txt'
            $createdFile = Join-Path $root 'create_denied.txt'
            $createdDir = Join-Path $root 'create_dir'
            if (Test-Path $createdFile) {
                throw 'deny-create session unexpectedly created file'
            }
            if (Test-Path $createdDir) {
                throw 'deny-create session unexpectedly created directory'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $fixture).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-create download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-create scenario did not observe permission-denied error'
            }
        } elseif ($DenyHardlink) {
            $source = Join-Path $root 'hardlink_source.txt'
            $target = Join-Path $root 'hardlink_target.txt'
            if (-not (Test-Path $source)) {
                throw 'deny-hardlink session missing source file'
            }
            if (Test-Path $target) {
                throw 'deny-hardlink session unexpectedly created hardlink target'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-hardlink download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-hardlink scenario did not observe permission-denied error'
            }
        } elseif ($DenyRemove) {
            $source = Join-Path $root 'remove_source.txt'
            if (-not (Test-Path $source)) {
                throw 'deny-remove session unexpectedly removed source file'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-remove download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-remove scenario did not observe permission-denied error'
            }
        } elseif ($DenyRmdir) {
            $source = Join-Path $root 'rmdir_source.txt'
            $dir = Join-Path $root 'rmdir_dir'
            if (-not (Test-Path $source)) {
                throw 'deny-rmdir session missing source file'
            }
            if (-not (Test-Path $dir)) {
                throw 'deny-rmdir session unexpectedly removed directory'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-rmdir download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-rmdir scenario did not observe permission-denied error'
            }
        } elseif ($DenyMkdir) {
            $source = Join-Path $root 'mkdir_source.txt'
            $dir = Join-Path $root 'mkdir_denied_dir'
            if (-not (Test-Path $source)) {
                throw 'deny-mkdir session missing source file'
            }
            if (Test-Path $dir) {
                throw 'deny-mkdir session unexpectedly created directory'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-mkdir download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-mkdir scenario did not observe permission-denied error'
            }
        } elseif ($DenyOpenCreate) {
            $fixture = Join-Path $root 'open_create_fixture.txt'
            $createdFile = Join-Path $root 'open_create_denied.txt'
            $allowedDir = Join-Path $root 'open_create_allowed_dir'
            if (Test-Path $createdFile) {
                throw 'deny-open-create session unexpectedly created file'
            }
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-open-create session failed to create allowed directory'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $fixture).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-open-create download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-open-create scenario did not observe permission-denied error'
            }
        } elseif ($DenyOpenTrunc) {
            $target = Join-Path $root 'open_trunc_target.txt'
            $allowedDir = Join-Path $root 'open_trunc_allowed_dir'
            if (-not (Test-Path $target)) {
                throw 'deny-open-trunc session missing target file'
            }
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-open-trunc session failed to create allowed directory'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-Content -LiteralPath $download -Raw) -ne 'open-trunc-fixture') {
                throw 'deny-open-trunc download content mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-open-trunc scenario did not observe permission-denied error'
            }
        } elseif ($DenyOpenAppend) {
            $target = Join-Path $root 'open_append_target.txt'
            $allowedDir = Join-Path $root 'open_append_allowed_dir'
            if (-not (Test-Path $target)) {
                throw 'deny-open-append session missing target file'
            }
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-open-append session failed to create allowed directory'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-Content -LiteralPath $download -Raw) -ne 'open-append-fixture') {
                throw 'deny-open-append download content mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-open-append scenario did not observe permission-denied error'
            }
        } elseif ($DenyOpenWrite) {
            $fixture = Join-Path $root 'open_write_fixture.txt'
            $createdFile = Join-Path $root 'open_write_denied.txt'
            $allowedDir = Join-Path $root 'open_write_allowed_dir'
            if (Test-Path $createdFile) {
                throw 'deny-open-write session unexpectedly created file'
            }
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-open-write session failed to create allowed directory'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $fixture).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-open-write download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-open-write scenario did not observe permission-denied error'
            }
        } elseif ($DenyOpenRead) {
            $allowedFile = Join-Path $root 'open_read_allowed.txt'
            $allowedDir = Join-Path $root 'open_read_allowed_dir'
            if (-not (Test-Path $allowedFile)) {
                throw 'deny-open-read session failed to create allowed file'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $allowedFile).Hash) {
                throw 'deny-open-read allowed file hash mismatch'
            }
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-open-read session failed to create allowed directory'
            }
            if (Test-Path $download) {
                throw 'deny-open-read scenario unexpectedly downloaded file'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-open-read scenario did not observe permission-denied error'
            }
        } elseif ($DenyRead) {
            $uploaded = Join-Path $root 'read_op_uploaded.txt'
            $allowedDir = Join-Path $root 'read_op_allowed_dir'
            if (-not (Test-Path $uploaded)) {
                throw 'deny-read session missing uploaded file'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $uploaded).Hash) {
                throw 'deny-read uploaded file hash mismatch'
            }
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-read session failed to create allowed directory'
            }
            if (Test-Path $download) {
                if ((Get-Item -LiteralPath $download).Length -ne 0) {
                    throw 'deny-read scenario unexpectedly downloaded non-empty file'
                }
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-read scenario did not observe permission-denied error'
            }
        } elseif ($DenyWrite) {
            $target = Join-Path $root 'write_op_denied.txt'
            $allowedDir = Join-Path $root 'write_op_allowed_dir'
            $fixture = Join-Path $root 'write_op_fixture.txt'
            if (Test-Path $target) {
                if ((Get-Item -LiteralPath $target).Length -ne 0) {
                    throw 'deny-write scenario unexpectedly wrote non-empty target file'
                }
            }
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-write session failed to create allowed directory'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $fixture).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-write download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-write scenario did not observe permission-denied error'
            }
        } elseif ($DenyStat) {
            $source = Join-Path $root 'stat_op_source.txt'
            $allowedDir = Join-Path $root 'stat_op_allowed_dir'
            if (-not (Test-Path $source)) {
                throw 'deny-stat session missing source file'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $source).Hash) {
                throw 'deny-stat uploaded file hash mismatch'
            }
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-stat session failed to create allowed directory'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch '(Permission denied|not found)') {
                throw 'deny-stat scenario did not observe expected ls failure'
            }
        } elseif ($DenyRealpath) {
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch '(Permission denied|canonicali[sz]e|Couldn''t canonicali[sz]e|not found|realpath denied|Need cwd)') {
                throw 'deny-realpath scenario did not observe expected realpath failure'
            }
        } elseif ($DenyFstat) {
            $source = Join-Path $root 'fstat_op_source.txt'
            $allowedDir = Join-Path $root 'fstat_op_allowed_dir'
            if (-not (Test-Path $source)) {
                throw 'deny-fstat session missing source file'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $source).Hash) {
                throw 'deny-fstat uploaded file hash mismatch'
            }
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-fstat session failed to create allowed directory'
            }
            if (Test-Path $download) {
                if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                    throw 'deny-fstat download hash mismatch'
                }
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if (-not (Test-Path $download) -and $sftpErrText -notmatch '(Permission denied|not found)') {
                throw 'deny-fstat scenario neither downloaded file nor observed expected get failure'
            }
        } elseif ($DenyFsetstat) {
            $target = Join-Path $root 'fsetstat_op_target.txt'
            $fixture = Join-Path $root 'fsetstat_op_fixture.txt'
            $allowedDir = Join-Path $root 'fsetstat_op_allowed_dir'
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-fsetstat session failed to create allowed directory'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $fixture).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-fsetstat download hash mismatch'
            }
            if (Test-Path $target) {
                if ((Get-FileHash $upload).Hash -ne (Get-FileHash $target).Hash) {
                    throw 'deny-fsetstat uploaded target hash mismatch'
                }
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch '(Permission denied|failure|fsetstat|setstat)') {
                throw 'deny-fsetstat scenario did not observe expected fsetstat failure'
            }
        } elseif ($DenyFsync) {
            $target = Join-Path $root 'fsync_op_target.txt'
            $fixture = Join-Path $root 'fsync_op_fixture.txt'
            $allowedDir = Join-Path $root 'fsync_op_allowed_dir'
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $fixture).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-fsync download hash mismatch'
            }
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-fsync session failed to create allowed directory'
            }
            if (Test-Path $target) {
                if ((Get-FileHash $upload).Hash -ne (Get-FileHash $target).Hash) {
                    throw 'deny-fsync uploaded target hash mismatch'
                }
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch '(Permission denied|failure|fsync)') {
                throw 'deny-fsync scenario did not observe expected fsync failure'
            }
        } elseif ($DenyStatvfs) {
            $source = Join-Path $root 'statvfs_op_source.txt'
            $allowedDir = Join-Path $root 'statvfs_op_allowed_dir'
            if (-not (Test-Path $source)) {
                throw 'deny-statvfs session missing source file'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $source).Hash) {
                throw 'deny-statvfs uploaded source hash mismatch'
            }
            if (-not (Test-Path $allowedDir)) {
                throw 'deny-statvfs session failed to create allowed directory'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-statvfs download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            $sftpOutText = if (Test-Path $sftpOut) { Get-Content -LiteralPath $sftpOut -Raw } else { '' }
            if ($sftpOutText -match '(?im)\\bsize\\b\\s+\\bused\\b.*\\bavail\\b') {
                throw 'deny-statvfs scenario unexpectedly succeeded in df/statvfs output'
            }
            if ($sftpErrText -ne '' -and $sftpErrText -notmatch '(statvfs|Permission denied|failure|Connection to)') {
                throw 'deny-statvfs scenario observed unexpected stderr text'
            }
        } elseif ($DenyOpendir) {
            $source = Join-Path $root 'opendir_op_source.txt'
            if (-not (Test-Path $source)) {
                throw 'deny-opendir session missing source file'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-opendir download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-opendir scenario did not observe permission-denied error'
            }
        } elseif ($DenyReaddir) {
            $source = Join-Path $root 'readdir_op_source.txt'
            if (-not (Test-Path $source)) {
                throw 'deny-readdir session missing source file'
            }
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                throw 'deny-readdir download hash mismatch'
            }
            $sftpErrText = if (Test-Path $sftpErr) { Get-Content -LiteralPath $sftpErr -Raw } else { '' }
            if ($sftpErrText -notmatch 'Permission denied') {
                throw 'deny-readdir scenario did not observe permission-denied error'
            }
        } else {
            if (-not (Test-Path $download)) {
                throw 'downloaded file missing'
            }
            if ((Get-FileHash $upload).Hash -ne (Get-FileHash $download).Hash) {
                throw 'downloaded file hash mismatch'
            }
        }
    }

    if ($ReadOnly) {
        Write-Output 'OpenSSH SFTP publickey read-only interop passed'
        return
    }
    if ($PathPrefix -ne '') {
        Write-Output 'OpenSSH SFTP publickey path-prefix interop passed'
        return
    }
    if ($MaxWriteEnd -ne '') {
        Write-Output 'OpenSSH SFTP publickey max-write-end interop passed'
        return
    }
    if ($MaxReadEnd -ne '') {
        Write-Output 'OpenSSH SFTP publickey max-read-end interop passed'
        return
    }
    if ($DenyRename) {
        Write-Output 'OpenSSH SFTP publickey deny-rename interop passed'
        return
    }
    if ($DenyDelete) {
        Write-Output 'OpenSSH SFTP publickey deny-delete interop passed'
        return
    }
    if ($DenySetstat) {
        Write-Output 'OpenSSH SFTP publickey deny-setstat interop passed'
        return
    }
    if ($DenyCreate) {
        Write-Output 'OpenSSH SFTP publickey deny-create interop passed'
        return
    }
    if ($DenyHardlink) {
        Write-Output 'OpenSSH SFTP publickey deny-hardlink interop passed'
        return
    }
    if ($DenyRemove) {
        Write-Output 'OpenSSH SFTP publickey deny-remove interop passed'
        return
    }
    if ($DenyRmdir) {
        Write-Output 'OpenSSH SFTP publickey deny-rmdir interop passed'
        return
    }
    if ($DenyMkdir) {
        Write-Output 'OpenSSH SFTP publickey deny-mkdir interop passed'
        return
    }
    if ($DenyOpenCreate) {
        Write-Output 'OpenSSH SFTP publickey deny-open-create interop passed'
        return
    }
    if ($DenyOpenTrunc) {
        Write-Output 'OpenSSH SFTP publickey deny-open-trunc interop passed'
        return
    }
    if ($DenyOpenAppend) {
        Write-Output 'OpenSSH SFTP publickey deny-open-append interop passed'
        return
    }
    if ($DenyOpenWrite) {
        Write-Output 'OpenSSH SFTP publickey deny-open-write interop passed'
        return
    }
    if ($DenyOpenRead) {
        Write-Output 'OpenSSH SFTP publickey deny-open-read interop passed'
        return
    }
    if ($DenyRead) {
        Write-Output 'OpenSSH SFTP publickey deny-read interop passed'
        return
    }
    if ($DenyRealpath) {
        Write-Output 'OpenSSH SFTP publickey deny-realpath interop passed'
        return
    }
    if ($DenyWrite) {
        Write-Output 'OpenSSH SFTP publickey deny-write interop passed'
        return
    }
    if ($DenyStat) {
        Write-Output 'OpenSSH SFTP publickey deny-stat interop passed'
        return
    }
    if ($DenyFstat) {
        Write-Output 'OpenSSH SFTP publickey deny-fstat interop passed'
        return
    }
    if ($DenyFsetstat) {
        Write-Output 'OpenSSH SFTP publickey deny-fsetstat interop passed'
        return
    }
    if ($DenyFsync) {
        Write-Output 'OpenSSH SFTP publickey deny-fsync interop passed'
        return
    }
    if ($DenyStatvfs) {
        Write-Output 'OpenSSH SFTP publickey deny-statvfs interop passed'
        return
    }
    if ($DenyOpendir) {
        Write-Output 'OpenSSH SFTP publickey deny-opendir interop passed'
        return
    }
    if ($DenyReaddir) {
        Write-Output 'OpenSSH SFTP publickey deny-readdir interop passed'
        return
    }
    if ($DenyNonSftpChannel) {
        Write-Output 'OpenSSH SFTP publickey deny-non-sftp-channel interop passed'
        return
    }
    Write-Output "OpenSSH SFTP $AuthMode interop passed ($RepeatCount connection(s))"
} finally {
    if ($AuthMode -eq 'password') {
        if ($null -eq $oldAskpass) {
            Remove-Item Env:\SSH_ASKPASS -ErrorAction SilentlyContinue
        } else {
            $env:SSH_ASKPASS = $oldAskpass
        }
        if ($null -eq $oldAskpassRequire) {
            Remove-Item Env:\SSH_ASKPASS_REQUIRE -ErrorAction SilentlyContinue
        } else {
            $env:SSH_ASKPASS_REQUIRE = $oldAskpassRequire
        }
        if ($null -eq $oldDisplay) {
            Remove-Item Env:\DISPLAY -ErrorAction SilentlyContinue
        } else {
            $env:DISPLAY = $oldDisplay
        }
        Remove-Item -LiteralPath $askpass -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500
    if ($server -and -not $server.HasExited) {
        if (-not $server.WaitForExit(3000)) {
            Stop-Process -Id $server.Id -Force
        }
    }
}
