#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,

    [string]$Label = 'windows'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('127.0.0.1'), 0)
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Wait-TcpPort {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$Attempts = 120,
        [int]$DelayMilliseconds = 500
    )

    for ($i = 0; $i -lt $Attempts; ++$i) {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $connect = $client.ConnectAsync('127.0.0.1', $Port)
            if ($connect.Wait($DelayMilliseconds) -and $client.Connected) {
                return
            }
        } catch {
        } finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds $DelayMilliseconds
    }

    throw "TCP port $Port did not open in time."
}

function Wait-PanelJson {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [string]$Description = $Uri,
        [int]$Attempts = 120,
        [int]$DelayMilliseconds = 500
    )

    $lastError = $null
    for ($i = 0; $i -lt $Attempts; ++$i) {
        try {
            return Invoke-RestMethod -Uri $Uri -TimeoutSec 3
        } catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Milliseconds $DelayMilliseconds
        }
    }

    throw "Panel endpoint '$Description' did not respond in time. Last error: $lastError"
}

function Write-LogTail {
    param([Parameter(Mandatory = $true)][string]$Directory)

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        return
    }

    Get-ChildItem -LiteralPath $Directory -File -ErrorAction SilentlyContinue |
        Sort-Object Name |
        ForEach-Object {
            Write-Host "--- $($_.FullName) ---"
            Get-Content -LiteralPath $_.FullName -Tail 120 -ErrorAction SilentlyContinue
        }
}

function Invoke-SshSessionProbe {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$WorkRoot
    )

    $sshExe = (Get-Command ssh.exe -ErrorAction Stop).Source
    $marker = 'EMTASK_SERVICE_SESSION_OK'
    $knownHosts = Join-Path $WorkRoot 'known_hosts'
    $sshInput = Join-Path $WorkRoot 'ssh-session.in'
    $sshOutput = Join-Path $WorkRoot 'ssh-session.out.log'
    $sshError = Join-Path $WorkRoot 'ssh-session.err.log'
    $askpass = Join-Path $WorkRoot 'ssh-askpass.cmd'

    Set-Content -LiteralPath $askpass -Value @('@echo off', 'echo emtask') -Encoding ASCII
    Set-Content -LiteralPath $sshInput -Value @('', "echo $marker", 'exit') -Encoding ASCII

    $oldAskpass = [Environment]::GetEnvironmentVariable('SSH_ASKPASS', 'Process')
    $oldAskpassRequire = [Environment]::GetEnvironmentVariable('SSH_ASKPASS_REQUIRE', 'Process')
    $oldDisplay = [Environment]::GetEnvironmentVariable('DISPLAY', 'Process')

    try {
        $env:SSH_ASKPASS = $askpass
        $env:SSH_ASKPASS_REQUIRE = 'force'
        $env:DISPLAY = 'emtask-service-ci'

        $sshArgs = @(
            '-p', [string]$Port,
            '-o', 'BatchMode=no',
            '-o', 'PreferredAuthentications=password',
            '-o', 'PubkeyAuthentication=no',
            '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'StrictHostKeyChecking=no',
            '-o', "UserKnownHostsFile=$knownHosts",
            '-tt',
            'emtask@127.0.0.1'
        )

        $client = Start-Process -FilePath $sshExe `
            -ArgumentList $sshArgs `
            -RedirectStandardInput $sshInput `
            -RedirectStandardOutput $sshOutput `
            -RedirectStandardError $sshError `
            -WindowStyle Hidden `
            -PassThru

        if (-not $client.WaitForExit(45000)) {
            Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
            throw 'SSH terminal session probe timed out.'
        }
        $client.Refresh()

        $stdout = if (Test-Path -LiteralPath $sshOutput -PathType Leaf) { Get-Content -LiteralPath $sshOutput -Raw } else { '' }
        $stderr = if (Test-Path -LiteralPath $sshError -PathType Leaf) { Get-Content -LiteralPath $sshError -Raw } else { '' }
        Write-Host '--- ssh session stdout ---'
        Write-Host ($stdout -replace "`e", '<ESC>')
        Write-Host '--- ssh session stderr ---'
        Write-Host ($stderr -replace "`e", '<ESC>')

        if ($stdout -notmatch [regex]::Escape($marker)) {
            throw "SSH terminal session did not return marker '$marker'. ExitCode=$($client.ExitCode)"
        }
    } finally {
        if ($null -eq $oldAskpass) { Remove-Item Env:\SSH_ASKPASS -ErrorAction SilentlyContinue } else { $env:SSH_ASKPASS = $oldAskpass }
        if ($null -eq $oldAskpassRequire) { Remove-Item Env:\SSH_ASKPASS_REQUIRE -ErrorAction SilentlyContinue } else { $env:SSH_ASKPASS_REQUIRE = $oldAskpassRequire }
        if ($null -eq $oldDisplay) { Remove-Item Env:\DISPLAY -ErrorAction SilentlyContinue } else { $env:DISPLAY = $oldDisplay }
    }
}

function Invoke-SftpSessionProbe {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$WorkRoot,
        [Parameter(Mandatory = $true)][string]$RuntimeRoot
    )

    $sftpExe = (Get-Command sftp.exe -ErrorAction Stop).Source
    $knownHosts = Join-Path $WorkRoot 'sftp-known_hosts'
    $askpass = Join-Path $WorkRoot 'sftp-askpass.cmd'
    $batch = Join-Path $WorkRoot 'sftp-session.batch'
    $upload = Join-Path $WorkRoot 'sftp-upload.txt'
    $download = Join-Path $WorkRoot 'sftp-download.txt'
    $sftpOutput = Join-Path $WorkRoot 'sftp-session.out.log'
    $sftpError = Join-Path $WorkRoot 'sftp-session.err.log'
    $serverFile = Join-Path $RuntimeRoot 'sftp-server-file.txt'
    $uploadedServerFile = Join-Path $RuntimeRoot 'uploaded-from-ci.txt'

    Set-Content -LiteralPath $askpass -Value @('@echo off', 'echo emtask') -Encoding ASCII
    Set-Content -LiteralPath $upload -Value 'emtask-service-sftp-upload-ok' -NoNewline -Encoding ASCII
    Set-Content -LiteralPath $serverFile -Value 'emtask-service-sftp-download-ok' -NoNewline -Encoding ASCII
    Remove-Item -LiteralPath $download, $uploadedServerFile -Force -ErrorAction SilentlyContinue

    $uploadPath = $upload.Replace('\', '/')
    $downloadPath = $download.Replace('\', '/')
    Set-Content -LiteralPath $batch -Value @(
        'pwd',
        'ls',
        "put `"$uploadPath`" uploaded-from-ci.txt",
        "get sftp-server-file.txt `"$downloadPath`"",
        'bye'
    ) -Encoding ASCII

    $oldAskpass = [Environment]::GetEnvironmentVariable('SSH_ASKPASS', 'Process')
    $oldAskpassRequire = [Environment]::GetEnvironmentVariable('SSH_ASKPASS_REQUIRE', 'Process')
    $oldDisplay = [Environment]::GetEnvironmentVariable('DISPLAY', 'Process')

    try {
        $env:SSH_ASKPASS = $askpass
        $env:SSH_ASKPASS_REQUIRE = 'force'
        $env:DISPLAY = 'emtask-service-ci'

        $sftpArgs = @(
            '-P', [string]$Port,
            '-o', 'BatchMode=no',
            '-o', 'PreferredAuthentications=password',
            '-o', 'PubkeyAuthentication=no',
            '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'StrictHostKeyChecking=no',
            '-o', "UserKnownHostsFile=$knownHosts",
            '-b', $batch,
            'emtask@127.0.0.1'
        )

        $client = Start-Process -FilePath $sftpExe `
            -ArgumentList $sftpArgs `
            -RedirectStandardOutput $sftpOutput `
            -RedirectStandardError $sftpError `
            -WindowStyle Hidden `
            -PassThru

        if (-not $client.WaitForExit(45000)) {
            Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
            throw 'SFTP session probe timed out.'
        }
        $client.Refresh()

        $stdout = if (Test-Path -LiteralPath $sftpOutput -PathType Leaf) { Get-Content -LiteralPath $sftpOutput -Raw } else { '' }
        $stderr = if (Test-Path -LiteralPath $sftpError -PathType Leaf) { Get-Content -LiteralPath $sftpError -Raw } else { '' }
        Write-Host '--- sftp session stdout ---'
        Write-Host ($stdout -replace "`e", '<ESC>')
        Write-Host '--- sftp session stderr ---'
        Write-Host ($stderr -replace "`e", '<ESC>')

        if ($client.ExitCode -ne 0) {
            throw "SFTP session probe failed. ExitCode=$($client.ExitCode)"
        }
        if (-not (Test-Path -LiteralPath $uploadedServerFile -PathType Leaf) -or
            (Get-Content -LiteralPath $uploadedServerFile -Raw) -ne 'emtask-service-sftp-upload-ok') {
            throw 'SFTP upload verification failed.'
        }
        if (-not (Test-Path -LiteralPath $download -PathType Leaf) -or
            (Get-Content -LiteralPath $download -Raw) -ne 'emtask-service-sftp-download-ok') {
            throw 'SFTP download verification failed.'
        }
    } finally {
        if ($null -eq $oldAskpass) { Remove-Item Env:\SSH_ASKPASS -ErrorAction SilentlyContinue } else { $env:SSH_ASKPASS = $oldAskpass }
        if ($null -eq $oldAskpassRequire) { Remove-Item Env:\SSH_ASKPASS_REQUIRE -ErrorAction SilentlyContinue } else { $env:SSH_ASKPASS_REQUIRE = $oldAskpassRequire }
        if ($null -eq $oldDisplay) { Remove-Item Env:\DISPLAY -ErrorAction SilentlyContinue } else { $env:DISPLAY = $oldDisplay }
    }
}

if (-not (Test-Administrator)) {
    throw 'Windows service integration test requires an elevated runner.'
}

$sourcePackageRoot = (Resolve-Path -LiteralPath $PackageRoot).Path
$runId = [Environment]::GetEnvironmentVariable('GITHUB_RUN_ID')
if ([string]::IsNullOrWhiteSpace($runId)) { $runId = 'local' }
$suffix = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$safeLabel = ($Label -replace '[^A-Za-z0-9_.-]', '-')
$serviceName = "emtask-ci-$suffix"
$tempBase = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { [IO.Path]::GetTempPath() } else { $env:RUNNER_TEMP }
$workRoot = Join-Path $tempBase "emtask-service-$safeLabel-$runId-$suffix"
$runtimeRoot = Join-Path $workRoot 'runtime'
$serviceDir = Join-Path $workRoot 'service'
$logDir = Join-Path $workRoot 'logs'
$panelPort = Get-FreeTcpPort
do { $taskPort = Get-FreeTcpPort } while ($taskPort -eq $panelPort)

New-Item -ItemType Directory -Force -Path $runtimeRoot, $serviceDir, $logDir | Out-Null
Get-ChildItem -LiteralPath $sourcePackageRoot -Force | Copy-Item -Destination $runtimeRoot -Recurse -Force

$emtaskExe = Join-Path $runtimeRoot 'emtask.exe'
$sqliteDll = Join-Path $runtimeRoot 'sqlite3.dll'
$serviceScript = Join-Path $runtimeRoot 'emtask-windows-service.ps1'
$wrapperExe = Join-Path $runtimeRoot 'emtask-service-wrapper.exe'
$configPath = Join-Path $runtimeRoot 'emtask.conf'

foreach ($required in @($emtaskExe, $sqliteDll, $serviceScript, $wrapperExe)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required package file is missing: $required"
    }
}

@"
username = emtask
password = emtask
hostkey_file = emtask_hostkey_p256.raw
timeout_ms = 30000
max_workers = 8
use_conpty = false
panel_enabled = true
panel_listen_address = 127.0.0.1
panel_port = $panelPort
panel_auth = none
panel_tasks_db_file = emtask_tasks.sqlite3
panel_qr_mode = disabled

[task smoke]
listen_address = 127.0.0.1
port = $taskPort
working_dir = .
use_sftp = true
use_conpty = false
command = cmd.exe /Q /K
"@ | Set-Content -LiteralPath $configPath -Encoding ASCII

Write-Host "Testing emtask Windows service package: $sourcePackageRoot"
Write-Host "Runtime root: $runtimeRoot"
Write-Host "Service name: $serviceName"
Write-Host "Panel port: $panelPort"
Write-Host "Task port: $taskPort"

try {
    & $serviceScript install `
        -ServiceName $serviceName `
        -DisplayName "emtask CI $Label" `
        -Description "GitHub Actions emtask service smoke test for $Label" `
        -EmtaskExe $emtaskExe `
        -Config $configPath `
        -ServiceDir $serviceDir `
        -LogDir $logDir `
        -WrapperExe $wrapperExe `
        -StartupType Automatic `
        -LocalSystem `
        -Force

    $service = Get-Service -Name $serviceName -ErrorAction Stop
    if ($null -eq $service) {
        throw "Service '$serviceName' was not registered."
    }

    $escapedServiceName = $serviceName.Replace("'", "''")
    $serviceCim = Get-CimInstance Win32_Service -Filter "Name='$escapedServiceName'" -ErrorAction Stop
    $serviceCim | Select-Object Name, State, StartMode, StartName, PathName | Format-List
    if ($serviceCim.StartMode -ne 'Auto') {
        throw "Service '$serviceName' is not configured for automatic startup. StartMode=$($serviceCim.StartMode)"
    }

    & $serviceScript start -ServiceName $serviceName
    (Get-Service -Name $serviceName -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

    $health = Wait-PanelJson -Uri "http://127.0.0.1:$panelPort/health" -Description 'panel health'
    Write-Host '--- panel /health ---'
    $health | ConvertTo-Json -Depth 8

    $status = Wait-PanelJson -Uri "http://127.0.0.1:$panelPort/status" -Description 'panel status'
    Write-Host '--- panel /status ---'
    $status | ConvertTo-Json -Depth 12

    $tasksResponse = Wait-PanelJson -Uri "http://127.0.0.1:$panelPort/tasks" -Description 'panel tasks'
    $tasks = if ($null -ne $tasksResponse.PSObject.Properties['tasks']) {
        @($tasksResponse.tasks)
    } else {
        @($tasksResponse)
    }
    if (-not ($tasks | Where-Object { $_.name -eq 'smoke' })) {
        throw "Panel /tasks did not report the smoke task."
    }

    Wait-TcpPort -Port $taskPort
    if ($safeLabel -match 'cygwin') {
        Write-Host 'Using SFTP session probe for Cygwin package because Win32 cmd.exe terminal echo is not stable under the Cygwin service build on GitHub-hosted runners.'
        Invoke-SftpSessionProbe -Port $taskPort -WorkRoot $workRoot -RuntimeRoot $runtimeRoot
    } else {
        Invoke-SshSessionProbe -Port $taskPort -WorkRoot $workRoot
    }

    Write-Host "emtask Windows service integration test passed for $Label."
} finally {
    try {
        if (Test-Path -LiteralPath $serviceScript -PathType Leaf) {
            & $serviceScript status -ServiceName $serviceName
        }
    } catch {
        Write-Warning "Failed to query service status: $($_.Exception.Message)"
    }

    Write-LogTail -Directory $logDir

    try {
        if (Test-Path -LiteralPath $serviceScript -PathType Leaf) {
            & $serviceScript uninstall -ServiceName $serviceName -ServiceDir $serviceDir -RemoveFiles
        }
    } catch {
        Write-Warning "Failed to uninstall service '$serviceName': $($_.Exception.Message)"
    }
}