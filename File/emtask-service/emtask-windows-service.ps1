#requires -Version 5.1
<#
.SYNOPSIS
    Install, uninstall, start, stop, or query emtask as a hidden Windows service.

.DESCRIPTION
    This script installs emtask.exe as a hidden Windows service by copying a prebuilt
    .NET Framework ServiceBase wrapper to the service directory. Install uses the
    current Windows user by default and prompts for that user's password. Pass
    -LocalSystem only when the service should run as LocalSystem instead.
    Install does not require a C# compiler when tools\emtask-service-wrapper.exe is already present.

    Use the build-wrapper action on a development machine to prebuild the wrapper from
    tools\emtask-service-wrapper.cs.

    Run install/uninstall/start/stop/restart from an elevated PowerShell session.

.EXAMPLE
    .\tools\emtask-windows-service.ps1 --help

.EXAMPLE
    .\tools\emtask-windows-service.ps1 build-wrapper

.EXAMPLE
    .\tools\emtask-windows-service.ps1 install `
        -EmtaskExe .\build-emtask-mscv-rename-check\Debug\emtask.exe `
        -Config .\APP\emtask\emtask.conf `
        -Force

.EXAMPLE
    # If .\emtask.exe and .\emtask.conf exist in the current directory, both paths can be omitted.
    # By default, install prompts for the current user's password and runs as that user.
    .\tools\emtask-windows-service.ps1 install `
        -Force

.EXAMPLE
    # Explicitly run the service as LocalSystem instead of the default current user.
    .\tools\emtask-windows-service.ps1 install `
        -LocalSystem `
        -Force

.EXAMPLE
    # Change an already installed service to run as the current Windows user, then start it again.
    .\tools\emtask-windows-service.ps1 set-current-user

.EXAMPLE
    .\tools\emtask-windows-service.ps1 start

.EXAMPLE
    .\tools\emtask-windows-service.ps1 status

.EXAMPLE
    .\tools\emtask-windows-service.ps1 uninstall -RemoveFiles
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'uninstall', 'start', 'stop', 'restart', 'status', 'set-current-user', 'build-wrapper', 'help', '-h', '--help')]
    [string]$Action = 'install',

    [string]$ServiceName = 'emtask',

    [string]$DisplayName = 'emtask SSH Task Service',

    [string]$Description = 'Runs emtask as a hidden Windows service.',

    [string]$EmtaskExe,

    [string]$Config,

    [string]$ServiceDir = "$env:ProgramData\emtask",

    [string]$LogDir,

    [string]$WrapperExe,

    [string]$WrapperSource,

    [ValidateSet('Automatic', 'Manual', 'Disabled')]
    [string]$StartupType = 'Automatic',

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$CurrentUser,

    [switch]$LocalSystem,

    [switch]$Force,

    [switch]$RemoveFiles,

    [Alias('h')]
    [switch]$Help,

    [switch]$CompileIfMissing
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$WrapperExeName = 'emtask-service-wrapper.exe'
$WrapperSourceName = 'emtask-service-wrapper.cs'
$WrapperConfigName = 'emtask-service-wrapper.ini'

function Show-Usage {
        $scriptName = Split-Path -Leaf $PSCommandPath
        @"
Usage:
    .\$scriptName [action] [options]
    .\$scriptName -h
    .\$scriptName --help

Actions:
    install         Install emtask as a hidden Windows service. Default action. Runs as the current user by default.
    uninstall       Stop and delete the Windows service.
    start           Start the service.
    stop            Stop the service.
    restart         Restart the service.
    status          Show service status.
    set-current-user Stop the service, set Log On As to the current Windows user, then start it.
    build-wrapper   Build the precompiled service wrapper exe from C# source.
    help            Show this help text.

Common options:
    -ServiceName <name>       Service name. Default: emtask
    -DisplayName <text>       Service display name.
    -Description <text>       Service description.
    -EmtaskExe <path>         Path to emtask.exe. If omitted, install tries .\emtask.exe in the current directory.
    -Config <path>            Path to emtask.conf. If omitted, install tries .\emtask.conf in the current directory.
    -ServiceDir <path>        Service files directory. Default: %ProgramData%\emtask
    -LogDir <path>            Log directory. Default: <ServiceDir>\logs
    -WrapperExe <path>        Prebuilt wrapper exe. Default: script directory\emtask-service-wrapper.exe
    -WrapperSource <path>     Wrapper C# source. Default: script directory\emtask-service-wrapper.cs
    -StartupType <type>       Automatic, Manual, or Disabled. Default: Automatic
    -Credential <credential>  Service account credential. Overrides the default current-user prompt.
    -CurrentUser              Run the service as the current Windows user. This is the install default.
    -LocalSystem              Run the service as LocalSystem instead of the default current user.
    -Force                    Replace an existing service during install.
    -RemoveFiles              Remove ServiceDir during uninstall.
    -CompileIfMissing         Compile wrapper if prebuilt exe is missing.
    -h, -Help, --help         Show this help text.

Examples:
    .\$scriptName build-wrapper
    .\$scriptName install -EmtaskExe .\emtask.exe -Config .\emtask.conf -Force
    .\$scriptName install -Force
    .\$scriptName install -LocalSystem -Force
    .\$scriptName set-current-user
    .\$scriptName start
    .\$scriptName status
    .\$scriptName uninstall -RemoveFiles
"@
}

if ($Help -or $Action -eq 'help' -or $Action -eq '-h' -or $Action -eq '--help') {
        Show-Usage
        exit 0
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-Administrator)) {
        throw 'This action requires an elevated PowerShell session. Run PowerShell as Administrator.'
    }
}

function Resolve-FullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if ([System.IO.Path]::IsPathRooted($expanded)) {
        return [System.IO.Path]::GetFullPath($expanded)
    }
    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $expanded))
}

function ConvertTo-Base64Utf8 {
    param([Parameter(Mandatory = $true)][string]$Value)
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value))
}

function ConvertTo-ServiceArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Get-ServiceOrNull {
    param([Parameter(Mandatory = $true)][string]$Name)
    return Get-Service -Name $Name -ErrorAction SilentlyContinue
}

function Get-WrapperExePath {
    if ([string]::IsNullOrWhiteSpace($WrapperExe)) {
        return [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $WrapperExeName))
    }
    return Resolve-FullPath $WrapperExe
}

function Get-WrapperSourcePath {
    if ([string]::IsNullOrWhiteSpace($WrapperSource)) {
        return [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $WrapperSourceName))
    }
    return Resolve-FullPath $WrapperSource
}

function Get-EmtaskExePath {
    if (-not [string]::IsNullOrWhiteSpace($EmtaskExe)) {
        return Resolve-FullPath $EmtaskExe
    }

    $currentDirectoryExe = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) 'emtask.exe'))
    if (Test-Path -LiteralPath $currentDirectoryExe -PathType Leaf) {
        return $currentDirectoryExe
    }

    throw "Missing -EmtaskExe and emtask.exe was not found in the current directory: $(Get-Location)"
}

function Get-EmtaskConfigPath {
    if (-not [string]::IsNullOrWhiteSpace($Config)) {
        return Resolve-FullPath $Config
    }

    $currentDirectoryConfig = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) 'emtask.conf'))
    if (Test-Path -LiteralPath $currentDirectoryConfig -PathType Leaf) {
        return $currentDirectoryConfig
    }

    throw "Missing -Config and emtask.conf was not found in the current directory: $(Get-Location)"
}

function Get-CurrentUserCredential {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = $identity.Name
    if ([string]::IsNullOrWhiteSpace($userName)) {
        throw 'Cannot determine the current Windows user name.'
    }
    return Get-Credential -UserName $userName -Message "Enter the Windows password for $userName to run the '$ServiceName' service."
}

function Get-ServiceCimOrNull {
    param([Parameter(Mandatory = $true)][string]$Name)
    $escapedName = $Name.Replace("'", "''")
    return Get-CimInstance Win32_Service -Filter "Name='$escapedName'" -ErrorAction SilentlyContinue
}

function Get-ServiceChangeReturnMessage {
    param([Parameter(Mandatory = $true)][int]$Code)

    switch ($Code) {
        0 { return 'Success' }
        1 { return 'Not Supported' }
        2 { return 'Access Denied' }
        3 { return 'Dependent Services Running' }
        4 { return 'Invalid Service Control' }
        5 { return 'Service Cannot Accept Control' }
        6 { return 'Service Not Active' }
        7 { return 'Service Request Timeout' }
        8 { return 'Unknown Failure' }
        9 { return 'Path Not Found' }
        10 { return 'Service Already Running' }
        11 { return 'Service Database Locked' }
        12 { return 'Service Dependency Deleted' }
        13 { return 'Service Dependency Failure' }
        14 { return 'Service Disabled' }
        15 { return 'Service Logon Failed. Check the password and the "Log on as a service" right.' }
        16 { return 'Service Marked For Deletion' }
        17 { return 'Service No Thread' }
        18 { return 'Status Circular Dependency' }
        19 { return 'Status Duplicate Name' }
        20 { return 'Status Invalid Name' }
        21 { return 'Status Invalid Parameter' }
        22 { return 'Status Invalid Service Account' }
        default { return "Win32_Service.Change returned $Code" }
    }
}

function Set-EmtaskServiceCredential {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$ServiceCredential
    )

    $serviceCim = Get-ServiceCimOrNull -Name $ServiceName
    if (-not $serviceCim) {
        throw "Service '$ServiceName' does not exist."
    }

    $password = $ServiceCredential.GetNetworkCredential().Password
    $result = Invoke-CimMethod -InputObject $serviceCim -MethodName Change -Arguments @{
        StartName = $ServiceCredential.UserName
        StartPassword = $password
    }
    if ($result.ReturnValue -ne 0) {
        throw "Failed to set service account to '$($ServiceCredential.UserName)': $(Get-ServiceChangeReturnMessage -Code ([int]$result.ReturnValue))"
    }

    $updated = Get-ServiceCimOrNull -Name $ServiceName
    if ($updated) {
        Write-Host "Actual service account: $($updated.StartName)"
    }
}

function Get-CSharpCompiler {
    $candidates = @(
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    throw 'Cannot find .NET Framework csc.exe. Build the wrapper on a development machine and deploy emtask-service-wrapper.exe together with this script.'
}

function Compile-ServiceWrapper {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
        throw "Service wrapper source not found: $SourcePath"
    }

    $outputDir = Split-Path -Parent $OutputPath
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

    $csc = Get-CSharpCompiler
    $arguments = @(
        '/nologo',
        '/target:winexe',
        '/reference:System.ServiceProcess.dll',
        ('/out:' + $OutputPath),
        $SourcePath
    )

    & $csc @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to compile service wrapper with $csc"
    }
}

function Build-ServiceWrapper {
    $sourcePath = Get-WrapperSourcePath
    $outputPath = Get-WrapperExePath

    Compile-ServiceWrapper -SourcePath $sourcePath -OutputPath $outputPath
    Write-Host "Built service wrapper: $outputPath"
}

function Write-WrapperConfig {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$RuntimeLogDir
    )

    $lines = @(
        '# Values are base64-encoded UTF-8 strings.',
        ('emtaskExe=' + (ConvertTo-Base64Utf8 $ExePath)),
        ('emtaskConfig=' + (ConvertTo-Base64Utf8 $ConfigPath)),
        ('workingDirectory=' + (ConvertTo-Base64Utf8 $WorkingDirectory)),
        ('logDirectory=' + (ConvertTo-Base64Utf8 $RuntimeLogDir))
    )
    Set-Content -LiteralPath $Path -Value $lines -Encoding UTF8
}

function Wait-ServiceDeleted {
    param([Parameter(Mandatory = $true)][string]$Name)

    for ($i = 0; $i -lt 20; ++$i) {
        if (-not (Get-ServiceOrNull -Name $Name)) {
            return
        }
        Start-Sleep -Milliseconds 500
    }
}

function Stop-EmtaskService {
    param([switch]$IgnoreMissing)

    Assert-Administrator

    $service = Get-ServiceOrNull -Name $ServiceName
    if (-not $service) {
        if ($IgnoreMissing) {
            return
        }
        throw "Service '$ServiceName' does not exist."
    }

    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
}

function Install-EmtaskService {
    Assert-Administrator

    if ($LocalSystem -and $Credential) {
        throw 'Use either -LocalSystem or -Credential, not both.'
    }
    if ($LocalSystem -and $CurrentUser) {
        throw 'Use either -LocalSystem or -CurrentUser, not both.'
    }
    if ($CurrentUser -and $Credential) {
        throw 'Use either -CurrentUser or -Credential, not both.'
    }

    $serviceCredential = $Credential
    if (-not $LocalSystem -and -not $serviceCredential) {
        $serviceCredential = Get-CurrentUserCredential
    }

    $exePath = Get-EmtaskExePath
    $configPath = Get-EmtaskConfigPath
    $sourceWrapperExe = Get-WrapperExePath
    $sourceWrapperSource = Get-WrapperSourcePath
    $serviceRoot = Resolve-FullPath $ServiceDir
    $runtimeLogDir = if ([string]::IsNullOrWhiteSpace($LogDir)) {
        Join-Path $serviceRoot 'logs'
    } else {
        Resolve-FullPath $LogDir
    }

    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "emtask executable not found: $exePath"
    }
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "emtask config not found: $configPath"
    }

    $existing = Get-ServiceOrNull -Name $ServiceName
    if ($existing -and -not $Force) {
        throw "Service '$ServiceName' already exists. Use -Force to replace it."
    }

    if ($existing) {
        Stop-EmtaskService -IgnoreMissing
        & sc.exe delete $ServiceName | Out-Null
        Wait-ServiceDeleted -Name $ServiceName
    }

    New-Item -ItemType Directory -Force -Path $serviceRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $runtimeLogDir | Out-Null

    $wrapperExe = Join-Path $serviceRoot $WrapperExeName
    $wrapperConfig = Join-Path $serviceRoot $WrapperConfigName
    $workingDirectory = Split-Path -Parent $configPath

    if (Test-Path -LiteralPath $sourceWrapperExe -PathType Leaf) {
        if (-not [string]::Equals($sourceWrapperExe, $wrapperExe, [StringComparison]::OrdinalIgnoreCase)) {
            Copy-Item -LiteralPath $sourceWrapperExe -Destination $wrapperExe -Force
        }
    } elseif ($CompileIfMissing) {
        Compile-ServiceWrapper -SourcePath $sourceWrapperSource -OutputPath $wrapperExe
    } else {
        throw "Prebuilt service wrapper not found: $sourceWrapperExe. Run '.\tools\emtask-windows-service.ps1 build-wrapper' on a development machine, or pass -CompileIfMissing."
    }

    Write-WrapperConfig `
        -Path $wrapperConfig `
        -ExePath $exePath `
        -ConfigPath $configPath `
        -WorkingDirectory $workingDirectory `
        -RuntimeLogDir $runtimeLogDir

    $binaryPath = (ConvertTo-ServiceArgument $wrapperExe) +
        ' --service ' + (ConvertTo-ServiceArgument $ServiceName) +
        ' --config ' + (ConvertTo-ServiceArgument $wrapperConfig)

    $newServiceParams = @{
        Name = $ServiceName
        BinaryPathName = $binaryPath
        DisplayName = $DisplayName
        StartupType = $StartupType
    }
    if ($serviceCredential) {
        $newServiceParams.Credential = $serviceCredential
    }

    New-Service @newServiceParams | Out-Null
    if ($serviceCredential) {
        Set-EmtaskServiceCredential -ServiceCredential $serviceCredential
    }
    & sc.exe description $ServiceName $Description | Out-Null
    & sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null

    Write-Host "Installed service: $ServiceName"
    $installedService = Get-ServiceCimOrNull -Name $ServiceName
    if ($installedService) {
        Write-Host "Run as: $($installedService.StartName)"
    } elseif ($serviceCredential) {
        Write-Host "Requested run as: $($serviceCredential.UserName)"
    } else {
        Write-Host 'Run as: LocalSystem'
    }
    Write-Host "Wrapper: $wrapperExe"
    Write-Host "Wrapper config: $wrapperConfig"
    Write-Host "Logs: $runtimeLogDir"
}

function Start-EmtaskService {
    Assert-Administrator

    $service = Get-ServiceOrNull -Name $ServiceName
    if (-not $service) {
        throw "Service '$ServiceName' does not exist."
    }

    if ($service.Status -ne 'Running') {
        Start-Service -Name $ServiceName
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
}

function Uninstall-EmtaskService {
    Assert-Administrator

    $service = Get-ServiceOrNull -Name $ServiceName
    if ($service) {
        Stop-EmtaskService -IgnoreMissing
        & sc.exe delete $ServiceName | Out-Null
        Wait-ServiceDeleted -Name $ServiceName
        Write-Host "Deleted service: $ServiceName"
    } else {
        Write-Host "Service '$ServiceName' does not exist."
    }

    if ($RemoveFiles) {
        $serviceRoot = Resolve-FullPath $ServiceDir
        if (Test-Path -LiteralPath $serviceRoot) {
            Remove-Item -LiteralPath $serviceRoot -Recurse -Force
            Write-Host "Removed files: $serviceRoot"
        }
    }
}

function Show-EmtaskServiceStatus {
    $service = Get-ServiceOrNull -Name $ServiceName
    if (-not $service) {
        Write-Host "Service '$ServiceName' does not exist."
        return
    }

    $cim = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($cim) {
        $cim | Select-Object Name, DisplayName, State, StartName, StartMode, ProcessId, PathName | Format-List
    } else {
        $service | Format-List Name, DisplayName, Status, ServiceType, CanStop
    }
}

function Set-EmtaskServiceCurrentUser {
    Assert-Administrator

    $service = Get-ServiceOrNull -Name $ServiceName
    if (-not $service) {
        throw "Service '$ServiceName' does not exist. Install it first."
    }

    $serviceCredential = Get-CurrentUserCredential
    Stop-EmtaskService -IgnoreMissing
    Set-EmtaskServiceCredential -ServiceCredential $serviceCredential
    Start-EmtaskService
    Show-EmtaskServiceStatus
}

switch ($Action) {
    'install' { Install-EmtaskService }
    'uninstall' { Uninstall-EmtaskService }
    'start' { Start-EmtaskService }
    'stop' { Stop-EmtaskService }
    'restart' {
        Stop-EmtaskService -IgnoreMissing
        Start-EmtaskService
    }
    'status' { Show-EmtaskServiceStatus }
    'set-current-user' { Set-EmtaskServiceCurrentUser }
    'build-wrapper' { Build-ServiceWrapper }
    'help' { Show-Usage }
    '-h' { Show-Usage }
    '--help' { Show-Usage }
}
