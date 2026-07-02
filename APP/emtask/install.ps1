param(
    [switch]$Uninstall,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$extraArgs = @($RemainingArgs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($extraArgs -contains '--uninstall') {
    $Uninstall = $true
    $extraArgs = @($extraArgs | Where-Object { $_ -ne '--uninstall' })
}
if ($extraArgs.Count -gt 0) {
    throw "Unsupported argument(s): $($extraArgs -join ' ')"
}

$packageDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$installRoot = Split-Path -Parent $packageDir
$manifestPath = Join-Path $packageDir 'install-manifest.psd1'
$configPath = Join-Path $installRoot 'emtask.conf'

function Convert-ToEmtaskConfigPath {
    param([string]$Path)

    return $Path -replace '\\', '/'
}

function Write-Manifest {
    param([object[]]$Items)

    $lines = @('@{', '    items = @(')
    foreach ($item in $Items) {
        $lines += '        @{'
        $lines += "            type = '$($item.type)'"
        $lines += "            path = '$($item.path.Replace("'", "''"))'"
        $lines += "            createdAt = '$($item.createdAt)'"
        $lines += "            createdByInstaller = `$$($item.createdByInstaller.ToString().ToLowerInvariant())"
        $lines += "            uninstallAction = '$($item.uninstallAction.Replace("'", "''"))'"
        $lines += '        }'
    }
    $lines += '    )'
    $lines += '}'
    Set-Content -LiteralPath $manifestPath -Encoding UTF8 -Value $lines
}

function Set-ConfigValue {
    param(
        [System.Collections.Generic.List[string]]$Lines,
        [string]$Key,
        [string]$Value
    )

    $found = $false
    for ($i = 0; $i -lt $Lines.Count; ++$i) {
        if ($Lines[$i] -match "^\s*$([regex]::Escape($Key))\s*=") {
            $Lines[$i] = "$Key = $Value"
            $found = $true
        }
    }
    if (-not $found) {
        $Lines.Add("$Key = $Value")
    }
}

function Update-ExternalConfig {
    $created = $false
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        $example = Join-Path $packageDir 'emtask.conf.example'
        if (Test-Path -LiteralPath $example -PathType Leaf) {
            Copy-Item -LiteralPath $example -Destination $configPath -Force
            $created = $true
        } else {
            Set-Content -LiteralPath $configPath -Encoding UTF8 -Value @(
                'username = emtask',
                'password = emtask',
                'panel_enabled = true'
            )
            $created = $true
        }
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content -LiteralPath $configPath) {
        $lines.Add($line)
    }

    Set-ConfigValue -Lines $lines -Key 'hostkey_file' -Value (Convert-ToEmtaskConfigPath (Join-Path $installRoot 'emtask_hostkey_p256.raw'))
    Set-ConfigValue -Lines $lines -Key 'authorized_keys_file' -Value (Convert-ToEmtaskConfigPath (Join-Path $installRoot 'authorized_keys'))
    Set-ConfigValue -Lines $lines -Key 'panel_auth_file' -Value (Convert-ToEmtaskConfigPath (Join-Path $installRoot 'emtask_panel_auth.keys'))
    Set-ConfigValue -Lines $lines -Key 'panel_tasks_db_file' -Value (Convert-ToEmtaskConfigPath (Join-Path $installRoot 'emtask_tasks.sqlite3'))
    Set-ConfigValue -Lines $lines -Key 'panel_qr_file' -Value (Convert-ToEmtaskConfigPath (Join-Path $installRoot 'emtask_panel_connect.svg'))

    Set-Content -LiteralPath $configPath -Encoding UTF8 -Value $lines
    if ($created) {
        Write-Host "Created external config: $configPath"
    } else {
        Write-Host "Updated external config paths: $configPath"
    }
}

function Read-YesNo {
    param([string]$Prompt)

    while ($true) {
        $answer = (Read-Host "$Prompt [yes/no]").Trim().ToLowerInvariant()
        if ($answer -eq 'yes' -or $answer -eq 'no') { return $answer }
    }
}

if ($Uninstall) {
    $items = @()
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
        $items = @($manifest.items)
    }

    $selected = @()
    foreach ($item in $items) {
        if ($item.uninstallAction -eq 'delete' -and (Test-Path -LiteralPath $item.path)) {
            if ((Read-YesNo "Delete $($item.type): $($item.path)?") -eq 'yes') {
                $selected += $item
            }
        }
    }

    if ($selected.Count -gt 0) {
        Write-Host 'Items selected for removal:'
        $selected | ForEach-Object { Write-Host "- $($_.path)" }
        if ((Read-YesNo 'Proceed with selected removals?') -ne 'yes') { return }
        foreach ($item in $selected) {
            Remove-Item -LiteralPath $item.path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    return
}

$items = @()
Update-ExternalConfig
Write-Host "emtask package is ready at: $packageDir"
Write-Host "Run from the install root: .\$(Split-Path -Leaf $packageDir)\emtask.exe"
Write-Host 'No Windows service is registered by default. Use emtask-windows-service.ps1 if you want to install it as a service.'
Write-Manifest -Items $items
Write-Host "Install manifest written: $manifestPath"
