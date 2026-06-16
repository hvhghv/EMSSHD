param(
    [Alias('uninstall')]
    [switch]$Uninstall
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$packageDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$manifestPath = Join-Path $packageDir 'install-manifest.psd1'

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
Write-Host "emtask client package is ready at: $packageDir"
Write-Host 'No shortcuts or system integrations are created by default. Run emtask_client.exe from this directory.'
Write-Manifest -Items $items
Write-Host "Install manifest written: $manifestPath"
