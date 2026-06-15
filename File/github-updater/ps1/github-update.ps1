param(
    [Parameter(Mandatory = $true)]
    [string]$Repo,

    [ValidateSet('release', 'action')]
    [string]$Channel = 'release',

    [ValidateSet('list', 'download', 'install')]
    [string]$Mode = 'list',

    [string]$Version,
    [string]$NamePattern = '*',
    [string]$Workflow,
    [string]$Branch,
    [string]$OutputDir = '.',
    [string]$InstallDir,
    [string]$Token = $env:GITHUB_TOKEN,
    [switch]$IncludePrerelease,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Resolve-GitHubToken {
    if ($Token -or $Channel -ne 'action') { return }

    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $gh) { return }
    try {
        $resolved = (& gh auth token 2>$null).Trim()
        if ($LASTEXITCODE -eq 0 -and $resolved) {
            Set-Variable -Name Token -Scope Script -Value $resolved
        }
    } catch {
        # Keep unauthenticated mode; the later download warning will explain the token need.
    }
}

function Resolve-GitHubRepo {
    param([string]$Value)

    $text = $Value.Trim()
    if ($text -match '^https://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?(?:[?#].*)?$') {
        return @{ Owner = $Matches[1]; Name = $Matches[2] }
    }
    if ($text -match '^git@github\.com:([^/]+)/(.+?)(?:\.git)?$') {
        return @{ Owner = $Matches[1]; Name = $Matches[2] }
    }
    if ($text -match '^([^/\s]+)/([^/\s]+)$') {
        return @{ Owner = $Matches[1]; Name = ($Matches[2] -replace '\.git$', '') }
    }
    throw "Invalid GitHub repository address: $Value"
}

function New-GitHubHeaders {
    $headers = @{
        'Accept' = 'application/vnd.github+json'
        'User-Agent' = 'github-updater-ps1'
        'X-GitHub-Api-Version' = '2022-11-28'
    }
    if ($Token) {
        $headers['Authorization'] = "Bearer $Token"
    }
    return $headers
}

function Invoke-GitHubJson {
    param([string]$Uri)

    Invoke-RestMethod -Uri $Uri -Headers (New-GitHubHeaders)
}

function Save-GitHubFile {
    param(
        [string]$Uri,
        [string]$Path
    )

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    Invoke-WebRequest -Uri $Uri -Headers (New-GitHubHeaders) -OutFile $Path
}

function Format-Size {
    param([Int64]$Bytes)

    if ($Bytes -ge 1GB) { return ('{0:n2} GiB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:n2} MiB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:n2} KiB' -f ($Bytes / 1KB)) }
    return "$Bytes B"
}

function Get-ReleaseVersions {
    param([string]$ApiRoot)

    $releases = Invoke-GitHubJson "$ApiRoot/releases?per_page=100"
    @($releases) | Where-Object { -not $_.draft -and ($IncludePrerelease -or -not $_.prerelease) }
}

function Select-ReleaseVersion {
    param(
        [string]$ApiRoot,
        [string]$WantedVersion
    )

    if ($WantedVersion) {
        $encoded = [uri]::EscapeDataString($WantedVersion)
        try {
            return Invoke-GitHubJson "$ApiRoot/releases/tags/$encoded"
        } catch {
            $all = Get-ReleaseVersions $ApiRoot
            $match = @($all | Where-Object { $_.name -eq $WantedVersion -or $_.tag_name -eq $WantedVersion } | Select-Object -First 1)
            if ($match.Count -gt 0) { return $match[0] }
            throw "Release version not found: $WantedVersion"
        }
    }

    $latest = Invoke-GitHubJson "$ApiRoot/releases/latest"
    if (-not $IncludePrerelease -and $latest.prerelease) {
        $latest = @(Get-ReleaseVersions $ApiRoot | Sort-Object published_at -Descending | Select-Object -First 1)[0]
    }
    if (-not $latest) { throw 'No release version found.' }
    return $latest
}

function Get-ActionRuns {
    param([string]$ApiRoot)

    $query = 'per_page=100&status=success'
    if ($Branch) { $query += '&branch=' + [uri]::EscapeDataString($Branch) }
    if ($Workflow) {
        $workflowEscaped = [uri]::EscapeDataString($Workflow)
        $result = Invoke-GitHubJson "$ApiRoot/actions/workflows/$workflowEscaped/runs?$query"
    } else {
        $result = Invoke-GitHubJson "$ApiRoot/actions/runs?$query"
    }
    @($result.workflow_runs)
}

function Select-ActionRun {
    param(
        [string]$ApiRoot,
        [string]$WantedVersion
    )

    if (-not $WantedVersion) {
        $runs = Get-ActionRuns $ApiRoot
        $run = @($runs | Where-Object { $_.conclusion -eq 'success' } | Sort-Object created_at -Descending | Select-Object -First 1)
        if ($run.Count -eq 0) { throw 'No successful action run found.' }
        return $run[0]
    }

    if ($WantedVersion -match '^\d+$') {
        try {
            $direct = Invoke-GitHubJson "$ApiRoot/actions/runs/$WantedVersion"
            if ($direct.conclusion -eq 'success') { return $direct }
        } catch {
            # Fall back to recent runs; the number may be a run_number instead of a run id.
        }
    }

    $runs = Get-ActionRuns $ApiRoot
    $match = @($runs | Where-Object {
        ([string]$_.id -eq $WantedVersion) -or
        ([string]$_.run_number -eq $WantedVersion) -or
        ($_.head_sha -like "$WantedVersion*") -or
        ($_.display_title -eq $WantedVersion) -or
        ($_.name -eq $WantedVersion)
    } | Select-Object -First 1)
    if ($match.Count -eq 0) { throw "Action run version not found: $WantedVersion" }
    return $match[0]
}

function Select-ItemsByPattern {
    param(
        [object[]]$Items,
        [string]$Property,
        [string]$Pattern
    )

    $selected = @($Items | Where-Object { $_.$Property -like $Pattern })
    if ($selected.Count -eq 0) {
        $names = ($Items | ForEach-Object { $_.$Property }) -join ', '
        throw "No item matched pattern '$Pattern'. Available: $names"
    }
    return $selected
}

function Expand-DownloadedPackage {
    param(
        [string]$ArchivePath,
        [string]$Destination
    )

    if (-not $Destination) { throw 'InstallDir is required for install mode.' }
    if ((Test-Path -LiteralPath $Destination) -and -not $Force) {
        $existing = Get-ChildItem -LiteralPath $Destination -Force -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($existing) {
            throw "InstallDir is not empty: $Destination. Use -Force to overwrite/copy into it."
        }
    }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null

    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('github-updater-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    try {
        if ($ArchivePath -match '\.zip$') {
            Expand-Archive -LiteralPath $ArchivePath -DestinationPath $temp -Force
        } elseif ($ArchivePath -match '\.tar\.gz$' -or $ArchivePath -match '\.tgz$') {
            tar -xzf $ArchivePath -C $temp
            if ($LASTEXITCODE -ne 0) { throw "tar failed to extract $ArchivePath" }
        } else {
            Copy-Item -LiteralPath $ArchivePath -Destination $Destination -Force
            return
        }

        $children = @(Get-ChildItem -LiteralPath $temp -Force)
        $source = $temp
        if ($children.Count -eq 1 -and $children[0].PSIsContainer) {
            $source = $children[0].FullName
        }
        Copy-Item -Path (Join-Path $source '*') -Destination $Destination -Recurse -Force
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Resolve-ActionPackageFromArtifact {
    param(
        [string]$ArtifactZip,
        [string]$Pattern
    )

    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('github-artifact-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    try {
        Expand-Archive -LiteralPath $ArtifactZip -DestinationPath $temp -Force
        $packages = @(Get-ChildItem -LiteralPath $temp -File -Recurse | Where-Object {
            $_.Name -like $Pattern -and ($_.Name -match '\.zip$' -or $_.Name -match '\.tar\.gz$' -or $_.Name -match '\.tgz$')
        })
        if ($packages.Count -eq 0) {
            return $ArtifactZip
        }
        if ($packages.Count -gt 1) {
            $names = ($packages | ForEach-Object { $_.Name }) -join ', '
            throw "Artifact contains multiple packages matching '$Pattern': $names"
        }
        $resolved = Join-Path (Split-Path -Parent $ArtifactZip) $packages[0].Name
        Copy-Item -LiteralPath $packages[0].FullName -Destination $resolved -Force
        return $resolved
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Resolve-GitHubToken

$repoInfo = Resolve-GitHubRepo $Repo
$apiRoot = "https://api.github.com/repos/$($repoInfo.Owner)/$($repoInfo.Name)"
$outputFull = (Resolve-Path -LiteralPath (New-Item -ItemType Directory -Force -Path $OutputDir).FullName).Path

if ($Channel -eq 'release') {
    if ($Mode -eq 'list') {
        Get-ReleaseVersions $apiRoot |
            Sort-Object published_at -Descending |
            Select-Object @{n='version';e={$_.tag_name}}, name, prerelease, published_at, @{n='assets';e={$_.assets.Count}} |
            Format-Table -AutoSize
        return
    }

    $release = Select-ReleaseVersion $apiRoot $Version
    $assets = Select-ItemsByPattern -Items @($release.assets) -Property 'name' -Pattern $NamePattern
    foreach ($asset in $assets) {
        $target = Join-Path $outputFull $asset.name
        Write-Host "Downloading release $($release.tag_name): $($asset.name) ($(Format-Size $asset.size))"
        Save-GitHubFile -Uri $asset.browser_download_url -Path $target
        Write-Host "Saved: $target"
        if ($Mode -eq 'install') { Expand-DownloadedPackage -ArchivePath $target -Destination $InstallDir }
    }
    return
}

if ($Channel -eq 'action') {
    if ($Mode -eq 'list') {
        Get-ActionRuns $apiRoot |
            Sort-Object created_at -Descending |
            Select-Object @{n='version';e={$_.id}}, run_number, name, display_title, head_branch, @{n='sha';e={$_.head_sha.Substring(0, 12)}}, created_at |
            Format-Table -AutoSize
        return
    }

    if (-not $Token) {
        Write-Warning 'GitHub Actions artifact downloads usually require a token. Set GITHUB_TOKEN or pass -Token.'
    }
    $run = Select-ActionRun $apiRoot $Version
    $artifactResult = Invoke-GitHubJson "$apiRoot/actions/runs/$($run.id)/artifacts?per_page=100"
    $artifacts = Select-ItemsByPattern -Items @($artifactResult.artifacts | Where-Object { -not $_.expired }) -Property 'name' -Pattern $NamePattern
    foreach ($artifact in $artifacts) {
        $artifactZip = Join-Path $outputFull ($artifact.name + '.artifact.zip')
        Write-Host "Downloading action run $($run.id) artifact: $($artifact.name) ($(Format-Size $artifact.size_in_bytes))"
        Save-GitHubFile -Uri $artifact.archive_download_url -Path $artifactZip
        $packagePath = Resolve-ActionPackageFromArtifact -ArtifactZip $artifactZip -Pattern $NamePattern
        Write-Host "Saved: $packagePath"
        if ($Mode -eq 'install') { Expand-DownloadedPackage -ArchivePath $packagePath -Destination $InstallDir }
    }
    return
}
