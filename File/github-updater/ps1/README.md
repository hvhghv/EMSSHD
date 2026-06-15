# GitHub updater for PowerShell

`github-update.ps1` is a generic GitHub package updater. Copy this `ps1/` directory to another project or package and pass that project's GitHub address with `-Repo`.

It supports two channels:

- `release`: reads GitHub Releases and downloads release assets.
- `action`: reads successful GitHub Actions runs and downloads run artifacts.

The repository is always passed as a parameter and can be `owner/repo`, `https://github.com/owner/repo`, or `git@github.com:owner/repo.git`.

## List versions

```powershell
# List release versions
./github-update.ps1 -Repo owner/repo -Channel release -Mode list

# List successful action runs
./github-update.ps1 -Repo owner/repo -Channel action -Mode list
```

## Download a package

```powershell
# Latest release asset matching package name
./github-update.ps1 -Repo owner/repo -Channel release -Mode download -NamePattern 'my-app-windows-x64*.zip' -OutputDir downloads

# Specific release tag
./github-update.ps1 -Repo owner/repo -Channel release -Mode download -Version v1.0.0 -NamePattern 'my-app-linux-x64*.tar.gz' -OutputDir downloads

# Specific Actions run id or run number. If -Token/GITHUB_TOKEN is omitted, gh auth token is tried.
./github-update.ps1 -Repo owner/repo -Channel action -Mode download -Version 1234567890 -NamePattern 'my-app-windows-x64*' -OutputDir downloads
```

## Install/extract a package

```powershell
./github-update.ps1 -Repo owner/repo -Channel release -Mode install -Version v1.0.0 -NamePattern 'my-app-windows-x64*.zip' -InstallDir C:\my-app -Force
```

For `install`, `.zip`, `.tar.gz`, and `.tgz` archives are extracted. If the archive contains one top-level directory, the contents of that directory are copied into `InstallDir`.

## Common parameters

- `-Repo`: GitHub project address, required.
- `-Channel`: `release` or `action`.
- `-Mode`: `list`, `download`, or `install`.
- `-Version`: release tag/name for `release`, or run id/run number/head SHA prefix/display title for `action`.
- `-NamePattern`: wildcard for release asset name or Actions artifact name.
- `-Workflow`: optional workflow file/name/id when listing/downloading from Actions.
- `-Branch`: optional branch filter for Actions.
- `-OutputDir`: download directory.
- `-InstallDir`: install/extract directory for `install` mode.
- `-Token`: GitHub token. Defaults to `GITHUB_TOKEN`; for `action` channel, falls back to `gh auth token` when available.
