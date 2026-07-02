# GitHub updater for PowerShell

`github-update.ps1` is a generic GitHub package updater. Copy this `ps1/` directory to another project or package and pass that project's GitHub address with `-Repo`.

It supports two channels:

- `release`: reads GitHub Releases and downloads release assets.
- `action`: reads successful GitHub Actions runs and downloads run artifacts.

The repository is always passed as a parameter and can be `owner/repo`, `https://github.com/owner/repo`, or `git@github.com:owner/repo.git`.

## List versions

```powershell
./github-update.ps1 -h
./github-update.ps1 --help
```

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

# Uninstall; runs my-app\install.ps1 -Uninstall first, then removes my-app.
./github-update.ps1 -Mode uninstall -InstallDir C:\my-app -PackageName my-app
# Equivalent alias.
./github-update.ps1 -Uninstall -InstallDir C:\my-app -PackageName my-app
# Or use the updater in the install root; it defaults to uninstalling the only package directory next to it.
C:\my-app\github-update.ps1 -Uninstall
```

For `install`, `.zip`, `.tar.gz`, and `.tgz` archives are extracted. If `-InstallDir` is omitted, the current directory is used. Updates remove the old `xxx/` directory, install the new `xxx/`, copy `github-update.ps1` to the install root, then run `xxx/install.ps1`.

Expected package layout:

- `release`: the downloaded `xxx.zip` / `xxx.tar.gz` contains top-level `xxx/` and same-level `github-update.ps1`.
- `action`: the outer artifact `xxx.zip` contains inner `xxx.zip` / `xxx.tar.gz`, matching `.sha256`, and `github-update.ps1`.
- The top-level `xxx/` contains the project-specific `install.ps1`.

## Common parameters

- `-Repo`: GitHub project address, required.
- `-Channel`: `release` or `action`.
- `-Mode`: `list`, `download`, `install`, or `uninstall`.
- `-Uninstall`: alias for `-Mode uninstall`.
- `-Version`: release tag/name for `release`, or run id/run number/head SHA prefix/display title for `action`.
- `-NamePattern`: wildcard for release asset name or Actions artifact name.
- `-Workflow`: optional workflow file/name/id when listing/downloading from Actions.
- `-Branch`: optional branch filter for Actions.
- `-OutputDir`: download directory.
- `-InstallDir`: install root for `install` / `uninstall`; defaults to the current directory.
- `-PackageName`: installed `xxx/` directory name; required for uninstall when it cannot be inferred.
- `-Token`: GitHub token. Defaults to `GITHUB_TOKEN`; for `action` channel, falls back to `gh auth token` when available.
- `-Help` / `-h` / `-?` / `--help` / `--h`: show usage.
