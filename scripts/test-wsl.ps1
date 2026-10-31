$ErrorActionPreference = 'Stop'

$projectPath = Split-Path -Parent $PSScriptRoot
$linuxPath = (& wsl -d Ubuntu -- wslpath -a -u $projectPath).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Unable to resolve WSL project path' }

# Pass the path as a positional argument, never interpolated shell source.
& wsl -d Ubuntu -- bash -lc 'cd "$1" && "$HOME/.local/share/nvyr-router/venv/bin/python" -m pytest -q' nvyr-tests $linuxPath
if ($LASTEXITCODE -ne 0) { throw 'nVyR tests failed' }
