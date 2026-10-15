# SecurityKit static scan for Windows without bash. Same output as run_static.sh.
#
#   powershell -ExecutionPolicy Bypass -File run_static.ps1 [project_dir]
param([string]$Target = ".")

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$rules = Join-Path $here "..\rules\api.yml"

$py = $null
foreach ($cand in @(@("python"), @("py", "-3"), @("python3"))) {
  try {
    $v = & $cand[0] @($cand[1..9] + "--version") 2>&1
    if ("$v" -match "Python 3\.") { $py = $cand; break }
  } catch {}
}
if (-not $py) { Write-Output '{"semgrep":"error","results":[],"error":"Python 3 not found"}'; exit 0 }

if (-not (Get-Command semgrep -ErrorAction SilentlyContinue)) {
  Write-Output '{"semgrep":"missing","results":[],"hint":"pip install semgrep, then re-run"}'
  exit 0
}
if (-not (Test-Path -PathType Container $Target)) {
  Write-Output "{`"semgrep`":`"error`",`"results`":[],`"error`":`"not a directory`"}"
  exit 0
}

$out = [System.IO.Path]::GetTempFileName()
$err = [System.IO.Path]::GetTempFileName()
try {
  $excludes = @("node_modules", ".git", "vendor", "dist", "build", ".venv", "venv", "__pycache__",
                ".securitykit", ".claude", ".codex", "*.min.js", "coverage") | ForEach-Object { "--exclude"; $_ }
  $env:PYTHONIOENCODING = "utf-8"
  # --output instead of ">" because Windows PowerShell 5.1 re-encodes redirected output as UTF-16.
  $ErrorActionPreference = "Continue"
  & semgrep scan --config $rules --json --quiet --metrics=off --disable-version-check --no-git-ignore `
    @excludes --timeout 30 --max-target-bytes 2000000 --output $out $Target 2>&1 |
    ForEach-Object { "$_" } | Out-File -Encoding utf8 $err
  $ErrorActionPreference = "Stop"
  $pyArgs = @()
  if ($py.Length -gt 1) { $pyArgs = $py[1..($py.Length - 1)] }
  & $py[0] @pyArgs (Join-Path $here "semgrep_to_candidates.py") --root $Target --stderr-file $err $out
} finally {
  Remove-Item -Force -ErrorAction SilentlyContinue $out, $err
}
