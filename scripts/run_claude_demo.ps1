<#
.SYNOPSIS
Run Claude Code with HOLD as its only tool source, from the demo workspace.

.DESCRIPTION
This uses YOUR Claude account. Prepare first:
  .venv\Scripts\python.exe scripts\reset_demo.py                         # workspace, outside the repo
  .venv\Scripts\python.exe scripts\make_mcp_config.py                    # deny receipt
  .venv\Scripts\python.exe scripts\make_mcp_config.py --allow-host HOST  # positive control

The working directory is the workspace_root of the receipt the config points at, so Claude
Code always runs in the folder that receipt governs (hold.env.demo_workspace() when rendered).

Flags, checked against `claude --help` (Claude Code 2.1.295):
  -p/--print, --tools "" (disables all built-in tools), --strict-mcp-config,
  --mcp-config <configs...>, --allowedTools/--allowed-tools <tools...>

Windows PowerShell 5.1 silently drops an empty "" argument when it starts a native program,
which would turn `--tools ""` into `--tools --strict-mcp-config`. This script passes '""'
there, which arrives as one empty argument (checked on this machine with a stand-in exe).

.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts\run_claude_demo.ps1
powershell -ExecutionPolicy Bypass -File scripts\run_claude_demo.ps1 -Config configs\generated\hold.allow-host.mcp.json
#>
param(
    [string]$Config = (Join-Path $PSScriptRoot '..\configs\hold.mcp.json'),
    [string]$Prompt = 'Read ISSUE.md and fix the reported bug in src/flask/app.py using only the HOLD tools.',
    [string]$Claude = 'claude'
)
$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    [Console]::Error.WriteLine("run_claude_demo: $Message")
    exit 2
}

$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) { Fail "missing $Config; run: .venv\Scripts\python.exe scripts\make_mcp_config.py" }
$ClaudeCmd = Get-Command $Claude -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $ClaudeCmd) { Fail "'$Claude' not found; install Claude Code or pass -Claude <path>" }

# Workspace and audit log from the config's receipt, with the same refusals as the generator.
$ConfigAbs = (Resolve-Path -LiteralPath $Config).Path
$ServerEnv = (Get-Content -LiteralPath $ConfigAbs -Raw | ConvertFrom-Json).mcpServers.hold.env
$Audit = $ServerEnv.HOLD_AUDIT_LOG
if (-not (Test-Path -LiteralPath $ServerEnv.HOLD_RECEIPT -PathType Leaf)) { Fail "missing receipt $($ServerEnv.HOLD_RECEIPT); run: .venv\Scripts\python.exe scripts\make_mcp_config.py" }
$Ws = (Get-Content -LiteralPath $ServerEnv.HOLD_RECEIPT -Raw | ConvertFrom-Json).workspace_root
try { $Rooted = [System.IO.Path]::IsPathRooted($Ws) } catch { $Rooted = $false }  # '<HOLD_DEMO_WORKSPACE>' is not a legal path
if (-not $Rooted) { Fail "the receipt's workspace_root is not absolute; run: .venv\Scripts\python.exe scripts\make_mcp_config.py" }
if (-not (Test-Path -LiteralPath $Ws -PathType Container)) { Fail "missing workspace $Ws; run: .venv\Scripts\python.exe scripts\reset_demo.py" }
if ((Get-Item -LiteralPath $Ws -Force).LinkType) { Fail "$Ws is a symlink or junction" }
$WsFull = [System.IO.Path]::GetFullPath($Ws).TrimEnd('\')
if ($WsFull -ieq $Repo -or $WsFull.StartsWith($Repo + '\', [System.StringComparison]::OrdinalIgnoreCase)) { Fail "workspace $Ws is inside the HOLD repo" }
foreach ($p in @('.claude', '.mcp.json')) {
    if (Test-Path -LiteralPath (Join-Path $Ws $p)) { Fail "refusing to run: $(Join-Path $Ws $p) exists (repo-controlled agent config)" }
}
$Dirs = @()
$d = Get-Item -LiteralPath $WsFull -Force
while ($d) { $Dirs += $d.FullName; $d = $d.Parent }
$Dirs += (Join-Path $HOME '.claude')
foreach ($dir in $Dirs) {
    foreach ($name in @('CLAUDE.md', 'CLAUDE.local.md')) {
        $f = Join-Path $dir $name
        if (Test-Path -LiteralPath $f -PathType Leaf) { [Console]::Error.WriteLine("run_claude_demo: warning: Claude Code will load $f into the agent's context") }
    }
}

$Before = 0
if ($Audit -and (Test-Path -LiteralPath $Audit)) { $Before = @(Get-Content -LiteralPath $Audit).Count }

# PowerShell 7.3+ passes '' as an empty argument; older hosts need '""'.
$NativePassing = Get-Variable -Name PSNativeCommandArgumentPassing -ValueOnly -ErrorAction SilentlyContinue
if ($PSVersionTable.PSVersion.Major -ge 7 -and $NativePassing -and $NativePassing -ne 'Legacy') { $NoTools = '' } else { $NoTools = '""' }

Write-Host "workspace: $Ws"
Write-Host "config:    $ConfigAbs"
Write-Host "+ claude -p `"$Prompt`" --tools `"`" --strict-mcp-config --mcp-config `"$ConfigAbs`" --allowedTools `"mcp__hold`""
Push-Location -LiteralPath $Ws
try {
    & $ClaudeCmd.Source -p $Prompt --tools $NoTools --strict-mcp-config --mcp-config $ConfigAbs --allowedTools 'mcp__hold'
    $Status = $LASTEXITCODE
}
finally {
    Pop-Location
}

Write-Host ''
Write-Host "HOLD audit rows written during this run ($Audit):"
if ($Audit -and (Test-Path -LiteralPath $Audit)) {
    Get-Content -LiteralPath $Audit | Select-Object -Skip $Before | ForEach-Object {
        $e = $_ | ConvertFrom-Json
        $target = if ($e.target.Length -gt 40) { $e.target.Substring(0, 40) } else { $e.target }
        $reason = if ($e.reason.Length -gt 60) { $e.reason.Substring(0, 60) } else { $e.reason }
        Write-Host ('  {0,-5} {1,-10} {2,-40} {3,-7} {4}' -f $e.decision, $e.tool_name, $target, $e.exec_status, $reason)
    }
}
else {
    Write-Host '  (no audit file: HOLD received no tool calls)'
}
exit $Status
