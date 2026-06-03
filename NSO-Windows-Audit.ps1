<#
.SYNOPSIS
    NextStep Online SysAdmin Security Auditor (Enhanced Edition)
.DESCRIPTION
    Defensive Windows security auditing and threat hunting tool.
    Focuses on exact finding location, evidence, and remediation.
    Outputs terminal, log, CSV, and HTML reports.
#>

[CmdletBinding()]
param(
    [int]$RecentDays = 7,
    [int]$MaxContentFileMB = 5
)

# =============================================================================
# 1. Initialization
# =============================================================================
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
} catch {}

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[CRITICAL] Administrator privileges are required." -ForegroundColor Red
    Write-Host "[INFO] Current Identity: $($currentIdentity.Name)" -ForegroundColor Yellow
    Read-Host "Press Enter to exit..."
    exit 1
}

$scriptDir = (Get-Location).Path
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath   = Join-Path $scriptDir "NextStep_Security_Scan_$timestamp.log"
$htmlPath  = Join-Path $scriptDir "NextStep_Security_Report_$timestamp.html"
$csvPath   = Join-Path $scriptDir "NextStep_Security_Findings_$timestamp.csv"

$global:Findings = New-Object System.Collections.Generic.List[object]
$global:TotalChecksPerformed = 0
$global:Timer = [System.Diagnostics.Stopwatch]::StartNew()
$global:LogLock = New-Object object

try { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue } catch {}

# =============================================================================
# 2. Configuration
# =============================================================================
$script:Config = [ordered]@{
    RecentDays          = $RecentDays
    MaxContentFileBytes = $MaxContentFileMB * 1MB

    DeepScanRoots = @(
        "C:\ProgramData",
        "C:\Windows\Panther",
        "C:\Windows\Temp",
        "C:\Windows\Tasks",
        "C:\Windows\System32\Tasks",
        "C:\inetpub",
        "C:\Users",
        "C:\Program Files\Microsoft SQL Server",
        "C:\var\log",
        "C:\LogFiles",
        "D:\inetpub",
        "D:\Websites",
        "D:\Backups",
        "C:\Windows\debug",
        "C:\Windows\System32\LogFiles",
        "C:\Windows\System32\Sysprep"
    )

    # ENHANCEMENT: Expanded to completely filter out common developer and system noise (.codex, AppData\Local, build bins)
    ExcludePathRegex = '(?i)\\(WinSxS|WindowsApps|System Volume Information|\$Recycle\.Bin|Microsoft\.NET|Package Cache|node_modules|bower_components|\.git|\.svn|\.hg|cache|Local\\Temp|AppData\\Local\\Microsoft\\Windows\\INetCache|NuGet\\Packages|\.cargo\\registry|\.gradle\\caches|pip\\cache|vcpkg\\packages|temp\\?|\.codex|\.vscode|\.idea|__pycache__|obj|bin)$'

    SensitiveFileNameRegex = @(
        '(?i)\.kdbx$',
        '(?i)\.ppk$',
        '(?i)\bid_rsa(\.pub)?$',
        '(?i)\bid_dsa(\.pub)?$',
        '(?i)\bid_ecdsa(\.pub)?$',
        '(?i)\bid_ed25519(\.pub)?$',
        '(?i)\.pem$',
        '(?i)\.pfx$',
        '(?i)\.p12$',
        '(?i)\.key$',
        '(?i)\.rdp$',
        '(?i)\bunattend\.xml$',
        '(?i)\bsysprep\.inf$',
        '(?i)\bsysprep\.xml$',
        '(?i)\bweb\.config$',
        '(?i)\bappsettings\.json$',
        '(?i)\.env$',
        '(?i)\bConsoleHost_history\.txt$',
        '(?i)\bcredentials?\.xml$',
        '(?i)\bpasswords?\.txt$',
        '(?i)\bsecrets?\.txt$',
        '(?i)\baws\\credentials$',
        '(?i)\bkube\\config$',
        '(?i)\bconfig\.yml$',
        '(?i)\bconfig\.yaml$',
        '(?i)\b(unattended|autounattend)\.(xml|txt|ini)$',
        '(?i)\b(iisConfig|applicationHost\.config)$',
        '(?i)\b(docker-compose\.yml|docker-compose\.yaml)$'
    )

    ContentSecretPatterns = @(
        '(?i)\b(password|passwd|pwd)\b\s*[:=]\s*.+',
        '(?i)\b(api[_-]?key|token|secret|client_secret)\b\s*[:=]\s*.+',
        'AKIA[0-9A-Z]{16}',
        '(?i)BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY',
        '(?i)\bConnection String\b.*(password|pwd|secret)=.+',
        '(?i)\b<Password>.*</Password>\b',
        'AIza[0-9A-Za-z-_]{35}',
        '(?i)\b(mongodb(\+srv)?://.+:.+@.+)\b',
        '(?i)\b(mysql://.+:.+@.+)\b',
        '(?i)\b(postgresql://.+:.+@.+)\b',
        'ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
    )
}

# =============================================================================
# 3. Utility Functions
# =============================================================================
function ConvertTo-HtmlSafeText {
    param([AllowNull()][object]$Value)
    $text = [string]$Value
    try {
        return [System.Web.HttpUtility]::HtmlEncode($text)
    } catch {
        return ($text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
    }
}

function Test-CommandAvailable {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-RegValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    try {
        if (-not (Test-Path -Path $Path)) { return $null }
        $item = Get-ItemProperty -Path $Path -ErrorAction Stop
        if ($item.PSObject.Properties.Name -contains $Name) {
            return $item.$Name
        }
    } catch {}
    return $null
}

function Get-ProcessNameById {
    param([Parameter(Mandatory = $true)][int]$ProcessId)
    try {
        return (Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName
    } catch {
        try {
            $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
            if ($p) { return $p.Name }
        } catch {}
    }
    return "Unknown"
}

function Get-ExecutablePathFromCommandLine {
    param([AllowNull()][string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $cmd = $CommandLine.Trim()
    if ($cmd.StartsWith('"')) {
        $m = [regex]::Match($cmd, '^"([^"]+?\.exe)"', 'IgnoreCase')
        if ($m.Success) { return $m.Groups[1].Value }
        $m = [regex]::Match($cmd, '^"([^"]+)"', 'IgnoreCase')
        if ($m.Success) { return $m.Groups[1].Value }
    }
    $m = [regex]::Match($cmd, '^([A-Za-z]:\\.*?\.exe)(?:\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Get-FileOwnerSafe {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        return $acl.Owner
    } catch {
        return "Unknown"
    }
}

function Get-AclWeaknessSummary {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $weak = New-Object System.Collections.Generic.List[string]
        foreach ($ace in $acl.Access) {
            $id = $ace.IdentityReference.Value
            $rights = $ace.FileSystemRights.ToString()
            if ($id -in @("Everyone", "BUILTIN\Users", "NT AUTHORITY\Authenticated Users") -and $rights -match 'Write|Modify|FullControl') {
                [void]$weak.Add("$id : $rights")
            }
        }
        if ($weak.Count -gt 0) { return ($weak -join "; ") }
    } catch {}
    return $null
}

function Test-TextLikeFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $name = [System.IO.Path]::GetFileName($Path).ToLowerInvariant()

    $textExt = @(
        ".txt",".log",".ini",".inf",".cfg",".conf",".config",".xml",".json",".yml",".yaml",".ps1",".psm1",
        ".psd1",".bat",".cmd",".csv",".md",".env",".sql",".py",".js",".ts",".html",".htm",".properties",
        ".rdp",".reg",".sh",".pem",".key",".pub",".bak",".old"
    )
    if ($textExt -contains $ext) { return $true }
    $targetNames = @("hosts", "authorized_keys", "known_hosts", "id_rsa", "credentials", "config")
    if ($name -in $targetNames) { return $true }
    return $false
}

function Get-FileContentEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string[]]$Patterns = $script:Config.ContentSecretPatterns
    )
    $matches = New-Object System.Collections.Generic.List[object]
    try {
        $info = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($info.Length -gt $script:Config.MaxContentFileBytes) { return @() }
        if (-not (Test-TextLikeFile -Path $Path)) { return @() }

        $lineNum = 0
        foreach ($line in Get-Content -LiteralPath $Path -ErrorAction Stop) {
            $lineNum++
            foreach ($pattern in $Patterns) {
                if ($line -match $pattern) {
                    $snippet = $line.Trim()
                    if ($snippet.Length -gt 240) { $snippet = $snippet.Substring(0, 240) + "..." }
                    [void]$matches.Add([pscustomobject]@{
                        Line    = $lineNum
                        Pattern = $pattern
                        Snippet = $snippet
                    })
                }
            }
        }
    } catch {}
    return $matches
}

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Title)
    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ("    {0}" -f $Title) -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Location,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Evidence,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Reason,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Remediation
    )

    $global:TotalChecksPerformed++
    $time = Get-Date -Format 'HH:mm:ss.fff'
    $sev = $Severity.ToUpper().Trim()

    $color = switch ($sev) {
        { $_ -in @('CRITICAL', 'FAILED', 'VULNERABLE', 'HIGH') } { 'Red' }
        { $_ -in @('WARNING', 'ALERT', 'SUSPICIOUS', 'MEDIUM') } { 'Yellow' }
        { $_ -in @('SECURE', 'GOOD', 'OK', 'LOW') } { 'Green' }
        { $_ -in @('INFO', 'NOTICE') } { 'Cyan' }
        default { 'White' }
    }

    Write-Host "[$sev] " -ForegroundColor $color -NoNewline
    Write-Host "$Category | $Title"
    Write-Host "         Location: $Location" -ForegroundColor DarkGray
    Write-Host "         Evidence : $Evidence" -ForegroundColor DarkGray

    $logLine = "[$time] [$Category] [$sev] $Title | Location: $Location | Evidence: $Evidence | Reason: $Reason | Remediation: $Remediation"
    $lockTaken = $false
    try {
        [System.Threading.Monitor]::Enter($global:LogLock, [ref]$lockTaken)
        [System.IO.File]::AppendAllText($logPath, $logLine + [Environment]::NewLine, [System.Text.Encoding]::UTF8)
    } catch {
        try { Add-Content -Path $logPath -Value $logLine -Encoding UTF8 } catch {}
    } finally {
        if ($lockTaken) { [System.Threading.Monitor]::Exit($global:LogLock) }
    }

    [void]$global:Findings.Add([pscustomobject]@{
        Time        = $time
        Category    = $Category
        Title       = $Title
        Severity    = $sev
        Location    = $Location
        Evidence    = $Evidence
        Reason      = $Reason
        Remediation = $Remediation
    })
}

function Add-InfoCheck {
    param(
        [string]$Category,
        [string]$Title,
        [AllowEmptyString()][string]$Location,
        [AllowEmptyString()][string]$Evidence,
        [AllowEmptyString()][string]$Reason
    )
    Add-Finding -Category $Category -Title $Title -Severity "INFO" -Location $Location -Evidence $Evidence -Reason $Reason -Remediation "No action required."
}

# =============================================================================
# 4. Baseline Audit
# =============================================================================
function Audit-LoggingPipeline {
    Write-Section "INITIALIZATION: Telemetry & Audit Controls"
    try {
        $sblPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (Test-Path $sblPath) {
            $enabled = Get-RegValue -Path $sblPath -Name "EnableScriptBlockLogging"
            if ($enabled -eq 1) {
                Add-Finding "Initialization" "Script Block Logging" "SECURE" $sblPath "EnableScriptBlockLogging=1" "PowerShell script block logging is enabled." "Keep policy enforced."
            } else {
                Add-Finding "Initialization" "Script Block Logging" "WARNING" $sblPath "Policy key exists but EnableScriptBlockLogging is not 1" "Logging policy exists but is not fully enabled." "Set EnableScriptBlockLogging to 1 via GPO."
            }
        } else {
            Add-Finding "Initialization" "Script Block Logging" "WARNING" $sblPath "Policy key not found" "Script block logging is not explicitly enforced." "Enable PowerShell Script Block Logging."
        }
    } catch {
        Add-Finding "Initialization" "Script Block Logging" "FAILED" "HKLM policy path" $_.Exception.Message "Could not read script block logging policy." "Verify registry access and policy settings."
    }
}

function Audit-SystemBaseline {
    Write-Section "MODULE 1: System Hardening Baseline"
    try {
        if (Test-CommandAvailable -Name Get-MpComputerStatus) {
            $defender = Get-MpComputerStatus -ErrorAction Stop
            $tamper = $false
            if ($defender.PSObject.Properties.Name -contains "IsTamperProtected") { $tamper = [bool]$defender.IsTamperProtected }
            $location = "Windows Defender"
            $evidence = "AntivirusEnabled=$($defender.AntivirusEnabled); RealTimeProtectionEnabled=$($defender.RealTimeProtectionEnabled); TamperProtected=$tamper"
            if ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled -and $tamper) {
                Add-Finding "Baseline" "Windows Defender" "SECURE" $location $evidence "Defender real-time protection and tamper protection are enabled." "Keep Defender protections active."
            } else {
                Add-Finding "Baseline" "Windows Defender" "CRITICAL" $location $evidence "Core anti-malware protection or tamper protection is not fully active." "Re-enable Defender protection and enforce tamper protection."
            }
        }
    } catch {
        Add-Finding "Baseline" "Windows Defender" "FAILED" "Windows Defender status" $_.Exception.Message "Could not query Defender status." "Verify Defender modules and permissions."
    }

    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $runAsPPL = Get-RegValue -Path $lsaPath -Name "RunAsPPL"
        $credGuard = Get-RegValue -Path $lsaPath -Name "LsaCfgFlags"
        if ($runAsPPL -in @(1,2)) {
            Add-Finding "Baseline" "LSA Protection" "SECURE" $lsaPath "RunAsPPL=$runAsPPL" "LSASS protection is enabled. Mimikatz credential dumping is restricted." "Keep protection enabled."
        } else {
            Add-Finding "Baseline" "LSA Protection" "VULNERABLE" $lsaPath "RunAsPPL=$runAsPPL" "LSA protection is not active. Vulnerable to memory credential harvesting." "Enable RunAsPPL via registry or GPO."
        }
        if ($credGuard -eq 1) {
            Add-Finding "Baseline" "Credential Guard" "SECURE" $lsaPath "LsaCfgFlags=1" "Credential Guard is enabled." "Keep it enabled."
        } else {
            Add-Finding "Baseline" "Credential Guard" "WARNING" $lsaPath "LsaCfgFlags=$credGuard" "Credential Guard is not active. Hardened Kerberos ticket protection missing." "Enable Windows Defender Credential Guard."
        }
    } catch {
        Add-Finding "Baseline" "LSA / Credential Guard" "WARNING" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" $_.Exception.Message "Could not verify LSA hardening settings." "Check registry access."
    }
}

# =============================================================================
# 5. Service, Firewall, and Network Audit
# =============================================================================
function Audit-ServicesAndFirewall {
    Write-Section "MODULE 2: Services, Binaries, and Firewall Exposure"
    $services = @()
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
    } catch {
        Add-Finding "PrivEsc" "Service Enumeration" "FAILED" "Win32_Service" $_.Exception.Message "Could not enumerate services." "Verify CIM access."
    }

    $unquotedCount = 0
    $weakBinaryCount = 0

    foreach ($srv in $services) {
        $pathName = [string]$srv.PathName
        if ([string]::IsNullOrWhiteSpace($pathName)) { continue }
        $binaryPath = $null
        try { $binaryPath = Get-ExecutablePathFromCommandLine -CommandLine $pathName } catch {}

        if ($pathName -match '\s' -and $pathName -notmatch '^"' -and $pathName -notmatch '^[A-Za-z]:\\Windows\\') {
            Add-Finding "PrivEsc" "Unquoted Service Path" "VULNERABLE" "Service: $($srv.Name)" "PathName=$pathName" "Service binary path contains spaces and is unquoted." "Quote the path or harden service configuration."
            $unquotedCount++
        }
        if ($binaryPath -and (Test-Path -LiteralPath $binaryPath)) {
            try {
                $weakAcl = Get-AclWeaknessSummary -Path $binaryPath
                if ($weakAcl) {
                    Add-Finding "PrivEsc" "Writable Service Binary" "CRITICAL" $binaryPath "Service: $($srv.Name); Weak ACL: $weakAcl" "Unprivileged write access on a service binary was detected." "Remove write permissions from non-admin identities."
                    $weakBinaryCount++
                }
            } catch {}
        }
    }

    if ($unquotedCount -eq 0) {
        Add-Finding "PrivEsc" "Service Path Review" "SECURE" "Win32_Service" "No unquoted service path issues found." "No obvious unquoted service paths were discovered." "No action required."
    }
    if ($weakBinaryCount -eq 0) {
        Add-Finding "PrivEsc" "Service Binary ACLs" "SECURE" "Service executables" "No weak writable service binaries found." "No high-risk writable service binaries were discovered." "No action required."
    }
}

function Audit-NetworkAndPorts {
    Write-Section "MODULE 3: Listening Ports, Hosts, and Name Resolution Exposure"
    try {
        if (Test-CommandAvailable -Name Get-NetTCPConnection) {
            $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop
            $flagged = 0
            foreach ($l in $listeners) {
                $procName = Get-ProcessNameById -ProcessId $l.OwningProcess
                $loc = "TCP listener $($l.LocalAddress):$($l.LocalPort) (PID $($l.OwningProcess))"
                $ev = "Process=$procName"
                if ($l.LocalAddress -in @("0.0.0.0", "::", "*") -and $l.LocalPort -in @(135,139,445,3389,5985,5986)) {
                    Add-Finding "Network" "Global TCP Listener" "ALERT" $loc $ev "A critical lateral movement port is bound globally on all interfaces." "Restrict the service binding via firewall or network isolation."
                    $flagged++
                }
            }
            Add-InfoCheck -Category "Network" -Title "TCP Listener Review Complete" -Location "Local host" -Evidence "$($listeners.Count) listeners reviewed; $flagged lateral-risk matches" -Reason "All listening sockets were enumerated."
        }
    } catch {
        Add-Finding "Network" "TCP Listener Review" "FAILED" "TCP listeners" $_.Exception.Message "Could not query TCP listeners." "Verify permissions."
    }
}

# =============================================================================
# 6. Persistence & Auto-Runs (Enhanced: Smart Deduplication)
# =============================================================================
function Audit-Persistence {
    Write-Section "MODULE 4: Persistence Artifacts & Auto-Start Execution"
    $runPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($path in $runPaths) {
        try {
            if (Test-Path $path) {
                $prop = Get-ItemProperty -Path $path -ErrorAction Stop
                foreach ($p in $prop.PSObject.Properties) {
                    if ($p.Name -in @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSIsContainer")) { continue }
                    $val = [string]$p.Value
                    if ([string]::IsNullOrEmpty($val)) { continue }

                    $evidenceStr = "Name=$($p.Name); Cmd=$val"
                    
                    # ENHANCEMENT: Context-aware analysis. Only flag high-risk paths or LOLBins as SUSPICIOUS. Default to INFO.
                    $isSuspicious = $false
                    if ($val -match '(?i)\\(Temp|AppData\\Local\\Temp|Users\\Public|ProgramData)\\' -or 
                        $val -match '(?i)(powershell|cmd\.exe|mshta|bitsadmin|certutil|wscript|cscript|regsvr32)') {
                        $isSuspicious = $true
                    }

                    if ($isSuspicious) {
                        Add-Finding "Persistence" "Suspicious Registry Run Key" "SUSPICIOUS" $path $evidenceStr "An auto-start entry leverages an untrusted path or an dual-use script interpreter." "Verify the program context and binary validity."
                    } else {
                        Add-InfoCheck -Category "Persistence" -Title "Standard Registry Run Key" -Location $path -Evidence $evidenceStr -Reason "Standard program or verified auto-start path discovered."
                    }
                }
            }
        } catch {
            Add-Finding "Persistence" "Registry Run Key" "FAILED" $path $_.Exception.Message "Could not read registry run entries." "Verify registry permissions."
        }
    }
}

# =============================================================================
# 7. File System Scanner (Enhanced: Aggressive Noise Cancellation)
# =============================================================================
function Audit-FileSystem {
    Write-Section "MODULE 5: File System Secrets & High-Risk Artifact Discovery"
    $cutoff = (Get-Date).AddDays(-$script:Config.RecentDays)

    foreach ($root in $script:Config.DeepScanRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        try {
            $files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $global:TotalChecksPerformed++
                
                # ENHANCEMENT: Skip scanning entirely if matching developer or cache directory rules
                if ($f.FullName -match $script:Config.ExcludePathRegex) { continue }

                $isSensitiveName = $false
                foreach ($regex in $script:Config.SensitiveFileNameRegex) {
                    if ($f.Name -match $regex) {
                        $isSensitiveName = $true
                        $owner = Get-FileOwnerSafe -Path $f.FullName
                        Add-Finding "File System" "Sensitive File Discovered" "HIGH" $f.FullName "Owner: $owner; Size: $($f.Length) bytes" "A file matching a highly sensitive naming signature was found." "Secure the file, adjust ACLs, or relocate out of shared paths."
                        break
                    }
                }

                if (-not $isSensitiveName -and ($f.LastWriteTime -ge $cutoff) -and ($f.Length -le $script:Config.MaxContentFileBytes)) {
                    $evidences = Get-FileContentEvidence -Path $f.FullName
                    foreach ($ev in $evidences) {
                        Add-Finding "File System" "Credential Pattern In File" "CRITICAL" "$($f.FullName):$($ev.Line)" "Pattern: $($ev.Pattern); Snippet: $($ev.Snippet)" "Active pattern match for secrets inside plaintext discovered." "Remove hardcoded credentials instantly."
                    }
                }
            }
        } catch {
            Add-Finding "File System" "Recursive File Review" "FAILED" $root $_.Exception.Message "Access restrictions occurred while scanning." "Review permissions."
        }
    }
}

# =============================================================================
# 8. Event Log Threat Hunt (Enhanced: Strict Temporal Filtering)
# =============================================================================
function Audit-EventLogs {
    Write-Section "MODULE 6: Tactical Security Log Analysis & Lateral Movement Hunt"
    if (-not (Test-CommandAvailable -Name Get-WinEvent)) {
        Add-Finding "Event Logs" "Threat Hunt" "INFO" "Get-WinEvent tool" "Cmdlet missing on this core edition." "Cannot parse logs." "No action required."
        return
    }

    $huntTargets = @(
        @{ Log = "Security"; ID = 1102; Title = "Audit Log Cleared"; Sev = "CRITICAL" },
        @{ Log = "Security"; ID = 4697; Title = "Service Installation Detected (Lateral Movement)"; Sev = "ALERT" },
        @{ Log = "System";   ID = 7045; Title = "Service Creation Event Flagged (PsExec/Lateral)"; Sev = "ALERT" }
    )

    # ENHANCEMENT: Enforce strict time-based analysis matching $RecentDays to close the historical gap
    $startTime = (Get-Date).AddDays(-$script:Config.RecentDays)

    foreach ($t in $huntTargets) {
        try {
            $filter = @{ LogName = $t.Log; Id = $t.ID; StartTime = $startTime }
            $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
            if ($events) {
                foreach ($e in $events) {
                    Add-Finding -Category "Event Logs" -Title $t.Title -Severity $t.Sev -Location "$($t.Log) log event" -Evidence "EventID=$($t.ID); TimeCreated=$($e.TimeCreated)" -Reason "An operational event mapped to explicit lateral movement or defense evasion was detected within the audit window." -Remediation "Cross-check PID, caller contexts, and log generation origin."
                }
            }
        } catch {
            Add-Finding -Category "Event Logs" -Title "Threat Hunt" -Severity "WARNING" -Location "$($t.Log) log" -Evidence $_.Exception.Message -Reason "Investigate the referenced event log capability." -Remediation "Verify event log access."
        }
    }
}

# =============================================================================
# 9. Local Administrators Audit (NEW FEATURE)
# =============================================================================
function Audit-LocalAdmins {
    Write-Section "MODULE 7: Local Administrators Group Membership Audit"
    try {
        # Using enterprise-safe CIM instance iteration for accurate mapping across all versions
        $group = Get-CimInstance -ClassName Win32_Group -Filter "Name='Administrators'"
        if ($group) {
            $query = "GroupComponent=""Win32_Group.Domain='$($group.Domain)',Name='$($group.Name)'"""
            $members = Get-CimInstance -ClassName Win32_GroupUser -Filter $query
            
            foreach ($m in $members) {
                $part = $m.PartComponent.Path.ToString()
                $domainMatch = [regex]::Match($part, 'Domain="([^"]+)"')
                $nameMatch = [regex]::Match($part, 'Name="([^"]+)"')
                
                if ($domainMatch.Success -and $nameMatch.Success) {
                    $domain = $domainMatch.Groups[1].Value
                    $name = $nameMatch.Groups[1].Value
                    $accountName = "$domain\$name"
                    
                    # Highlight built-in local or unexpected accounts to detect local admin sprawl
                    $severity = "INFO"
                    if ($domain -ne $env:COMPUTERNAME -and $name -match '(?i)(Guest|User|Admin\d+)') {
                        $severity = "WARNING"
                    }
                    
                    Add-Finding -Category "AccessControl" -Title "Local Administrator Member" -Severity $severity -Location "Administrators Group" -Evidence "Account=$accountName" -Reason "User or Group possesses full administrative rights over the local machine." -Remediation "Validate according to the principle of least privilege."
                }
            }
        }
    } catch {
        Add-Finding "AccessControl" "Local Administrators Audit" "FAILED" "Administrators Group" $_.Exception.Message "Could not enumerate local administrator members." "Verify CIM/WMI status."
    }
}

# =============================================================================
# 10. Remote Management Access Control Audit (NEW FEATURE)
# =============================================================================
function Audit-RemoteAccess {
    Write-Section "MODULE 8: Remote Management & RDP Access Control"
    
    # 1. Remote Desktop (RDP) Safety check
    try {
        $rdpPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
        $denyRdp = Get-RegValue -Path $rdpPath -Name "fDenyTSConnections"
        if ($denyRdp -eq 0) {
            $nla = Get-RegValue -Path "$rdpPath\WinStations\RDP-Tcp" -Name "UserAuthentication"
            $evidence = "fDenyTSConnections=0 (RDP Enabled); UserAuthentication(NLA)=$nla"
            
            if ($nla -eq 1) {
                Add-Finding "RemoteAccess" "RDP Enabled with NLA" "WARNING" $rdpPath $evidence "RDP is exposed but protected via Network Level Authentication (NLA)." "Ensure inbound RDP connections are limited to bastion hosts via firewall."
            } else {
                Add-Finding "RemoteAccess" "RDP Exposed without NLA" "CRITICAL" $rdpPath $evidence "RDP is active WITHOUT Network Level Authentication. Susceptible to BlueKeep-style scanner abuse and password spraying." "Enforce NLA immediately by setting UserAuthentication=1."
            }
        } else {
            Add-Finding "RemoteAccess" "Remote Desktop State" "SECURE" $rdpPath "fDenyTSConnections=1" "RDP is disabled on this host." "Keep RDP disabled if business needs permit."
        }
    } catch {
        Add-Finding "RemoteAccess" "RDP Audit" "FAILED" "Terminal Server Registry" $_.Exception.Message "Could not evaluate RDP status." "Verify permissions."
    }

    # 2. WinRM CredSSP Authentication Exposure check
    try {
        $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
        if ($winrmService -and $winrmService.Status -eq "Running") {
            $credSSPServer = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service\CredentialSSP"
            $evidence = "WinRM=Running; CredSSPServerConfigured=$credSSPServer"
            
            if ($credSSPServer) {
                Add-Finding "RemoteAccess" "WinRM CredSSP Delegation Active" "HIGH" "WSMAN Registry" $evidence "WinRM allows CredSSP server-side delegation. Cleartext credentials can be left cached in LSASS if admins connect via CredSSP." "Disable CredSSP authentication for WinRM; transition to Kerberos or Remoting over HTTPS."
            } else {
                Add-Finding "RemoteAccess" "WinRM Active" "WARNING" "WinRM Service" $evidence "WinRM service is running for remote management." "Ensure WinRM access is hardened and constrained via GPO network profiles."
            }
        } else {
            Add-Finding "RemoteAccess" "WinRM Status" "SECURE" "WinRM Service" "WinRM Service Stopped/Not Running" "WinRM is inactive. Prevents standard PowerShell-based remote lateral movement." "No action required."
        }
    } catch {
        Add-Finding "RemoteAccess" "WinRM Audit" "FAILED" "WinRM Service State" $_.Exception.Message "Could not evaluate WinRM structural security." "Check administrative permissions."
    }
}

# =============================================================================
# 11. Reporting Pipeline
# =============================================================================
function Export-FinalReports {
    $global:Timer.Stop()
    $elapsedSeconds = [math]::Round($global:Timer.Elapsed.TotalSeconds, 2)

    if ($global:Findings.Count -eq 0) {
        Add-InfoCheck -Category "Summary" -Title "No Findings" -Location "System Scope" -Evidence "Scan Clean" -Reason "No security gaps detected."
    }

    try {
        $global:Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        Write-Host "[WARN] CSV export failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    $criticalCount = ($global:Findings | Where-Object { $_.Severity -in @('CRITICAL', 'FAILED', 'VULNERABLE', 'HIGH') }).Count
    $warningCount  = ($global:Findings | Where-Object { $_.Severity -in @('WARNING', 'ALERT', 'SUSPICIOUS', 'MEDIUM') }).Count
    $secureCount   = ($global:Findings | Where-Object { $_.Severity -in @('SECURE', 'GOOD', 'OK', 'LOW') }).Count
    $infoCount     = ($global:Findings | Where-Object { $_.Severity -eq 'INFO' }).Count

    $summaryHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NextStep Online SysAdmin Security Audit Report</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; background: #0a0a0a; color: #eaeaea; }
h1 { border-left: 5px solid #5c42ff; padding-left: 12px; }
.meta { background: #111; border: 1px solid #222; padding: 14px; border-radius: 6px; margin-bottom: 20px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap: 14px; margin-bottom: 24px; }
.card { padding: 16px; border: 1px solid #222; border-radius: 8px; background: #111; }
.card .label { font-size: 12px; text-transform: uppercase; color: #999; }
.card .value { font-size: 28px; font-weight: bold; margin-top: 6px; }
.CRITICAL, .FAILED, .VULNERABLE, .HIGH { color: #ff4a4a; font-weight: bold; }
.WARNING, .ALERT, .SUSPICIOUS, .MEDIUM { color: #ffb624; font-weight: bold; }
.SECURE, .GOOD, .OK, .LOW { color: #2bf761; font-weight: bold; }
.INFO, .NOTICE { color: #24d0ff; font-weight: bold; }
table { width: 100%; border-collapse: collapse; margin-top: 15px; background: #111; }
th, td { text-align: left; padding: 10px; border: 1px solid #222; font-size: 13px; }
th { background: #1a1a1a; color: #bbb; text-transform: uppercase; font-size: 11px; }
tr:hover { background: #161616; }
</style>
</head>
<body>
<h1>Security Audit & Threat Hunt Report</h1>
<div class="meta">
    <strong>Host:</strong> $env:COMPUTERNAME &nbsp;|&nbsp; 
    <strong>User:</strong> $env:USERNAME &nbsp;|&nbsp; 
    <strong>Duration:</strong> $elapsedSeconds seconds &nbsp;|&nbsp;
    <strong>Timestamp:</strong> $timestamp
</div>
<div class="grid">
    <div class="card"><div class="label">Total Checks</div><div class="value" style="color:#bbb">$global:TotalChecksPerformed</div></div>
    <div class="card"><div class="label">Critical / High</div><div class="value CRITICAL">$criticalCount</div></div>
    <div class="card"><div class="label">Warning / Alert</div><div class="value WARNING">$warningCount</div></div>
    <div class="card"><div class="label">Secure / Good</div><div class="value SECURE">$secureCount</div></div>
    <div class="card"><div class="label">Info Records</div><div class="value INFO">$infoCount</div></div>
</div>
<table>
<thead>
    <tr>
        <th>Time</th>
        <th>Category</th>
        <th>Title</th>
        <th>Severity</th>
        <th>Location</th>
        <th>Evidence</th>
        <th>Reason</th>
        <th>Remediation</th>
    </tr>
</thead>
<tbody>
'@

    $rows = New-Object System.Text.StringBuilder
    foreach ($f in $global:Findings) {
        $time = ConvertTo-HtmlSafeText -Value $f.Time
        $category = ConvertTo-HtmlSafeText -Value $f.Category
        $title = ConvertTo-HtmlSafeText -Value $f.Title
        $severity = ConvertTo-HtmlSafeText -Value $f.Severity
        $location = ConvertTo-HtmlSafeText -Value $f.Location
        $evidence = ConvertTo-HtmlSafeText -Value $f.Evidence
        $reason = ConvertTo-HtmlSafeText -Value $f.Reason
        $reremediation = ConvertTo-HtmlSafeText -Value $f.Remediation
        $severityClass = $severity.ToUpper().Trim()

        [void]$rows.AppendLine(@"
<tr>
<td>$time</td>
<td>$category</td>
<td>$title</td>
<td><span class="$severityClass">$severity</span></td>
<td>$location</td>
<td>$evidence</td>
<td>$reason</td>
<td>$reremediation</td>
</tr>
"@)
    }

    $html = @"
$summaryHtml
$($rows.ToString())
</tbody>
</table>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    } catch {
        Write-Host "[WARN] HTML export failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "[DONE] Audit completed." -ForegroundColor Cyan
    Write-Host "[STAT] Total Checks: $global:TotalChecksPerformed" -ForegroundColor Green
    Write-Host "[STAT] Duration: $elapsedSeconds seconds" -ForegroundColor Yellow
    Write-Host "[STAT] Critical: $criticalCount | Warning: $warningCount | Secure: $secureCount | Info: $infoCount" -ForegroundColor Cyan
    Write-Host "[SAVE] Log  -> $logPath" -ForegroundColor White
    Write-Host "[SAVE] CSV  -> $csvPath" -ForegroundColor White
    Write-Host "[SAVE] HTML -> $htmlPath" -ForegroundColor White
}

# =============================================================================
# 12. Execution
# =============================================================================
Audit-LoggingPipeline
Audit-SystemBaseline
Audit-ServicesAndFirewall
Audit-NetworkAndPorts
Audit-Persistence
Audit-FileSystem
Audit-EventLogs
Audit-LocalAdmins
Audit-RemoteAccess
Export-FinalReports
