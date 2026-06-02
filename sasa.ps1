<#
.SYNOPSIS
    NextStep Online SysAdmin Security Auditor
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
    RecentDays = $RecentDays
    MaxContentFileBytes = $MaxContentFileMB * 1MB

    DeepScanRoots = @(
        "C:\ProgramData",
        "C:\Windows\Panther",
        "C:\Windows\Temp",
        "C:\Windows\Tasks",
        "C:\Windows\System32\Tasks",
        "C:\inetpub",
        "C:\Users"
    )

    ExcludePathRegex = '(?i)\\(WinSxS|WindowsApps|System Volume Information|\$Recycle\.Bin|Microsoft\.NET|Package Cache|node_modules|\.git|cache|temp\\?$)'

    SensitiveFileNameRegex = @(
        '(?i)\.kdbx$',
        '(?i)\.ppk$',
        '(?i)\bid_rsa(\.pub)?$',
        '(?i)\bid_dsa(\.pub)?$',
        '(?i)\bid_ecdsa(\.pub)?$',
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
        '(?i)\bknown_hosts$',
        '(?i)\bauthorized_keys$',
        '(?i)\bconfig\.yml$',
        '(?i)\bconfig\.yaml$'
    )

    ContentSecretPatterns = @(
        '(?i)\b(password|passwd|pwd)\b\s*[:=]\s*.+',
        '(?i)\b(api[_-]?key|token|secret|client_secret|refresh_token|access_key)\b\s*[:=]\s*.+',
        'AKIA[0-9A-Z]{16}',
        'ASIA[0-9A-Z]{16}',
        'gh[pousr]_[A-Za-z0-9_]{20,}',
        '(?i)BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY',
        '(?i)\bConnection String\b.*(password|pwd|secret)=.+',
        '(?i)\bserver=.*;.*(password|pwd)=.+',
        '(?i)\bAdministratorPassword\b',
        '(?i)\bAutoLogon\b',
        '(?i)\bDefaultPassword\b',
        '(?i)\b<Password>.*</Password>\b'
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

        if ($weak.Count -gt 0) {
            return ($weak -join "; ")
        }
    } catch {}

    return $null
}

function Test-TextLikeFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $name = [System.IO.Path]::GetFileName($Path).ToLowerInvariant()

    $textExt = @(
        ".txt",".log",".ini",".inf",".cfg",".conf",".config",".xml",".json",".yml",".yaml",".ps1",".psm1",
        ".psd1",".bat",".cmd",".csv",".md",".env",".sql",".py",".js",".ts",".html",".htm",".php",".asp",
        ".aspx",".properties",".rdp",".reg",".sh",".kusto",".pem",".key",".pub"
    )

    if ($textExt -contains $ext) { return $true }
    if ($name -in @("hosts", "authorized_keys", "known_hosts")) { return $true }
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
        [Parameter(Mandatory = $true)][string]$Location,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Reason,
        [Parameter(Mandatory = $true)][string]$Remediation
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
        if ($lockTaken) {
            [System.Threading.Monitor]::Exit($global:LogLock)
        }
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
        [string]$Location,
        [string]$Evidence,
        [string]$Reason
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

    try {
        $transPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
        if (Test-Path $transPath) {
            $enabled = Get-RegValue -Path $transPath -Name "EnableTranscripting"
            if ($enabled -eq 1) {
                Add-Finding "Initialization" "PowerShell Transcription" "SECURE" $transPath "EnableTranscripting=1" "Transcription logging is enabled." "Keep policy enforced."
            } else {
                Add-Finding "Initialization" "PowerShell Transcription" "WARNING" $transPath "Policy key exists but transcription is not enabled" "Transcription is not fully active." "Enable transcription logging."
            }
        } else {
            Add-Finding "Initialization" "PowerShell Transcription" "INFO" $transPath "Policy key not found" "Transcription logging is not globally enforced." "Optional but recommended."
        }
    } catch {
        Add-Finding "Initialization" "PowerShell Transcription" "FAILED" "HKLM policy path" $_.Exception.Message "Could not read transcription policy." "Verify registry access and policy settings."
    }
}

function Audit-SystemBaseline {
    Write-Section "MODULE 1: System Hardening Baseline"

    try {
        if (Test-CommandAvailable -Name Get-MpComputerStatus) {
            $defender = Get-MpComputerStatus -ErrorAction Stop
            $tamper = $false
            if ($defender.PSObject.Properties.Name -contains "IsTamperProtected") {
                $tamper = [bool]$defender.IsTamperProtected
            }

            $location = "Windows Defender"
            $evidence = "AntivirusEnabled=$($defender.AntivirusEnabled); RealTimeProtectionEnabled=$($defender.RealTimeProtectionEnabled); TamperProtected=$tamper"
            if ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled -and $tamper) {
                Add-Finding "Baseline" "Windows Defender" "SECURE" $location $evidence "Defender real-time protection and tamper protection are enabled." "Keep Defender protections active."
            } elseif ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) {
                Add-Finding "Baseline" "Windows Defender" "WARNING" $location $evidence "Defender is active, but tamper protection was not confirmed." "Verify tamper protection and cloud-delivered protection."
            } else {
                Add-Finding "Baseline" "Windows Defender" "CRITICAL" $location $evidence "Core anti-malware protection is not fully active." "Re-enable Defender protection."
            }
        } else {
            Add-Finding "Baseline" "Windows Defender" "INFO" "Command unavailable" "Get-MpComputerStatus not present on this host." "No action required."
        }
    } catch {
        Add-Finding "Baseline" "Windows Defender" "FAILED" "Windows Defender status" $_.Exception.Message "Could not query Defender status." "Verify Defender modules and permissions."
    }

    try {
        $vbsReg = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        $vbs = Get-RegValue -Path $vbsReg -Name "EnableVirtualizationBasedSecurity"
        if ($vbs -eq 1) {
            Add-Finding "Baseline" "Virtualization-Based Security" "SECURE" $vbsReg "EnableVirtualizationBasedSecurity=1" "VBS is enabled." "Keep VBS enabled."
        } elseif ($null -ne $vbs) {
            Add-Finding "Baseline" "Virtualization-Based Security" "WARNING" $vbsReg "EnableVirtualizationBasedSecurity=$vbs" "VBS is not enabled." "Consider enabling VBS."
        } else {
            Add-Finding "Baseline" "Virtualization-Based Security" "INFO" $vbsReg "Value not found" "VBS state is not explicitly configured." "Optional but recommended."
        }
    } catch {
        Add-Finding "Baseline" "Virtualization-Based Security" "FAILED" "DeviceGuard registry" $_.Exception.Message "Could not read DeviceGuard settings." "Verify registry access."
    }

    try {
        $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $uac = Get-ItemProperty -Path $uacPath -ErrorAction Stop
        $consent = $uac.ConsentPromptBehaviorAdmin
        $enableLUA = $uac.EnableLUA
        $filterAdmin = $uac.FilterAdministratorToken

        if ($enableLUA -eq 0) {
            Add-Finding "Baseline" "UAC" "CRITICAL" $uacPath "EnableLUA=0" "User Account Control is disabled." "Set EnableLUA=1."
        } elseif ($consent -eq 0) {
            Add-Finding "Baseline" "UAC" "CRITICAL" $uacPath "ConsentPromptBehaviorAdmin=0" "Admin elevation prompts are effectively bypassed." "Restore standard UAC prompt behavior."
        } elseif ($consent -in @(2,5)) {
            Add-Finding "Baseline" "UAC" "GOOD" $uacPath "EnableLUA=$enableLUA; ConsentPromptBehaviorAdmin=$consent; FilterAdministratorToken=$filterAdmin" "UAC token authorization behaves normally." "No action required."
        } else {
            Add-Finding "Baseline" "UAC" "WARNING" $uacPath "EnableLUA=$enableLUA; ConsentPromptBehaviorAdmin=$consent; FilterAdministratorToken=$filterAdmin" "Non-standard UAC configuration detected." "Review UAC policy values."
        }
    } catch {
        Add-Finding "Baseline" "UAC" "FAILED" "UAC registry key" $_.Exception.Message "Could not read UAC policy settings." "Verify registry access."
    }

    try {
        if (Test-CommandAvailable -Name Get-BitLockerVolume) {
            $sysDrive = $env:SystemDrive
            $bitlocker = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction Stop
            $protectorTypes = @()
            try { $protectorTypes = $bitlocker.KeyProtector.KeyProtectorType } catch {}

            $location = "BitLocker volume $sysDrive"
            $evidence = "VolumeStatus=$($bitlocker.VolumeStatus); Protectors=$($protectorTypes -join ', ')"
            if ($bitlocker.VolumeStatus -eq "FullyEncrypted") {
                Add-Finding "Baseline" "BitLocker" "SECURE" $location $evidence "System volume is fully encrypted." "No action required."
            } else {
                Add-Finding "Baseline" "BitLocker" "BAD" $location $evidence "System volume is not fully encrypted." "Enable BitLocker on the system volume."
            }
        } else {
            Add-Finding "Baseline" "BitLocker" "INFO" "Command unavailable" "Get-BitLockerVolume not available." "No action required."
        }
    } catch {
        Add-Finding "Baseline" "BitLocker" "WARNING" "System volume" $_.Exception.Message "BitLocker state could not be verified." "Check BitLocker feature availability."
    }

    try {
        $smbChecked = $false
        if (Test-CommandAvailable -Name Get-WindowsOptionalFeature) {
            $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
            if ($null -ne $smb1) {
                $smbChecked = $true
                if ($smb1.State -eq "Disabled") {
                    Add-Finding "Baseline" "SMBv1" "SECURE" "Windows Optional Feature SMB1Protocol" "State=Disabled" "SMBv1 is disabled." "Keep SMBv1 disabled."
                } else {
                    Add-Finding "Baseline" "SMBv1" "CRITICAL" "Windows Optional Feature SMB1Protocol" "State=$($smb1.State)" "SMBv1 is enabled." "Disable SMBv1."
                }
            }
        }
        if (-not $smbChecked) {
            $smbReg = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1"
            if ($null -ne $smbReg) {
                if ($smbReg -eq 0) {
                    Add-Finding "Baseline" "SMBv1" "SECURE" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1=0" "SMBv1 is disabled via registry." "Keep it disabled."
                } else {
                    Add-Finding "Baseline" "SMBv1" "CRITICAL" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1=$smbReg" "SMBv1 may be enabled." "Disable SMBv1."
                }
            } else {
                Add-Finding "Baseline" "SMBv1" "INFO" "SMBv1 registry/feature" "Could not confirm SMBv1 state." "State not explicitly configured." "No action required."
            }
        }
    } catch {
        Add-Finding "Baseline" "SMBv1" "FAILED" "SMBv1 configuration" $_.Exception.Message "Could not audit SMBv1." "Verify access."
    }

    try {
        if (Test-CommandAvailable -Name Confirm-SecureBootUEFI) {
            $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            if ($secureBoot -eq $true) {
                Add-Finding "Baseline" "Secure Boot" "SECURE" "UEFI firmware" "Confirm-SecureBootUEFI=True" "Secure Boot is enabled." "No action required."
            } elseif ($secureBoot -eq $false) {
                Add-Finding "Baseline" "Secure Boot" "WARNING" "UEFI firmware" "Confirm-SecureBootUEFI=False" "Secure Boot is disabled." "Consider enabling Secure Boot."
            }
        } else {
            Add-Finding "Baseline" "Secure Boot" "INFO" "Command unavailable" "Confirm-SecureBootUEFI not available." "No action required."
        }
    } catch {
        Add-Finding "Baseline" "Secure Boot" "INFO" "UEFI firmware" $_.Exception.Message "Could not verify Secure Boot." "No action required."
    }

    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $runAsPPL = Get-RegValue -Path $lsaPath -Name "RunAsPPL"
        $credGuard = Get-RegValue -Path $lsaPath -Name "LsaCfgFlags"

        if ($runAsPPL -in @(1,2)) {
            Add-Finding "Baseline" "LSA Protection" "SECURE" $lsaPath "RunAsPPL=$runAsPPL" "LSASS protection is enabled." "Keep protection enabled."
        } else {
            Add-Finding "Baseline" "LSA Protection" "VULNERABLE" $lsaPath "RunAsPPL=$runAsPPL" "LSA protection is not active." "Enable RunAsPPL."
        }

        if ($credGuard -eq 1) {
            Add-Finding "Baseline" "Credential Guard" "SECURE" $lsaPath "LsaCfgFlags=1" "Credential Guard is enabled." "Keep it enabled."
        } elseif ($null -ne $credGuard) {
            Add-Finding "Baseline" "Credential Guard" "WARNING" $lsaPath "LsaCfgFlags=$credGuard" "Credential Guard is not clearly active." "Review Credential Guard policy."
        } else {
            Add-Finding "Baseline" "Credential Guard" "INFO" $lsaPath "LsaCfgFlags not set" "Credential Guard is not explicitly configured." "Optional but recommended."
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
    $svcDllCount = 0

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

        if ($pathName -match '(?i)svchost\.exe.*-k' -and $srv.StartName -eq "LocalSystem") {
            # Not inherently bad; keep as context only
        }
    }

    if ($unquotedCount -eq 0) {
        Add-Finding "PrivEsc" "Service Path Review" "SECURE" "Win32_Service" "No unquoted service path issues found." "No obvious unquoted service paths were discovered." "No action required."
    }
    if ($weakBinaryCount -eq 0) {
        Add-Finding "PrivEsc" "Service Binary ACLs" "SECURE" "Service executables" "No weak writable service binaries found." "No high-risk writable service binaries were discovered." "No action required."
    }

    try {
        if (Test-CommandAvailable -Name Get-NetFirewallProfile) {
            $profiles = Get-NetFirewallProfile -ErrorAction Stop
            foreach ($profile in $profiles) {
                $loc = "Firewall profile: $($profile.Name)"
                $ev = "Enabled=$($profile.Enabled); DefaultInboundAction=$($profile.DefaultInboundAction); DefaultOutboundAction=$($profile.DefaultOutboundAction)"
                if ($profile.Enabled) {
                    if ($profile.DefaultInboundAction -eq "Allow") {
                        Add-Finding "Network" "Firewall Profile" "ALERT" $loc $ev "The profile allows inbound traffic by default." "Set default inbound action to Block."
                    } else {
                        Add-Finding "Network" "Firewall Profile" "SECURE" $loc $ev "Firewall profile is enabled with a safer inbound default." "No action required."
                    }
                } else {
                    Add-Finding "Network" "Firewall Profile" "CRITICAL" $loc $ev "Firewall profile is disabled." "Enable the firewall profile."
                }
            }
        } else {
            Add-Finding "Network" "Firewall Profile" "INFO" "NetSecurity module" "Get-NetFirewallProfile unavailable." "No action required."
        }
    } catch {
        Add-Finding "Network" "Firewall Profile" "FAILED" "Firewall profiles" $_.Exception.Message "Could not read firewall profile state." "Verify NetSecurity access."
    }

    try {
        if (Test-CommandAvailable -Name Get-NetFirewallRule -and Test-CommandAvailable -Name Get-NetFirewallPortFilter) {
            $dangerPorts = @(21,22,23,25,53,135,139,1433,1521,2049,3389,5985,5986,3306,5432,445)
            $matches = New-Object System.Collections.Generic.List[object]

            $rules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue
            foreach ($rule in $rules) {
                $ports = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                foreach ($pf in $ports) {
                    if ($pf.LocalPort -and $dangerPorts -contains [int]$pf.LocalPort) {
                        [void]$matches.Add([pscustomobject]@{
                            RuleName = $rule.DisplayName
                            Port     = $pf.LocalPort
                            Protocol = $pf.Protocol
                        })
                    }
                }
            }

            if ($matches.Count -gt 0) {
                foreach ($m in $matches) {
                    Add-Finding "Network" "Inbound Firewall Rule" "WARNING" "Firewall rule: $($m.RuleName)" "Port=$($m.Port); Protocol=$($m.Protocol)" "Inbound firewall rule exposes a sensitive port." "Review whether this rule is required."
                }
            } else {
                Add-Finding "Network" "Inbound Firewall Rules" "SECURE" "Firewall rules" "No risky inbound port rules matched." "No sensitive inbound rules were found." "No action required."
            }
        } else {
            Add-Finding "Network" "Firewall Rule Parsing" "INFO" "NetSecurity module" "Firewall rule port filter cmdlets unavailable." "Could not inspect firewall port filters." "No action required."
        }
    } catch {
        Add-Finding "Network" "Firewall Rule Parsing" "FAILED" "Firewall rule inspection" $_.Exception.Message "Could not parse firewall rules." "Verify module availability."
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

                if ($l.LocalAddress -in @("0.0.0.0", "::", "*") -and $l.LocalPort -in @(21,22,23,80,135,139,445,1433,1521,3306,3389,5432,5985,5986)) {
                    Add-Finding "Network" "Global TCP Listener" "ALERT" $loc $ev "A sensitive port is bound on all interfaces." "Restrict the service binding or firewall exposure."
                    $flagged++
                } elseif ($l.LocalAddress -in @("0.0.0.0", "::", "*")) {
                    Add-Finding "Network" "Global TCP Listener" "INFO" $loc $ev "Listener is exposed on all interfaces." "Review whether this exposure is intended."
                }
            }

            Add-InfoCheck -Category "Network" -Title "TCP Listener Review Complete" -Location "Local host" -Evidence "$($listeners.Count) listeners reviewed; $flagged high-risk matches" -Reason "All listening sockets were enumerated."
        } else {
            Add-Finding "Network" "TCP Listener Review" "INFO" "Command unavailable" "Get-NetTCPConnection unavailable." "Could not enumerate TCP listeners." "No action required."
        }
    } catch {
        Add-Finding "Network" "TCP Listener Review" "FAILED" "TCP listeners" $_.Exception.Message "Could not query TCP listeners." "Verify permissions and module availability."
    }

    try {
        $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
        if (Test-Path -LiteralPath $hostsPath) {
            $content = Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue
            $custom = $content | Where-Object { $_.Trim() -match '^[^#]' -and $_ -notmatch 'localhost|127\.0\.0\.1|::1' }

            if ($custom) {
                foreach ($entry in $custom) {
                    Add-Finding "Network" "Hosts File Override" "SUSPICIOUS" $hostsPath $entry.Trim() "A custom hosts override was found." "Verify whether this entry is legitimate."
                }
            } else {
                Add-Finding "Network" "Hosts File" "SECURE" $hostsPath "No custom overrides found." "Hosts file appears standard." "No action required."
            }
        }
    } catch {
        Add-Finding "Network" "Hosts File" "FAILED" "C:\Windows\System32\drivers\etc\hosts" $_.Exception.Message "Could not inspect hosts file." "Verify file access."
    }

    try {
        $llmnrPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
        $llmnr = Get-RegValue -Path $llmnrPath -Name "TurnOffMulticast"
        if ($llmnr -eq 1) {
            Add-Finding "Network" "LLMNR" "SECURE" $llmnrPath "TurnOffMulticast=1" "LLMNR is disabled." "No action required."
        } else {
            Add-Finding "Network" "LLMNR" "WARNING" $llmnrPath "TurnOffMulticast not set to 1" "LLMNR appears enabled or not enforced." "Disable LLMNR by policy."
        }
    } catch {
        Add-Finding "Network" "LLMNR" "WARNING" "HKLM policy path" $_.Exception.Message "Could not confirm LLMNR policy." "Disable LLMNR by policy."
    }

    try {
        $nbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
        $nodeType = Get-RegValue -Path $nbtPath -Name "NodeType"
        if ($nodeType) {
            Add-Finding "Network" "NetBIOS Node Type" "INFO" $nbtPath "NodeType=$nodeType" "NetBIOS node type is configured." "Review if NetBIOS is still required."
        }
    } catch {}
}

# =============================================================================
# 6. Wi-Fi Audit
# =============================================================================
function Audit-WifiSecurity {
    Write-Section "MODULE 4: Wireless Profiles"

    try {
        $profilesRaw = netsh wlan show profiles 2>$null
        $profiles = New-Object System.Collections.Generic.List[string]

        foreach ($line in $profilesRaw) {
            if ($line -match '(All User Profile|所有使用者設定檔|所有用户配置文件)\s*:\s*(.+)$') {
                $name = $Matches[2].Trim()
                if ($name) { [void]$profiles.Add($name) }
            }
        }

        if ($profiles.Count -eq 0) {
            Add-Finding "Wi-Fi" "Wireless Profiles" "GOOD" "netsh wlan" "No saved Wi-Fi profiles found." "No saved wireless profiles were enumerated." "No action required."
            return
        }

        foreach ($profile in $profiles) {
            $details = netsh wlan show profile name="$profile" key=clear 2>$null
            $authType = "Unknown"
            $cipher = "Unknown"
            $autoConnect = "Unknown"
            $hasOpen = $false

            foreach ($line in $details) {
                if ($line -match '(Authentication|驗證|验证|Auth)\s*:\s*(.*)$') {
                    $authType = $Matches[2].Trim()
                    if ($authType -match '(?i)\bOpen\b|\bWEP\b|\bWPA-Personal\b') { $hasOpen = $true }
                }
                if ($line -match '(Cipher|加密)\s*:\s*(.*)$') {
                    $cipher = $Matches[2].Trim()
                }
                if ($line -match '(Connection mode|連線模式|连接模式)\s*:\s*(.*)$') {
                    $autoConnect = $Matches[2].Trim()
                }
            }

            $loc = "Wireless profile: $profile"
            $ev = "Authentication=$authType; Cipher=$cipher; ConnectionMode=$autoConnect"
            if ($hasOpen) {
                Add-Finding "Wi-Fi" "Weak Wireless Profile" "VULNERABLE" $loc $ev "The profile uses open or legacy authentication." "Remove or reconfigure this wireless profile."
            } else {
                Add-Finding "Wi-Fi" "Wireless Profile" "INFO" $loc $ev "Saved profile reviewed." "No action required."
            }
        }

        Add-InfoCheck -Category "Wi-Fi" -Title "Profile Audit Complete" -Location "WLAN subsystem" -Evidence "$($profiles.Count) profiles reviewed" -Reason "All saved Wi-Fi profiles were enumerated."
    } catch {
        Add-Finding "Wi-Fi" "Wireless Audit" "WARNING" "WLAN subsystem" $_.Exception.Message "Could not inspect wireless profiles." "Verify WLAN AutoConfig service and adapter state."
    }
}

# =============================================================================
# 7. Persistence Audit
# =============================================================================
function Audit-Persistence {
    Write-Section "MODULE 5: Persistence, Autoruns, Tasks, and WMI"

    $runKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    )

    foreach ($regPath in $runKeys) {
        try {
            if (-not (Test-Path $regPath)) { continue }
            $items = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($null -eq $items) { continue }

            foreach ($prop in $items.PSObject.Properties) {
                if ($prop.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }

                $valueText = [string]$prop.Value
                $location = "$regPath\$($prop.Name)"
                $evidence = $valueText

                if ($regPath -match "Winlogon") {
                    if ($prop.Name -eq "Userinit") {
                        if ($valueText -notmatch 'userinit\.exe[,]?$') {
                            Add-Finding "Persistence" "Winlogon Userinit" "CRITICAL" $location $evidence "Userinit is not standard." "Restore the default userinit.exe value."
                        } else {
                            Add-Finding "Persistence" "Winlogon Userinit" "INFO" $location $evidence "Userinit entry reviewed." "No action required."
                        }
                    } elseif ($prop.Name -eq "Shell") {
                        if ($valueText -notmatch 'explorer\.exe') {
                            Add-Finding "Persistence" "Winlogon Shell" "CRITICAL" $location $evidence "Shell is redirected away from Explorer." "Restore explorer.exe as the shell."
                        } else {
                            Add-Finding "Persistence" "Winlogon Shell" "INFO" $location $evidence "Shell entry reviewed." "No action required."
                        }
                    }
                    continue
                }

                if ($valueText -match '(?i)(-enc|encodedcommand|-nop|-w\s+hidden|windowstyle\s+hidden|powershell\.exe\s+-e|\btemp\\|\bappdata\\)') {
                    Add-Finding "Persistence" "Registry Run Entry" "SUSPICIOUS" $location $evidence "The autorun value contains suspicious execution indicators." "Review whether this autorun entry is legitimate."
                } elseif ($valueText -match '(?i)\bOneDrive\b|\bTeams\b|\bMicrosoft\b|\bAdobe\b|\bGoogle\b|\bEdge\b') {
                    Add-Finding "Persistence" "Registry Run Entry" "INFO" $location $evidence "Common vendor autorun entry." "No action required."
                } else {
                    Add-Finding "Persistence" "Registry Run Entry" "INFO" $location $evidence "Autorun value reviewed." "No action required."
                }
            }
        } catch {
            Add-Finding "Persistence" "Registry Autoruns" "FAILED" $regPath $_.Exception.Message "Could not inspect autorun registry key." "Verify registry access."
        }
    }

    # IFEO
    try {
        $ifeoRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        if (Test-Path $ifeoRoot) {
            Get-ChildItem $ifeoRoot -ErrorAction SilentlyContinue | ForEach-Object {
                $debugger = Get-RegValue -Path $_.PSPath -Name "Debugger"
                if ($debugger) {
                    Add-Finding "Persistence" "IFEO Debugger" "SUSPICIOUS" $_.PSPath "Debugger=$debugger" "Image File Execution Options debugger redirection exists." "Verify that the debugger is legitimate."
                }
            }
        }
    } catch {
        Add-Finding "Persistence" "IFEO" "FAILED" "Image File Execution Options" $_.Exception.Message "Could not inspect IFEO." "Verify registry access."
    }

    # AppInit_DLLs
    try {
        $appInitPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
        $appInit = Get-RegValue -Path $appInitPath -Name "AppInit_DLLs"
        $loadAppInit = Get-RegValue -Path $appInitPath -Name "LoadAppInit_DLLs"
        if ($appInit -or $loadAppInit -eq 1) {
            Add-Finding "Persistence" "AppInit_DLLs" "WARNING" $appInitPath "LoadAppInit_DLLs=$loadAppInit; AppInit_DLLs=$appInit" "Legacy DLL injection persistence surface may be active." "Review AppInit_DLLs settings."
        }
    } catch {}

    # Startup folders
    try {
        $startupDirs = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        )

        $userProfiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Special }
        foreach ($profile in $userProfiles) {
            if ($profile.LocalPath) {
                $startupDirs += Join-Path $profile.LocalPath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            }
        }

        foreach ($sd in $startupDirs | Select-Object -Unique) {
            if (Test-Path $sd) {
                Get-ChildItem -LiteralPath $sd -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Add-Finding "Persistence" "Startup Folder Item" "INFO" $_.FullName "Parent=$sd" "Startup item found." "Verify whether the item is expected."
                }
            }
        }
    } catch {}

    # Scheduled tasks via cmdlet
    try {
        if (Test-CommandAvailable -Name Get-ScheduledTask) {
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
            foreach ($task in $tasks) {
                $taskName = "$($task.TaskPath)$($task.TaskName)"
                if ($task.TaskPath -match '^\\Microsoft\\Windows\\') { continue }

                if ($task.Actions) {
                    foreach ($action in $task.Actions) {
                        $exec = [string]$action.Execute
                        $args = [string]$action.Arguments
                        $loc = "Task: $taskName"
                        $ev = "Execute=$exec; Arguments=$args; State=$($task.State)"

                        if ($exec -match '(?i)powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32' -or $args -match '(?i)-enc|-encodedcommand|base64|http://|https://') {
                            Add-Finding "Persistence" "Scheduled Task" "SUSPICIOUS" $loc $ev "Task executes scripting or LOLBin-style commands." "Verify task purpose and signature."
                        } else {
                            Add-Finding "Persistence" "Scheduled Task" "INFO" $loc $ev "Task reviewed." "No action required."
                        }

                        try {
                            $sig = $null
                            $exePath = $exec
                            if ($exePath -and (Test-Path $exePath)) {
                                $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                                if ($sig) {
                                    if ($sig.Status -ne "Valid") {
                                        Add-Finding "Persistence" "Task Binary Signature" "WARNING" $exePath "Status=$($sig.Status)" "Scheduled task binary is not validly signed." "Verify the binary provenance."
                                    }
                                }
                            }
                        } catch {}
                    }
                }
            }
        }
    } catch {
        Add-Finding "Persistence" "Scheduled Tasks" "FAILED" "Task Scheduler" $_.Exception.Message "Could not inspect scheduled tasks." "Verify Task Scheduler access."
    }

    # Raw task XML files
    try {
        $taskRoots = @("C:\Windows\System32\Tasks", "C:\Windows\Tasks")
        foreach ($root in $taskRoots) {
            if (-not (Test-Path $root)) { continue }
            Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $file = $_.FullName
                try {
                    $content = Get-Content -LiteralPath $file -ErrorAction Stop
                    $joined = ($content -join "`n")
                    if ($joined -match '(?i)<Command>(.+?)</Command>' -or $joined -match '(?i)<Arguments>(.+?)</Arguments>') {
                        $cmd = $null
                        $args = $null
                        if ($joined -match '(?i)<Command>(.+?)</Command>') { $cmd = $Matches[1] }
                        if ($joined -match '(?i)<Arguments>(.+?)</Arguments>') { $args = $Matches[1] }
                        $loc = $file
                        $ev = "Command=$cmd; Arguments=$args"
                        if ($cmd -match '(?i)powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|curl|wget') {
                            Add-Finding "Persistence" "Task XML" "SUSPICIOUS" $loc $ev "Task XML contains script/LOLBin execution." "Inspect the task and delete if unauthorized."
                        }
                    }
                } catch {}
            }
        }
    } catch {}

    # WMI persistence
    try {
        if (Test-CommandAvailable -Name Get-CimInstance) {
            $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
            $consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
            $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
            $scripts = Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue

            foreach ($f in $filters) {
                Add-Finding "Persistence" "WMI Event Filter" "SUSPICIOUS" "root\subscription::__EventFilter" "Name=$($f.Name); Query=$($f.Query)" "WMI event filter persistence exists." "Verify whether this is legitimate."
            }
            foreach ($c in $consumers) {
                Add-Finding "Persistence" "WMI CommandLine Consumer" "SUSPICIOUS" "root\subscription::CommandLineEventConsumer" "Name=$($c.Name); CommandLineTemplate=$($c.CommandLineTemplate)" "WMI command consumer persistence exists." "Verify whether this is legitimate."
            }
            foreach ($s in $scripts) {
                Add-Finding "Persistence" "WMI Script Consumer" "SUSPICIOUS" "root\subscription::ActiveScriptEventConsumer" "Name=$($s.Name); ScriptingEngine=$($s.ScriptingEngine)" "WMI script consumer persistence exists." "Verify whether this is legitimate."
            }
            foreach ($b in $bindings) {
                Add-Finding "Persistence" "WMI Binding" "SUSPICIOUS" "root\subscription::__FilterToConsumerBinding" "Filter=$($b.Filter); Consumer=$($b.Consumer)" "WMI persistence binding exists." "Verify whether this is legitimate."
            }
        }
    } catch {
        Add-Finding "Persistence" "WMI Persistence" "FAILED" "root\subscription" $_.Exception.Message "Could not inspect WMI persistence." "Verify WMI permissions."
    }

    # Scheduled task files and hidden artifacts
    try {
        $rawTaskDirs = @("C:\Windows\System32\Tasks", "C:\Windows\Tasks")
        foreach ($d in $rawTaskDirs) {
            if (-not (Test-Path $d)) { continue }
            Get-ChildItem -LiteralPath $d -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Length -lt 200KB) {
                    $hit = Get-FileContentEvidence -Path $_.FullName -Patterns @('(?i)<Command>','(?i)<Arguments>','(?i)powershell|cmd|wscript|cscript|mshta|rundll32')
                    if ($hit.Count -gt 0) {
                        $first = $hit | Select-Object -First 1
                        Add-Finding "Persistence" "Task File Artifact" "INFO" $_.FullName "Line $($first.Line): $($first.Snippet)" "Raw task file inspected." "No action required."
                    }
                }
            }
        }
    } catch {}

    # IFEO, LSA, and Winlogon context already covered in baseline
}

# =============================================================================
# 8. Deep File and Secret Artifact Audit
# =============================================================================
function Audit-DeepFileArtifacts {
    Write-Section "MODULE 6: Deep Recursive File Artifacts and Secret Exposure"

    $roots = New-Object System.Collections.Generic.List[string]

    try {
        $profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Special }
        foreach ($p in $profiles) {
            if (-not [string]::IsNullOrWhiteSpace($p.LocalPath) -and (Test-Path -LiteralPath $p.LocalPath)) {
                foreach ($sub in @(
                    "",
                    "Desktop",
                    "Documents",
                    "Downloads",
                    "Favorites",
                    "Pictures",
                    "Videos",
                    "Music",
                    "AppData\Roaming",
                    "AppData\Roaming\Microsoft\Windows\PowerShell",
                    "AppData\Roaming\Microsoft\Credentials",
                    "AppData\Local\Microsoft\Windows\PowerShell",
                    "AppData\Local\Microsoft\Windows\INetCache",
                    "AppData\Local\Google\Chrome\User Data",
                    "AppData\Local\Microsoft\Edge\User Data",
                    "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine",
                    "OneDrive"
                )) {
                    $candidate = if ($sub) { Join-Path $p.LocalPath $sub } else { $p.LocalPath }
                    if (Test-Path -LiteralPath $candidate) { [void]$roots.Add($candidate) }
                }
            }
        }
    } catch {}

    foreach ($fixed in $script:Config.DeepScanRoots) {
        if (Test-Path -LiteralPath $fixed) { [void]$roots.Add($fixed) }
    }

    $roots = $roots | Select-Object -Unique

    $totalFiles = 0
    $findings = 0

    foreach ($root in $roots) {
        Write-Host "[*] Scanning root: $root" -ForegroundColor Yellow

        try {
            $files = Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.FullName -notmatch $script:Config.ExcludePathRegex
                }

            foreach ($file in $files) {
                $totalFiles++
                Increment-SilentCheck

                $full = $file.FullName
                $name = $file.Name
                $ext = [System.IO.Path]::GetExtension($full).ToLowerInvariant()

                # 1) High-value file name matches
                $isSensitiveName = $false
                foreach ($pattern in $script:Config.SensitiveFileNameRegex) {
                    if ($name -match $pattern) {
                        $isSensitiveName = $true
                        break
                    }
                }

                if ($isSensitiveName) {
                    $owner = Get-FileOwnerSafe -Path $full
                    $weakAcl = Get-AclWeaknessSummary -Path $full
                    $sizeKB = [Math]::Round($file.Length / 1KB, 2)

                    # Special classification for harmless public cert bundles
                    if ($full -match '(?i)certifi\\cacert\.pem$' -or $name -match '(?i)^cacert\.pem$') {
                        Add-Finding "File System" "Public CA Certificate Bundle" "INFO" $full "Size=${sizeKB}KB; Owner=$owner" "This is typically a public trust store bundle, not a secret." "No action required."
                        continue
                    }

                    # Special classification for browser dictionaries
                    if ($full -match '(?i)ZxcvbnData\\.*passwords\.txt$') {
                        Add-Finding "File System" "Password Strength Dictionary" "INFO" $full "Size=${sizeKB}KB; Owner=$owner" "This is a password-strength dictionary used by the browser." "No action required."
                        continue
                    }

                    # Deep content inspection for candidate files
                    $contentHits = Get-FileContentEvidence -Path $full
                    if ($contentHits.Count -gt 0) {
                        $first = $contentHits | Select-Object -First 1
                        $evidence = "Line $($first.Line): $($first.Snippet)"
                        $reason = "The file name and content both indicate sensitive material."
                        $remediation = "Restrict access, remove secrets, or rotate any exposed credentials."
                        Add-Finding "File System" "Sensitive File With Secret Content" "CRITICAL" $full $evidence $reason $remediation
                        $findings++
                    } else {
                        $reason = "The filename strongly suggests sensitive content."
                        $evidence = "Size=${sizeKB}KB; Owner=$owner"
                        if ($weakAcl) {
                            $evidence += "; WeakACL=$weakAcl"
                            Add-Finding "File System" "Sensitive File Exposure" "WARNING" $full $evidence $reason "Restrict file permissions and review content."
                        } else {
                            Add-Finding "File System" "Sensitive File Exposure" "INFO" $full $evidence $reason "Review whether this file should exist."
                        }
                        $findings++
                    }
                    continue
                }

                # 2) Content-based secret discovery on text-like files
                if (Test-TextLikeFile -Path $full -and $file.Length -le $script:Config.MaxContentFileBytes) {
                    $hits = Get-FileContentEvidence -Path $full
                    if ($hits.Count -gt 0) {
                        $first = $hits | Select-Object -First 1
                        $loc = $full
                        $ev = "Line $($first.Line): $($first.Snippet)"
                        Add-Finding "File System" "Secret Artifact in File Content" "CRITICAL" $loc $ev "A secret-like string was detected in file content." "Remove secrets and rotate any exposed credentials."
                        $findings++
                        continue
                    }
                }

                # 3) Unattend / sysprep special parsing
                if ($full -match '(?i)unattend\.xml$|sysprep\.xml$|sysprep\.inf$') {
                    $hits = Get-FileContentEvidence -Path $full -Patterns @(
                        '(?i)<Password>.*</Password>',
                        '(?i)<AdministratorPassword>',
                        '(?i)<AutoLogon>',
                        '(?i)<Credentials>',
                        '(?i)<UserName>.*</UserName>',
                        '(?i)<Value>.*</Value>'
                    )
                    if ($hits.Count -gt 0) {
                        $first = $hits | Select-Object -First 1
                        Add-Finding "File System" "Unattend Credential Exposure" "CRITICAL" $full "Line $($first.Line): $($first.Snippet)" "Unattend/sysprep file contains credential-related content." "Delete credential sections after deployment and rotate any exposed secrets."
                        $findings++
                    } else {
                        Add-Finding "File System" "Unattend/Sysprep Artifact" "WARNING" $full "Deployment artifact present" "Deployment XML/INF found; contents should be reviewed." "Review for embedded credentials or product keys."
                        $findings++
                    }
                    continue
                }

                # 4) PSReadLine history
                if ($full -match '(?i)ConsoleHost_history\.txt$') {
                    $hits = Get-FileContentEvidence -Path $full -Patterns @(
                        '(?i)\bpassword\b',
                        '(?i)\btoken\b',
                        '(?i)\bsecret\b',
                        '(?i)\bapi[_-]?key\b',
                        '(?i)\baws\b',
                        '(?i)\baz login\b',
                        '(?i)\bconvertto-securestring\b'
                    )
                    if ($hits.Count -gt 0) {
                        $first = $hits | Select-Object -First 1
                        Add-Finding "File System" "PowerShell History Secret Leak" "HIGH" $full "Line $($first.Line): $($first.Snippet)" "PowerShell history contains secret-like commands or values." "Purge history and rotate any exposed credentials."
                    } else {
                        Add-Finding "File System" "PowerShell History" "INFO" $full "History file present" "PowerShell history file exists and may contain sensitive commands." "Review manually."
                    }
                    $findings++
                    continue
                }

                # 5) RDP files
                if ($full -match '(?i)\.rdp$') {
                    $hits = Get-FileContentEvidence -Path $full -Patterns @(
                        '(?i)^username:s:',
                        '(?i)^full address:s:',
                        '(?i)^password',
                        '(?i)^enablecredsspsupport'
                    )
                    if ($hits.Count -gt 0) {
                        $first = $hits | Select-Object -First 1
                        Add-Finding "File System" "RDP Artifact" "INFO" $full "Line $($first.Line): $($first.Snippet)" "RDP connection settings found." "Verify whether the profile should remain on disk."
                    } else {
                        Add-Finding "File System" "RDP Artifact" "INFO" $full "RDP profile present" "Remote desktop profile found." "Review for sensitive connection metadata."
                    }
                    $findings++
                    continue
                }
            }
        } catch {
            Add-Finding "File System" "Recursive Scan" "WARNING" $root $_.Exception.Message "Access restrictions or file system errors occurred while scanning the root." "Review permissions or exclude protected system paths."
        }
    }

    # ADS scan for a smaller set of locations to keep it practical
    try {
        foreach ($root in $roots | Select-Object -First 8) {
            Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch $script:Config.ExcludePathRegex } |
                ForEach-Object {
                    try {
                        $streams = Get-Item -LiteralPath $_.FullName -Stream * -ErrorAction SilentlyContinue
                        foreach ($s in $streams) {
                            if ($s.Stream -ne ':$DATA' -and $s.Stream -notmatch '^::$') {
                                Add-Finding "File System" "Alternate Data Stream" "SUSPICIOUS" $_.FullName "Stream=$($s.Stream); Length=$($s.Length)" "A non-default NTFS stream exists." "Review the stream contents."
                            }
                        }
                    } catch {}
                }
        }
    } catch {}

    if ($findings -eq 0) {
        Add-Finding "File System" "Recursive File Review" "SECURE" "Deep scan roots" "No high-risk file artifacts were found." "Deep recursive scan completed without obvious exposures." "No action required."
    } else {
        Add-Finding "File System" "Recursive File Review" "INFO" "Deep scan roots" "Files evaluated: $totalFiles; Findings: $findings" "Deep recursive scan completed." "Review the findings above."
    }
}

# =============================================================================
# 9. Event Log Threat Hunt
# =============================================================================
function Audit-EventLogThreatHunt {
    Write-Section "MODULE 7: Event Log Threat Hunting"

    if (-not (Test-CommandAvailable -Name Get-WinEvent)) {
        Add-Finding "Event Logs" "Threat Hunt" "INFO" "Get-WinEvent" "Command unavailable." "Event log review was skipped." "No action required."
        return
    }

    $start = (Get-Date).AddDays(-[Math]::Abs($script:Config.RecentDays))
    $queries = @(
        @{ LogName = "Security"; Id = 4624,4625,4672,4688,4697,4698 },
        @{ LogName = "System";   Id = 7040,7045 }
    )

    foreach ($q in $queries) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $q.LogName; StartTime = $start; Id = $q.Id } -ErrorAction SilentlyContinue
            foreach ($e in $events | Select-Object -First 50) {
                $msg = $e.Message
                if ([string]::IsNullOrWhiteSpace($msg)) { $msg = $e.ProviderName }

                $snippet = ($msg -replace '\s+', ' ').Trim()
                if ($snippet.Length -gt 240) { $snippet = $snippet.Substring(0, 240) + "..." }

                $sev = "INFO"
                if ($e.Id -in @(4625,4672,4697,4698,7045)) { $sev = "WARNING" }
                if ($e.Id -eq 7045) { $sev = "ALERT" }

                Add-Finding "Event Logs" "Event ID $($e.Id)" $sev "$($q.LogName) log" "RecordId=$($e.RecordId); TimeCreated=$($e.TimeCreated)" $snippet "Review the event in the Event Viewer for context." "Investigate the referenced event."
            }
        } catch {
            Add-Finding "Event Logs" "Threat Hunt" "WARNING" "$($q.LogName) log" $_.Exception.Message "Could not query selected event IDs." "Verify event log access."
        }
    }
}

# =============================================================================
# 10. Report Export
# =============================================================================
function Export-Reports {
    Write-Section "MODULE 8: Report Compilation"

    $global:Timer.Stop()
    $elapsedSeconds = [Math]::Round($global:Timer.Elapsed.TotalSeconds, 2)

    $criticalCount = ($global:Findings | Where-Object { $_.Severity -in @('CRITICAL','FAILED','VULNERABLE','BAD','HIGH') } | Measure-Object).Count
    $warningCount  = ($global:Findings | Where-Object { $_.Severity -in @('WARNING','ALERT','SUSPICIOUS','MEDIUM') } | Measure-Object).Count
    $secureCount   = ($global:Findings | Where-Object { $_.Severity -in @('SECURE','GOOD','OK','LOW') } | Measure-Object).Count
    $infoCount     = ($global:Findings | Where-Object { $_.Severity -in @('INFO','NOTICE') } | Measure-Object).Count

    try {
        $global:Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
    }
    catch {
        Write-Host "[WARN] CSV export failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    $summaryHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NextStep Online SysAdmin Security Audit Report</title>
<style>
body {
    font-family: Segoe UI, Arial, sans-serif;
    margin: 30px;
    background: #0a0a0a;
    color: #eaeaea;
}
h1 {
    border-left: 5px solid #5c42ff;
    padding-left: 12px;
}
.meta {
    background: #111;
    border: 1px solid #222;
    padding: 14px;
    border-radius: 6px;
    margin-bottom: 20px;
}
.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit,minmax(180px,1fr));
    gap: 14px;
    margin-bottom: 24px;
}
.card {
    padding: 16px;
    border: 1px solid #222;
    border-radius: 8px;
    background: #111;
}
.card .label {
    font-size: 12px;
    text-transform: uppercase;
    color: #999;
}
.card .value {
    font-size: 28px;
    font-weight: 700;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}
th, td {
    padding: 10px 12px;
    border-bottom: 1px solid #222;
    vertical-align: top;
}
th {
    position: sticky;
    top: 0;
    background: #151515;
}
.CRITICAL,.FAILED,.VULNERABLE,.BAD,.HIGH {
    color: #fff;
    background: #b42318;
    padding: 3px 8px;
    border-radius: 4px;
}
.WARNING,.ALERT,.SUSPICIOUS,.MEDIUM {
    color: #111;
    background: #f5a524;
    padding: 3px 8px;
    border-radius: 4px;
}
.SECURE,.GOOD,.OK,.LOW {
    color: #fff;
    background: #16794c;
    padding: 3px 8px;
    border-radius: 4px;
}
.INFO,.NOTICE {
    color: #fff;
    background: #4f46e5;
    padding: 3px 8px;
    border-radius: 4px;
}
.small {
    color: #bbb;
    font-size: 12px;
}
</style>
</head>
<body>

<h1>NextStep Online SysAdmin Security Auditor</h1>

<div class="meta">
    <div><strong>Runtime Host Execution Path:</strong> $(ConvertTo-HtmlSafeText $scriptDir)</div>
    <div><strong>Report Generation Timestamp:</strong> $(ConvertTo-HtmlSafeText (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'))</div>
    <div><strong>Subsystem Diagnostics Operational Time:</strong> $elapsedSeconds seconds</div>
</div>

<div class="grid">
    <div class="card">
        <div class="label">Critical</div>
        <div class="value">$criticalCount</div>
    </div>

    <div class="card">
        <div class="label">Warnings</div>
        <div class="value">$warningCount</div>
    </div>

    <div class="card">
        <div class="label">Secure</div>
        <div class="value">$secureCount</div>
    </div>

    <div class="card">
        <div class="label">Info</div>
        <div class="value">$infoCount</div>
    </div>

    <div class="card">
        <div class="label">Checks</div>
        <div class="value">$global:TotalChecksPerformed</div>
    </div>
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
"@

    $rows = New-Object System.Text.StringBuilder

    foreach ($f in $global:Findings) {

        $time        = ConvertTo-HtmlSafeText $f.Time
        $category    = ConvertTo-HtmlSafeText $f.Category
        $title       = ConvertTo-HtmlSafeText $f.Title
        $severity    = ConvertTo-HtmlSafeText $f.Severity
        $location    = ConvertTo-HtmlSafeText $f.Location
        $evidence    = ConvertTo-HtmlSafeText $f.Evidence
        $reason      = ConvertTo-HtmlSafeText $f.Reason
        $remediation = ConvertTo-HtmlSafeText $f.Remediation

        $severityClass = ($f.Severity -replace '[^a-zA-Z0-9_-]','')

        [void]$rows.AppendLine(@"
<tr>
<td>$time</td>
<td>$category</td>
<td>$title</td>
<td><span class="$severityClass">$severity</span></td>
<td>$location</td>
<td>$evidence</td>
<td>$reason</td>
<td>$remediation</td>
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
    }
    catch {
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
# 11. Execution
# =============================================================================
Audit-LoggingPipeline
Audit-SystemBaseline
Audit-ServicesAndFirewall
Audit-NetworkAndPorts
Audit-WifiSecurity
Audit-Persistence
Audit-DeepFileArtifacts
Audit-EventLogThreatHunt
Export-Reports