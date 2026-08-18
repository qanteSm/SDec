$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$result = @{
    chunk_id = "04_persistence"
    timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    layer_name = "OS Persistence"
    status = "completed"
    data = @{}
    findings = @()
}

$is64BitOS = [Environment]::Is64BitOperatingSystem
$is64BitProcess = [Environment]::Is64BitProcess
$isWoW64 = $is64BitOS -and (-not $is64BitProcess)

$sigCache = @{}

function Get-CachedSignature {
    param([string]$FilePath)
    if (-not $FilePath) { return @{ IsValid = $false; Status = "NoPath"; Signer = "none" } }
    $norm = $FilePath.ToLowerInvariant()
    if ($sigCache.ContainsKey($norm)) {
        return $sigCache[$norm]
    }
    if (Test-Path $FilePath -PathType Leaf) {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath
        $info = @{
            IsValid = ($sig.Status -eq 'Valid')
            Status = [string]$sig.Status
            Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "none" }
        }
        $sigCache[$norm] = $info
        return $info
    }
    $info = @{ IsValid = $false; Status = "FileNotFound"; Signer = "none" }
    $sigCache[$norm] = $info
    return $info
}

function Resolve-CleanBinaryPath {
    param([string]$RawPath)
    if (-not $RawPath) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($RawPath.Trim())
    $isExplicitlyDelimited = $false
    if ($p -match '^"([^"]+)"') {
        $p = $Matches[1].Trim()
        $isExplicitlyDelimited = $true
    } elseif ($p -match "^'([^']+)'") {
        $p = $Matches[1].Trim()
        $isExplicitlyDelimited = $true
    }
    $p = [Environment]::ExpandEnvironmentVariables($p)
    if ($p.StartsWith('\??\') -or $p.StartsWith('\\?\')) {
        $p = $p.Substring(4)
    }
    $p = $p.Replace('/', '\')

    function Test-BinaryCandidate {
        param([string]$Candidate)
        if (-not $Candidate) { return $null }
        if (Test-Path $Candidate -PathType Leaf) {
            try { return [System.IO.Path]::GetFullPath($Candidate) } catch { return $Candidate }
        }
        if ($isWoW64) {
            $sys32Prefix = "$env:SystemRoot\System32"
            if ($Candidate.StartsWith($sys32Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $alt = Join-Path (Join-Path $env:SystemRoot "Sysnative") $Candidate.Substring($sys32Prefix.Length).TrimStart('\')
                if (Test-Path $alt -PathType Leaf) {
                    try { return [System.IO.Path]::GetFullPath($alt) } catch { return $alt }
                }
            }
        }
        return $null
    }

    $direct = Test-BinaryCandidate $p
    if ($direct) { return $direct }

    if ($isExplicitlyDelimited) {
        return $p
    }

    if ($p -match '^(.*?(\.exe|\.sys|\.dll|\.bat|\.cmd|\.vbs|\.ps1|\.scr|\.hta|\.wsf|\.com|\.pif))(\s.*)?$') {
        $cand = [Environment]::ExpandEnvironmentVariables($Matches[1].Trim())
        $res = Test-BinaryCandidate $cand
        if ($res) { return $res }
    }

    $parts = $p -split '\s+'
    $testPath = ""
    for ($i = 0; $i -lt $parts.Length; $i++) {
        $testPath = if ($i -eq 0) { $parts[0] } else { "$testPath $($parts[$i])" }
        $exp = [Environment]::ExpandEnvironmentVariables($testPath)
        $res = Test-BinaryCandidate $exp
        if ($res) { return $res }
    }

    if ($p -match '^(.*?(\.exe|\.sys|\.dll|\.bat|\.cmd|\.vbs|\.ps1|\.scr|\.hta|\.wsf|\.com|\.pif))(\s.*)?$') {
        return $Matches[1].Trim()
    }
    if ($p -match '^(\S+)') {
        return $Matches[1].Trim()
    }
    return $p
}

function Get-IfeoPersistence {
    param(
        [string[]]$AccessibilityList = @('sethc.exe', 'utilman.exe', 'narrator.exe', 'magnify.exe', 'osk.exe', 'DisplaySwitch.exe', 'AtBroker.exe')
    )
    $ifeoPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    )
    if ($is64BitOS) {
        $ifeoPaths += "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    }

    $ifeoEntries = @()
    $ifeoFindings = @()
    $ifeoErrors = @()

    foreach ($basePath in $ifeoPaths) {
        if (-not (Test-Path $basePath)) { continue }
        try {
            $keys = Get-ChildItem -Path $basePath -ErrorAction Stop
            foreach ($key in $keys) {
                try {
                    $props = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop
                    $targetExe = $key.PSChildName
                    $debugger = [string]$props.Debugger
                    $verifierDlls = [string]$props.VerifierDlls

                    $isAccessibility = $false
                    foreach ($acc in $AccessibilityList) {
                        if ($targetExe.ToLowerInvariant() -eq $acc.ToLowerInvariant()) {
                            $isAccessibility = $true
                            break
                        }
                    }

                    if ($debugger -and $debugger.Trim() -ne '') {
                        $cleanDbg = Resolve-CleanBinaryPath $debugger
                        $isLegitDebugger = $false

                        if ($cleanDbg -and (Test-Path $cleanDbg -PathType Leaf)) {
                            $dbgSig = Get-CachedSignature -FilePath $cleanDbg
                            $isKnownName = $debugger -match '(?i)(vsjitdebugger\.exe|windbg\.exe|windbgx\.exe|cdb\.exe|ntsd\.exe|drwtsn32\.exe|gflags\.exe)'
                            if ($dbgSig.IsValid -and $dbgSig.Signer -match 'Microsoft' -and $isKnownName) {
                                $isLegitDebugger = $true
                            }
                        }

                        $entry = @{
                            target = $targetExe
                            registry_path = $key.PSPath
                            debugger = $debugger
                            resolved_path = $cleanDbg
                            is_legitimate_debugger = $isLegitDebugger
                            is_accessibility_target = $isAccessibility
                        }
                        $ifeoEntries += $entry

                        if ($isAccessibility -and -not $isLegitDebugger) {
                            $ifeoFindings += @{
                                id = "PERS-007"
                                severity = "HIGH"
                                mitre = "T1546.008"
                                title = "Accessibility IFEO Hijack"
                                detail = "accessibility_ifeo|$targetExe|$debugger"
                            }
                        } elseif (-not $isAccessibility -and -not $isLegitDebugger) {
                            $ifeoFindings += @{
                                id = "PERS-005"
                                severity = "HIGH"
                                mitre = "T1546.012"
                                title = "IFEO Debugger"
                                detail = "ifeo|$targetExe|$debugger"
                            }
                        }
                    }

                    if ($verifierDlls -and $verifierDlls.Trim() -ne '') {
                        $ifeoEntries += @{
                            target = $targetExe
                            registry_path = $key.PSPath
                            verifier_dlls = $verifierDlls
                        }
                        $ifeoFindings += @{
                            id = "PERS-005"
                            severity = "HIGH"
                            mitre = "T1546.012"
                            title = "IFEO Debugger"
                            detail = "ifeo_verifier_dlls|$targetExe|$verifierDlls"
                        }
                    }

                    $silentKeyPath = Join-Path $key.PSPath "SilentProcessExit"
                    if (Test-Path $silentKeyPath) {
                        try {
                            $silentProps = Get-ItemProperty -Path $silentKeyPath -ErrorAction Stop
                            $monProc = [string]$silentProps.MonitorProcess
                            if ($monProc -and $monProc.Trim() -ne '') {
                                $cleanMon = Resolve-CleanBinaryPath $monProc
                                $isLegitMon = $false
                                if ($cleanMon -and (Test-Path $cleanMon -PathType Leaf)) {
                                    $monSig = Get-CachedSignature -FilePath $cleanMon
                                    if ($monSig.IsValid -and $monSig.Signer -match 'Microsoft') {
                                        $isLegitMon = $true
                                    }
                                }
                                $ifeoEntries += @{
                                    target = $targetExe
                                    registry_path = $silentKeyPath
                                    monitor_process = $monProc
                                    resolved_path = $cleanMon
                                }
                                if (-not $isLegitMon) {
                                    $ifeoFindings += @{
                                        id = "PERS-005"
                                        severity = "HIGH"
                                        mitre = "T1546.012"
                                        title = "IFEO Debugger"
                                        detail = "ifeo_silent_exit|$targetExe|$monProc"
                                    }
                                }
                            }
                        } catch {}
                    }
                } catch {}
            }
        } catch {
            $ifeoErrors += @{ path = $basePath; reason = $_.Exception.Message }
        }
    }

    $silentBasePaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
    )
    if ($is64BitOS) {
        $silentBasePaths += "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
    }
    foreach ($sBasePath in $silentBasePaths) {
        if (-not (Test-Path $sBasePath)) { continue }
        try {
            $sKeys = Get-ChildItem -Path $sBasePath -ErrorAction Stop
            foreach ($sKey in $sKeys) {
                try {
                    $sProps = Get-ItemProperty -Path $sKey.PSPath -ErrorAction Stop
                    $monProc = [string]$sProps.MonitorProcess
                    if ($monProc -and $monProc.Trim() -ne '') {
                        $targetExe = $sKey.PSChildName
                        $cleanMon = Resolve-CleanBinaryPath $monProc
                        $isLegitMon = $false
                        if ($cleanMon -and (Test-Path $cleanMon -PathType Leaf)) {
                            $monSig = Get-CachedSignature -FilePath $cleanMon
                            if ($monSig.IsValid -and $monSig.Signer -match 'Microsoft') {
                                $isLegitMon = $true
                            }
                        }
                        $ifeoEntries += @{
                            target = $targetExe
                            registry_path = $sKey.PSPath
                            monitor_process = $monProc
                            resolved_path = $cleanMon
                        }
                        if (-not $isLegitMon) {
                            $ifeoFindings += @{
                                id = "PERS-005"
                                severity = "HIGH"
                                mitre = "T1546.012"
                                title = "IFEO Debugger"
                                detail = "ifeo_silent_exit|$targetExe|$monProc"
                            }
                        }
                    }
                } catch {}
            }
        } catch {}
    }

    return @{
        entries = $ifeoEntries
        findings = $ifeoFindings
        errors = $ifeoErrors
    }
}

function Get-AppCertDllsPersistence {
    $appCertPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCertDLLs"
    )
    if ($is64BitOS) {
        $appCertPaths += "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AppCertDLLs"
    }

    $appCertEntries = @()
    $appCertFindings = @()
    $presentKeys = @()

    foreach ($path in $appCertPaths) {
        if (-not (Test-Path $path)) { continue }
        $presentKeys += $path
        try {
            $props = Get-ItemProperty -Path $path -ErrorAction Stop
            $propNames = $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
            foreach ($prop in $propNames) {
                $rawVal = [string]$prop.Value
                $cleanPath = Resolve-CleanBinaryPath $rawVal
                $fileExists = ($cleanPath -and (Test-Path $cleanPath -PathType Leaf))
                $sigInfo = if ($fileExists) { Get-CachedSignature -FilePath $cleanPath } else { @{ IsValid = $false; Status = "FileNotFound"; Signer = "none" } }

                $entry = @{
                    registry_path = $path
                    name = $prop.Name
                    value = $rawVal
                    resolved_path = $cleanPath
                    file_exists = $fileExists
                    signature_valid = $sigInfo.IsValid
                    signer = $sigInfo.Signer
                }
                $appCertEntries += $entry

                $appCertFindings += @{
                    id = "PERS-012"
                    severity = "HIGH"
                    mitre = "T1546.009"
                    title = "AppCertDLLs Set"
                    detail = "appcert_dlls|$($prop.Name)|$rawVal"
                }
            }
        } catch {}
    }

    return @{
        key_present = ($presentKeys.Count -gt 0)
        present_keys = $presentKeys
        total_entries = $appCertEntries.Count
        entries = $appCertEntries
        findings = $appCertFindings
    }
}

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $result.data.is_admin = $isAdmin

    $regPaths = @(
        @{ path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"; scope = "machine" }
        @{ path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; scope = "machine" }
        @{ path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"; scope = "user" }
        @{ path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; scope = "user" }
        @{ path = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; scope = "machine_wow64" }
        @{ path = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"; scope = "machine_wow64" }
        @{ path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices"; scope = "user" }
        @{ path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"; scope = "machine" }
        @{ path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"; scope = "user" }
        @{ path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"; scope = "machine" }
        @{ path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"; scope = "machine_policy" }
        @{ path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"; scope = "user_policy" }
    )

    $runEntries = @()
    $runErrors = @()
    foreach ($reg in $regPaths) {
        try {
            if (-not (Test-Path $reg.path)) { continue }
            $props = Get-ItemProperty -Path $reg.path -ErrorAction Stop
            $propNames = $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
            foreach ($prop in $propNames) {
                $entry = @{
                    scope = $reg.scope
                    registry_path = $reg.path
                    name = $prop.Name
                    value = [string]$prop.Value
                }
                $runEntries += $entry

                $valLower = $prop.Value.ToString().ToLowerInvariant()
                $isCleanupCommand = ($reg.path -like "*\RunOnce" -and ($valLower -match '^cmd(\.exe)?\s+(/[qc]\s+)*(del|rmdir|rd)\s+' -or $prop.Name -match '(?i)Delete Cached' -or $prop.Name -match '(?i)Uninstall\s+\d+'))

                if (-not $isCleanupCommand) {
                    $suspicious = $valLower -match '(powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin|rundll32|regsvr32)' -or
                                  $valLower -match '(\\temp\\|\\appdata\\local\\temp|\\downloads\\|\\users\\public\\|\\perflogs\\)' -or
                                  $valLower -match '(-enc\s|-encodedcommand|frombase64|iex\s|invoke-expression|downloadstring)' -or
                                  $valLower -match '(http://|https://|ftp://)'

                    if ($suspicious) {
                        $result.findings += @{
                            id = "PERS-001"
                            severity = "HIGH"
                            mitre = "T1547.001"
                            title = "Suspicious Run Entry"
                            detail = "suspicious_run|$($prop.Name)|$($reg.path)"
                        }
                    }
                }
            }
        } catch {
            $runErrors += @{ path = $reg.path; reason = $_.Exception.Message }
        }
    }
    $result.data.run_entries = $runEntries
    if ($runErrors.Count -gt 0) {
        $result.data.run_entries_errors = $runErrors
    }

    $startupDirs = @()
    $userStartup = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs\Startup")
    if ($userStartup -and (Test-Path $userStartup)) {
        $startupDirs += @{ path = $userStartup; scope = "user" }
    }
    $commonStartup = [System.IO.Path]::Combine($env:ProgramData, "Microsoft\Windows\Start Menu\Programs\Startup")
    if ($commonStartup -and (Test-Path $commonStartup)) {
        $startupDirs += @{ path = $commonStartup; scope = "common" }
    }

    try {
        $hkcuStartup = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup" -ErrorAction SilentlyContinue).Startup
        if ($hkcuStartup) {
            $expHkcu = [Environment]::ExpandEnvironmentVariables($hkcuStartup)
            if ((Test-Path $expHkcu) -and ($startupDirs.path -notcontains $expHkcu)) {
                $startupDirs += @{ path = $expHkcu; scope = "user_custom" }
            }
        }
    } catch {}

    try {
        $hklmStartup = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Common Startup" -ErrorAction SilentlyContinue)."Common Startup"
        if ($hklmStartup) {
            $expHklm = [Environment]::ExpandEnvironmentVariables($hklmStartup)
            if ((Test-Path $expHklm) -and ($startupDirs.path -notcontains $expHklm)) {
                $startupDirs += @{ path = $expHklm; scope = "common_custom" }
            }
        }
    } catch {}

    $startupItems = @()
    foreach ($sd in $startupDirs) {
        try {
            $files = Get-ChildItem -Path $sd.path -File -ErrorAction Stop
            foreach ($file in $files) {
                $itemEntry = @{
                    scope = $sd.scope
                    directory = $sd.path
                    name = $file.Name
                    full_path = $file.FullName
                    size_kb = [Math]::Round($file.Length / 1KB, 2)
                    last_modified = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    extension = $file.Extension.ToLowerInvariant()
                }

                if ($file.Extension -eq '.lnk') {
                    try {
                        $wsh = New-Object -ComObject WScript.Shell
                        $shortcut = $wsh.CreateShortcut($file.FullName)
                        $itemEntry.target_path = $shortcut.TargetPath
                        $itemEntry.arguments = $shortcut.Arguments
                        $itemEntry.working_dir = $shortcut.WorkingDirectory

                        $tgtLower = $shortcut.TargetPath.ToLowerInvariant()
                        $argLower = if ($shortcut.Arguments) { $shortcut.Arguments.ToLowerInvariant() } else { "" }
                        $comb = "$tgtLower $argLower"

                        $isLnkSuspicious = $comb -match '(powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin|rundll32|regsvr32)' -or
                                           $comb -match '(\\temp\\|\\appdata\\local\\temp|\\downloads\\|\\users\\public\\|\\perflogs\\)' -or
                                           $comb -match '(-enc\s|-encodedcommand|frombase64|iex\s|invoke-expression|downloadstring|http://|https://)'

                        if ($isLnkSuspicious) {
                            $result.findings += @{
                                id = "PERS-001"
                                severity = "HIGH"
                                mitre = "T1547.001"
                                title = "Suspicious Startup Entry"
                                detail = "suspicious_startup_lnk|$($file.Name)|$($shortcut.TargetPath)"
                            }
                        }

                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null
                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($wsh) | Out-Null
                    } catch {}
                } elseif ($file.Extension.ToLowerInvariant() -eq '.exe') {
                    $sigInfo = Get-CachedSignature -FilePath $file.FullName
                    $itemEntry.signature_valid = $sigInfo.IsValid
                    $itemEntry.signer = $sigInfo.Signer

                    if (-not $sigInfo.IsValid) {
                        $result.findings += @{
                            id = "PERS-001"
                            severity = "HIGH"
                            mitre = "T1547.001"
                            title = "Suspicious Startup Entry"
                            detail = "unsigned_startup_executable|$($file.Name)|$($sd.path)"
                        }
                    }
                } elseif ($file.Extension.ToLowerInvariant() -in @('.bat', '.cmd', '.vbs', '.js', '.ps1', '.wsf', '.hta', '.scr', '.pif', '.com')) {
                    $isScriptSuspicious = $false
                    try {
                        $content = [System.IO.File]::ReadAllText($file.FullName)
                        $contentLower = $content.ToLowerInvariant()
                        if ($contentLower -match '(powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin|rundll32|regsvr32|downloadstring|encodedcommand|frombase64|iex\s|invoke-expression|http://|https://|ftp://)' -or
                            $file.Extension.ToLowerInvariant() -in @('.hta', '.scr', '.pif', '.com', '.wsf')) {
                            $isScriptSuspicious = $true
                        }
                    } catch {
                        $isScriptSuspicious = $true
                    }

                    if ($isScriptSuspicious) {
                        $result.findings += @{
                            id = "PERS-001"
                            severity = "HIGH"
                            mitre = "T1547.001"
                            title = "Suspicious Startup Entry"
                            detail = "suspicious_startup_script|$($file.Name)|$($sd.path)"
                        }
                    }
                }
                $startupItems += $itemEntry
            }
        } catch {
            $runErrors += @{ directory = $sd.path; reason = $_.Exception.Message }
        }
    }
    $result.data.startup_items = $startupItems

    try {
        $winlogon = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction Stop
        $result.data.winlogon = @{
            shell = $winlogon.Shell
            userinit = $winlogon.Userinit
        }

        if ($winlogon.Shell -and $winlogon.Shell.ToLowerInvariant() -ne 'explorer.exe') {
            $result.findings += @{
                id = "PERS-002"
                severity = "HIGH"
                mitre = "T1547.004"
                title = "Winlogon Shell Modified"
                detail = "winlogon_shell|$($winlogon.Shell)"
            }
        }

        $defaultUserinit = "$env:SystemRoot\system32\userinit.exe".ToLowerInvariant()
        $actualUserinit = if ($winlogon.Userinit) { $winlogon.Userinit.Trim().TrimEnd(',').ToLowerInvariant() } else { "" }

        if ($actualUserinit -and ($actualUserinit -ne $defaultUserinit)) {
            $result.findings += @{
                id = "PERS-003"
                severity = "HIGH"
                mitre = "T1547.004"
                title = "Winlogon Userinit Modified"
                detail = "winlogon_userinit|$($winlogon.Userinit)"
            }
        }
    } catch {
        $result.data.winlogon = @{
            status = "skipped"
            reason = if ($_.Exception -is [System.UnauthorizedAccessException]) { "elevation_required" } else { "access_denied" }
        }
    }

    try {
        $appinit = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction Stop
        $loadVal = $appinit.LoadAppInit_DLLs
        $dllsVal = [string]$appinit.AppInit_DLLs
        $isEnabled = ($loadVal -and [int]$loadVal -ne 0)

        $result.data.appinit_dlls = @{
            value = $dllsVal
            load_appinit = $loadVal
            is_enabled = $isEnabled
        }

        if ($isEnabled -and $dllsVal.Trim() -ne '') {
            $result.findings += @{
                id = "PERS-004"
                severity = "HIGH"
                mitre = "T1546.010"
                title = "AppInit_DLLs Set"
                detail = "appinit_dlls|$dllsVal"
            }
        }
    } catch {
        $result.data.appinit_dlls = @{
            status = "skipped"
            reason = if ($_.Exception -is [System.UnauthorizedAccessException]) { "elevation_required" } else { "access_denied" }
        }
    }

    $accessibilityTargets = @('sethc.exe', 'utilman.exe', 'narrator.exe', 'magnify.exe', 'osk.exe', 'DisplaySwitch.exe', 'AtBroker.exe')

    $ifeoRes = Get-IfeoPersistence -AccessibilityList $accessibilityTargets
    $result.data.ifeo = $ifeoRes.entries
    if ($ifeoRes.findings.Count -gt 0) {
        $result.findings += $ifeoRes.findings
    }
    if ($ifeoRes.errors.Count -gt 0) {
        $result.data.ifeo_errors = $ifeoRes.errors
    }

    $appCertRes = Get-AppCertDllsPersistence
    $result.data.appcert_dlls = @{
        key_present = $appCertRes.key_present
        present_keys = $appCertRes.present_keys
        total_entries = $appCertRes.total_entries
        entries = $appCertRes.entries
    }
    if ($appCertRes.findings.Count -gt 0) {
        $result.findings += $appCertRes.findings
    }

    $accessBackdoors = @()
    try {
        foreach ($target in $accessibilityTargets) {
            $targetPath = Join-Path "$env:SystemRoot\System32" $target
            if (Test-Path $targetPath -PathType Leaf) {
                $fileInfo = Get-Item $targetPath
                $sigInfo = Get-CachedSignature -FilePath $targetPath

                $entry = @{
                    file = $target
                    path = $targetPath
                    size_kb = [Math]::Round($fileInfo.Length / 1KB, 2)
                    last_modified = $fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    signature_valid = $sigInfo.IsValid
                    signer = $sigInfo.Signer
                }
                $accessBackdoors += $entry

                if (-not $sigInfo.IsValid) {
                    $result.findings += @{
                        id = "PERS-006"
                        severity = "HIGH"
                        mitre = "T1546.008"
                        title = "Accessibility Backdoor"
                        detail = "accessibility_backdoor|$target|sig:$($sigInfo.Status)"
                    }
                }
            }
        }
        $result.data.accessibility_checks = $accessBackdoors
    } catch {
        $result.data.accessibility_checks = @{
            status = "skipped"
            reason = "access_denied"
        }
    }

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' }
        $suspiciousTasks = @()
        foreach ($task in $tasks) {
            $actions = $task.Actions
            foreach ($action in $actions) {
                if (-not $action.Execute) { continue }
                $execLower = $action.Execute.ToLowerInvariant()
                $argsLower = if ($action.Arguments) { $action.Arguments.ToLowerInvariant() } else { "" }
                $combined = "$execLower $argsLower"

                $isSuspicious = $combined -match '(powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin|rundll32|regsvr32)' -and
                               ($combined -match '(http|ftp|\\temp\\|\\appdata\\|downloadstring|encodedcommand|-enc\s|iex\s|frombase64|invoke-expression|hidden)')

                $isFromTemp = $execLower -match '(\\temp\\|\\appdata\\local\\temp|\\downloads\\|\\users\\public\\|\\perflogs\\)'

                if ($isSuspicious -or $isFromTemp) {
                    $suspiciousTasks += @{
                        name = $task.TaskName
                        path = $task.TaskPath
                        state = [string]$task.State
                        execute = $action.Execute
                        arguments = $action.Arguments
                        triggers = @($task.Triggers | ForEach-Object { [string]$_ })
                    }

                    $result.findings += @{
                        id = "PERS-008"
                        severity = "HIGH"
                        mitre = "T1053.005"
                        title = "Suspicious Scheduled Task"
                        detail = "suspicious_task|$($task.TaskName)|$($action.Execute)"
                    }
                }
            }
        }
        $result.data.scheduled_tasks = @{
            total_active = $tasks.Count
            suspicious = $suspiciousTasks
        }
    } catch {
        $result.data.scheduled_tasks = @{
            status = "skipped"
            reason = if ($_.Exception -is [System.UnauthorizedAccessException]) { "elevation_required" } else { "task_query_failed" }
        }
    }

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name, DisplayName, State, StartMode, PathName, StartName, Description
        $suspiciousServices = @()
        foreach ($svc in $services) {
            if (-not $svc.PathName) { continue }
            $pathLower = $svc.PathName.ToLowerInvariant()

            $isSuspicious = $false
            $reasons = @()

            if ($pathLower -match '(\\temp\\|\\appdata\\|\\downloads\\|\\users\\public\\|\\perflogs\\)') {
                $isSuspicious = $true
                $reasons += "runs_from_temp_or_user_dir"
            }

            $cleanPath = Resolve-CleanBinaryPath $svc.PathName
            $fileExists = ($cleanPath -and (Test-Path $cleanPath -PathType Leaf))

            if ($fileExists) {
                if ($svc.StartMode -eq 'Auto') {
                    $sigInfo = Get-CachedSignature -FilePath $cleanPath
                    if (-not $sigInfo.IsValid) {
                        $isSuspicious = $true
                        $reasons += "unsigned_auto_start"
                    }
                }
            } else {
                if ($svc.StartMode -eq 'Auto' -or $svc.State -eq 'Running') {
                    $isSuspicious = $true
                    $reasons += "missing_service_binary"
                }
            }

            $rawTrimmed = $svc.PathName.Trim()
            if (-not $rawTrimmed.StartsWith('"') -and -not $rawTrimmed.StartsWith("'")) {
                if ($rawTrimmed -match '^[a-zA-Z]:\\[^"]*\s+[^"]*(\.exe|\.sys|\s)' -and ($rawTrimmed -notmatch '(?i)^C:\\Windows\\System32\\svchost\.exe')) {
                    $reasons += "unquoted_path_with_spaces"
                }
            }

            if (-not $svc.Description -and $svc.StartMode -eq 'Auto' -and $svc.State -eq 'Running') {
                $reasons += "no_description"
            }

            if ($isSuspicious) {
                $svcSeverity = if ($reasons -contains "runs_from_temp_or_user_dir") {
                    "HIGH"
                } elseif ($svc.State -eq 'Running' -and ($reasons -contains "missing_service_binary" -or $reasons -contains "unsigned_auto_start")) {
                    "MEDIUM"
                } else {
                    "LOW"
                }

                $suspiciousServices += @{
                    name = $svc.Name
                    display_name = $svc.DisplayName
                    state = $svc.State
                    start_mode = $svc.StartMode
                    path = $svc.PathName
                    clean_path = $cleanPath
                    run_as = $svc.StartName
                    reasons = $reasons
                    severity = $svcSeverity
                }

                $result.findings += @{
                    id = "PERS-009"
                    severity = $svcSeverity
                    mitre = "T1543.003"
                    title = "Suspicious Service"
                    detail = "suspicious_service|$($svc.Name)|$($reasons -join ',')"
                }
            }
        }
        $result.data.services = @{
            total = $services.Count
            running = ($services | Where-Object { $_.State -eq 'Running' }).Count
            suspicious = $suspiciousServices
        }
    } catch {
        $result.data.services = @{
            status = "skipped"
            reason = if ($_.Exception -is [System.UnauthorizedAccessException]) { "elevation_required" } else { "service_query_failed" }
        }
    }

    try {
        $filters = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction Stop)
        $consumers = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction Stop)
        $bindings = @(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop)

        $wmiFindings = @()
        $suspiciousWmiCount = 0

        $filterMap = @{}
        foreach ($filter in $filters) {
            $filterMap[$filter.Name] = $filter
            $wmiFindings += @{
                type = "EventFilter"
                name = $filter.Name
                query = $filter.Query
                query_language = $filter.QueryLanguage
            }
        }

        $defaultConsumers = @('SCM Event Log Consumer', 'BVTFilter', 'NTEventLogEventConsumer')

        foreach ($consumer in $consumers) {
            $className = if ($consumer.CimSystemProperties.ClassName) {
                $consumer.CimSystemProperties.ClassName
            } elseif ($consumer.CimClass) {
                $consumer.CimClass.CimClassName
            } else {
                [string]$consumer.PSObject.TypeNames[0]
            }

            $consumerInfo = @{
                type = "EventConsumer"
                name = $consumer.Name
                class = $className
            }

            $isSuspiciousConsumer = $false
            if ($className -eq 'CommandLineEventConsumer') {
                $consumerInfo.command = $consumer.CommandLineTemplate
                $consumerInfo.executable = $consumer.ExecutablePath
                if ($defaultConsumers -notcontains $consumer.Name) {
                    $isSuspiciousConsumer = $true
                }
            } elseif ($className -eq 'ActiveScriptEventConsumer') {
                $consumerInfo.script_engine = $consumer.ScriptingEngine
                $consumerInfo.script_text = if ($consumer.ScriptText.Length -gt 300) { $consumer.ScriptText.Substring(0, 300) } else { $consumer.ScriptText }
                if ($defaultConsumers -notcontains $consumer.Name) {
                    $isSuspiciousConsumer = $true
                }
            }
            $wmiFindings += $consumerInfo

            if ($isSuspiciousConsumer) {
                $suspiciousWmiCount++
            }
        }

        foreach ($binding in $bindings) {
            $wmiFindings += @{
                type = "Binding"
                filter = [string]$binding.Filter
                consumer = [string]$binding.Consumer
            }
        }

        $result.data.wmi_subscriptions = @{
            total_items = $wmiFindings.Count
            filters_count = $filters.Count
            consumers_count = $consumers.Count
            bindings_count = $bindings.Count
            items = $wmiFindings
        }

        if ($suspiciousWmiCount -gt 0 -and $bindings.Count -gt 0) {
            $result.findings += @{
                id = "PERS-010"
                severity = "HIGH"
                mitre = "T1546.003"
                title = "WMI Event Subscription"
                detail = "wmi_persistence|suspicious_consumers:$suspiciousWmiCount|bindings:$($bindings.Count)"
            }
        }
    } catch {
        $result.data.wmi_subscriptions = @{
            status = "skipped"
            reason = if ($_.Exception -is [System.UnauthorizedAccessException]) { "elevation_required" } else { "wmi_subscription_query_failed" }
        }
    }

    $comHijacks = @()
    $clsidRoots = @(
        @{ rel = "Software\Classes\CLSID"; scope = "user" }
        @{ rel = "Software\Classes\WOW6432Node\CLSID"; scope = "user_wow64" }
    )

    $knownHijackTargets = @{
        "{06290BD3-48AA-11D2-8432-006008C3FBFC}" = "ScriptletURL"
        "{49B2791A-B1AE-4C90-9B8E-E860BA07F889}" = "MMC20.Application"
        "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}" = "ShellWindows"
        "{BCDE0395-E52F-467C-8E3D-C4579291692E}" = "MMDeviceEnumerator"
        "{F564446D-D753-4A4B-B78B-78D4E0E2E213}" = "CAccPropServices"
        "{B54F3741-5B07-11CF-A4B0-00AA004A55E8}" = "VBSScript"
        "{F414C260-6AC0-11CF-B6D1-00AA00BBBB58}" = "JScript"
    }

    try {
        $hklmClsid = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("Software\Classes\CLSID")
        $hklmWowClsid = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("Software\Classes\WOW6432Node\CLSID")

        $totalScannedClsid = 0

        foreach ($item in $clsidRoots) {
            $hkcuClsid = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($item.rel)
            if ($hkcuClsid) {
                $subKeyNames = $hkcuClsid.GetSubKeyNames()
                $totalScannedClsid += $subKeyNames.Count

                foreach ($sub in $subKeyNames) {
                    $subKey = $hkcuClsid.OpenSubKey($sub)
                    if ($subKey) {
                        foreach ($serverSubName in @("InprocServer32", "LocalServer32", "TreatAs")) {
                            $srvKey = $subKey.OpenSubKey($serverSubName)
                            if ($srvKey) {
                                $val = [string]$srvKey.GetValue("")
                                $threading = [string]$srvKey.GetValue("ThreadingModel")
                                if ($val) {
                                    $isSuspicious = $false
                                    $isHklmOverride = $false
                                    $reasons = @()
                                    $cleanVal = $null

                                    if ($serverSubName -eq "TreatAs") {
                                        $targetClsid = $val.Trim()
                                        $targetUpper = $targetClsid.ToUpperInvariant()

                                        $hklmMatch = $null
                                        if ($item.rel -like "*WOW6432Node*") {
                                            if ($hklmWowClsid) { $hklmMatch = $hklmWowClsid.OpenSubKey($sub) }
                                        } else {
                                            if ($hklmClsid) { $hklmMatch = $hklmClsid.OpenSubKey($sub) }
                                        }

                                        if ($hklmMatch) {
                                            $hklmTreat = $hklmMatch.OpenSubKey("TreatAs")
                                            if ($hklmTreat) {
                                                $hklmVal = [string]$hklmTreat.GetValue("")
                                                if ($hklmVal -and ($hklmVal.ToUpperInvariant() -ne $targetUpper)) {
                                                    $isHklmOverride = $true
                                                    $reasons += "hklm_treatas_override"
                                                }
                                                $hklmTreat.Close()
                                            } else {
                                                $isHklmOverride = $true
                                                $reasons += "user_treatas_redirect"
                                            }
                                            $hklmMatch.Close()
                                        }

                                        $upperGuid = $sub.ToUpperInvariant()
                                        if ($knownHijackTargets.ContainsKey($upperGuid)) {
                                            $isSuspicious = $true
                                            $reasons += "known_hijack_target:$($knownHijackTargets[$upperGuid])"
                                        }
                                    } else {
                                        $valLower = $val.ToLowerInvariant()
                                        $isTemp = $valLower -match '(\\temp\\|\\appdata\\local\\temp|\\downloads\\|\\users\\public\\|\\perflogs\\)'
                                        $isLolbin = $valLower -match '(powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin|rundll32|scrobj\.dll|regsvr32)'
                                        $upperGuid = $sub.ToUpperInvariant()
                                        $isKnownTarget = $knownHijackTargets.ContainsKey($upperGuid)

                                        $hklmMatch = $null
                                        if ($item.rel -like "*WOW6432Node*") {
                                            if ($hklmWowClsid) { $hklmMatch = $hklmWowClsid.OpenSubKey($sub) }
                                        } else {
                                            if ($hklmClsid) { $hklmMatch = $hklmClsid.OpenSubKey($sub) }
                                        }

                                        if ($hklmMatch) {
                                            $hklmSrv = $hklmMatch.OpenSubKey($serverSubName)
                                            if ($hklmSrv) {
                                                $hklmVal = [string]$hklmSrv.GetValue("")
                                                if ($hklmVal -and ($hklmVal.ToLowerInvariant() -ne $valLower)) {
                                                    $isHklmOverride = $true
                                                    $reasons += "hklm_override"
                                                }
                                                $hklmSrv.Close()
                                            }
                                            $hklmMatch.Close()
                                        }

                                        $cleanVal = Resolve-CleanBinaryPath $val
                                        $fileExists = ($cleanVal -and (Test-Path $cleanVal -PathType Leaf))
                                        $sigInfo = if ($fileExists) { Get-CachedSignature -FilePath $cleanVal } else { $null }
                                        $isSignedValid = ($sigInfo -and $sigInfo.IsValid)

                                        if ($isLolbin) {
                                            $isSuspicious = $true
                                            $reasons += "lolbin_or_script_engine"
                                        }
                                        if ($isKnownTarget) {
                                            $isSuspicious = $true
                                            $reasons += "known_hijack_target:$($knownHijackTargets[$upperGuid])"
                                        }
                                        if ($isTemp -and $fileExists -and -not $isSignedValid) {
                                            $isSuspicious = $true
                                            $reasons += "runs_from_temp_or_public_dir"
                                        }
                                        if ($isHklmOverride -and $fileExists -and -not $isSignedValid) {
                                            $isSuspicious = $true
                                            if ($serverSubName -eq "InprocServer32") {
                                                $reasons += "unsigned_user_inproc_dll"
                                            } else {
                                                $reasons += "unsigned_user_local_exe"
                                            }
                                        }
                                    }

                                    $entry = @{
                                        clsid = $sub
                                        scope = $item.scope
                                        server_type = $serverSubName
                                        server_path = $val
                                        clean_path = $cleanVal
                                        threading_model = $threading
                                        is_suspicious = $isSuspicious
                                        reasons = $reasons
                                    }

                                    if ($isSuspicious) {
                                        $comHijacks += $entry
                                        $result.findings += @{
                                            id = "PERS-011"
                                            severity = "HIGH"
                                            mitre = "T1546.015"
                                            title = "COM Object Hijack"
                                            detail = "com_hijack|$sub|$serverSubName|$($reasons -join ',')"
                                        }
                                    }
                                }
                                $srvKey.Close()
                            }
                        }
                        $subKey.Close()
                    }
                }
                $hkcuClsid.Close()
            }
        }

        if ($hklmClsid) { $hklmClsid.Close() }
        if ($hklmWowClsid) { $hklmWowClsid.Close() }

        $result.data.com_hijacks = @{
            total_user_clsid_scanned = $totalScannedClsid
            suspicious_count = $comHijacks.Count
            suspicious = $comHijacks
        }
    } catch {
        $result.data.com_hijacks = @{
            status = "skipped"
            reason = "registry_access_denied"
        }
    }

} catch {
    $result.status = "error"
    $result.data.error = $_.Exception.Message
}

$json = $result | ConvertTo-Json -Depth 10 -Compress
$utf8NoBom = New-Object System.Text.UTF8Encoding $false

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { (Get-Location).Path }
$chunkDir = [System.IO.Path]::GetFullPath((Join-Path $scriptDir "..\chunks"))
if (-not (Test-Path $chunkDir)) {
    New-Item -ItemType Directory -Path $chunkDir -Force | Out-Null
}
$chunkPath = Join-Path $chunkDir "chunk_04_persistence.json"
[System.IO.File]::WriteAllText($chunkPath, $json, $utf8NoBom)
