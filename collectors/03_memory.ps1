$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$result = @{
    chunk_id = "03_memory"
    timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    layer_name = "Memory & Runtime"
    status = "completed"
    data = @{}
    findings = @()
}

function Normalize-PathStr {
    param([string]$PathVal)
    if (-not $PathVal) { return "" }
    $p = $PathVal.Trim().Trim('"').Trim("'")
    if ($p.StartsWith('\\?\') -or $p.StartsWith('\??\')) {
        $p = $p.Substring(4)
    }
    $p = $p.Replace('/', '\')
    if ($p -like "*\Sysnative\*") {
        $p = $p -replace '(?i)\\sysnative\\', '\System32\'
    }
    try {
        if ([System.IO.Path]::IsPathRooted($p)) {
            return [System.IO.Path]::GetFullPath($p)
        }
    } catch {}
    return $p
}

function Get-SigStr {
    param([string]$b64)
    if (-not $b64) { return "" }
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
}

$is64BitOS = [Environment]::Is64BitOperatingSystem
$is64BitProcess = [Environment]::Is64BitProcess
$isWoW64 = $is64BitOS -and (-not $is64BitProcess)

$sys32 = "$env:SystemRoot\System32"
$syswow64 = "$env:SystemRoot\SysWOW64"
$sysnative = if ($isWoW64) { "$env:SystemRoot\Sysnative" } else { $sys32 }
$sysroot = "$env:SystemRoot"
$sysapps = "$env:SystemRoot\SystemApps"

$knownSystemProcesses = @{
    'smss.exe' = @("$sys32\smss.exe")
    'csrss.exe' = @("$sys32\csrss.exe")
    'wininit.exe' = @("$sys32\wininit.exe")
    'winlogon.exe' = @("$sys32\winlogon.exe")
    'services.exe' = @("$sys32\services.exe")
    'lsass.exe' = @("$sys32\lsass.exe")
    'lsaiso.exe' = @("$sys32\lsaiso.exe")
    'svchost.exe' = @("$sys32\svchost.exe")
    'explorer.exe' = @("$sysroot\explorer.exe", "$syswow64\explorer.exe")
    'dwm.exe' = @("$sys32\dwm.exe")
    'taskhostw.exe' = @("$sys32\taskhostw.exe", "$syswow64\taskhostw.exe")
    'conhost.exe' = @("$sys32\conhost.exe", "$syswow64\conhost.exe")
    'runtimebroker.exe' = @("$sys32\RuntimeBroker.exe", "$syswow64\RuntimeBroker.exe", "$sysapps")
    'sihost.exe' = @("$sys32\sihost.exe")
    'fontdrvhost.exe' = @("$sys32\fontdrvhost.exe")
    'spoolsv.exe' = @("$sys32\spoolsv.exe")
    'ctfmon.exe' = @("$sys32\ctfmon.exe", "$syswow64\ctfmon.exe")
    'securityhealthservice.exe' = @("$sys32\SecurityHealthService.exe")
    'searchindexer.exe' = @("$sys32\SearchIndexer.exe")
}

$lookalikeProcesses = @(
    'scvhost.exe', 'svhost.exe', 'svch0st.exe', 'scvhost32.exe',
    'lsas.exe', 'lssas.exe', 'lsassa.exe', 'lsasss.exe',
    'csrs.exe', 'csrsss.exe', 'crss.exe',
    'smss32.exe', 'smss64.exe',
    'winlog0n.exe', 'winlogon32.exe', 'wininit32.exe',
    'explorerr.exe', 'explorer32.exe', 'iexplore32.exe',
    'taskh0st.exe', 'taskhost32.exe', 'conh0st.exe', 'conhost32.exe',
    'dwm32.exe', 'spoolsv32.exe', 'services32.exe'
)

$lolbinsPatterns = @(
    @{ binary = 'certutil.exe'; patterns = @('-urlcache', '-split', '-f ', '-decode', '-encode', '-verifyctl') }
    @{ binary = 'bitsadmin.exe'; patterns = @('/transfer', '/create', '/addfile') }
    @{ binary = 'mshta.exe'; patterns = @('javascript:', 'vbscript:', 'http://', 'https://', 'about:') }
    @{ binary = 'rundll32.exe'; patterns = @('javascript:', 'shell32.dll,ShellExec_RunDLL', 'url.dll,FileProtocolHandler', 'advpack.dll', 'ieadvpack.dll', 'syssetup.dll', 'setupapi.dll') }
    @{ binary = 'regsvr32.exe'; patterns = @('/s /i:http', '/s /i:https', 'scrobj.dll', '/i:http', '/i:https') }
    @{ binary = 'wmic.exe'; patterns = @('process call create', '/node:', 'shadowcopy delete', 'os get') }
    @{ binary = 'cmstp.exe'; patterns = @('/ni', '/s', '.inf') }
    @{ binary = 'msiexec.exe'; patterns = @('/q http', '/q https', 'http://', 'https://') }
    @{ binary = 'forfiles.exe'; patterns = @('/c cmd', '/c powershell', '/c cscript') }
    @{ binary = 'pcalua.exe'; patterns = @('-a cmd', '-a powershell', '-a rundll32') }
    @{ binary = 'cscript.exe'; patterns = @('//e:jscript', '//e:vbscript', 'http://', 'https://') }
    @{ binary = 'wscript.exe'; patterns = @('//e:jscript', '//e:vbscript', 'http://', 'https://') }
    @{ binary = 'vssadmin.exe'; patterns = @('delete shadows', 'resize shadowstorage') }
    @{ binary = 'wevtutil.exe'; patterns = @('cl ', 'clear-log') }
    @{ binary = 'bcdedit.exe'; patterns = @('recoveryenabled no', 'bootstatuspolicy ignoreallfailures') }
    @{ binary = 'wbadmin.exe'; patterns = @('delete catalog', 'delete systemstatebackup') }
)

$suspiciousParents = @{
    'winword.exe' = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'rundll32.exe', 'regsvr32.exe', 'wmic.exe', 'schtasks.exe', 'vssadmin.exe', 'curl.exe')
    'excel.exe' = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'rundll32.exe', 'regsvr32.exe', 'wmic.exe', 'schtasks.exe', 'vssadmin.exe', 'curl.exe')
    'powerpnt.exe' = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'rundll32.exe', 'regsvr32.exe', 'wmic.exe', 'schtasks.exe', 'vssadmin.exe', 'curl.exe')
    'outlook.exe' = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'rundll32.exe', 'regsvr32.exe', 'wmic.exe', 'schtasks.exe', 'vssadmin.exe', 'curl.exe')
    'msaccess.exe' = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe', 'rundll32.exe')
    'eqnedt32.exe' = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'curl.exe')
    'acrord32.exe' = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'bitsadmin.exe')
    'acrobat.exe' = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'bitsadmin.exe')
    'wmiprvse.exe' = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'wscript.exe', 'cscript.exe')
    'sqlservr.exe' = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'whoami.exe', 'net.exe', 'net1.exe', 'bitsadmin.exe', 'certutil.exe')
    'w3wp.exe' = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'whoami.exe', 'net.exe', 'net1.exe', 'certutil.exe')
}

$sigMimikatz = Get-SigStr "SW52b2tlLU1pbWlrYXR6"
$sigShellcode = Get-SigStr "SW52b2tlLVNoZWxsY29kZQ=="
$sigReflective = Get-SigStr "SW52b2tlLVJlZmxlY3RpdmVQRUluamVjdGlvbg=="
$sigAmsiUtils = Get-SigStr "QW1zaVV0aWxz"
$sigAmsiFailed = Get-SigStr "YW1zaUluaXRGYWlsZWQ="
$sigAmsiScan = Get-SigStr "QW1zaVNjYW5CdWZmZXI="
$sigDumpCreds = Get-SigStr "RHVtcENyZWRz"
$sigSafetyKatz = Get-SigStr "U2FmZXR5S2F0eg=="
$sigRubeus = Get-SigStr "UnViZXVz"
$sigSharpHound = Get-SigStr "U2hhcnBIb3VuZA=="
$sigVirtualAlloc = Get-SigStr "VmlydHVhbEFsbG9j"
$sigWriteMem = Get-SigStr "V3JpdGVQcm9jZXNzTWVtb3J5"
$sigCreateThread = Get-SigStr "Q3JlYXRlUmVtb3RlVGhyZWFk"

try {
    $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId, ExecutablePath, CommandLine, CreationDate

    $processMap = @{}
    foreach ($proc in $processes) {
        $processMap[$proc.ProcessId] = $proc
    }

    $result.data.total_processes = $processes.Count

    $masquerading = @()
    foreach ($proc in $processes) {
        if (-not $proc.Name) { continue }
        $procNameLower = $proc.Name.Trim().ToLower()

        if ($procNameLower -in $lookalikeProcesses) {
            $masquerading += @{
                pid = $proc.ProcessId
                name = $proc.Name
                type = "lookalike_typosquatting"
                actual_path = $proc.ExecutablePath
                command_line = if ($proc.CommandLine.Length -gt 300) { $proc.CommandLine.Substring(0, 300) } else { $proc.CommandLine }
            }
            $result.findings += @{
                id = "MEM-001"
                severity = "HIGH"
                mitre = "T1036.005"
                title = "Process Masquerading"
                detail = "typosquatting|$($proc.Name)|PID:$($proc.ProcessId)|$($proc.ExecutablePath)"
            }
            continue
        }

        $procPath = if ($proc.ExecutablePath) { $proc.ExecutablePath } else {
            if ($proc.CommandLine) {
                $trimmedCmd = $proc.CommandLine.Trim()
                if ($trimmedCmd -match '^"([^"]+)"') { $Matches[1] } elseif ($trimmedCmd -match '^(\S+)') { $Matches[1] } else { $null }
            } else { $null }
        }

        if ($knownSystemProcesses.ContainsKey($procNameLower) -and $procPath) {
            $actualNorm = Normalize-PathStr $procPath
            $actualLower = $actualNorm.ToLower()

            $isMatch = $false
            foreach ($allowed in $knownSystemProcesses[$procNameLower]) {
                $allowedNorm = Normalize-PathStr $allowed
                $allowedLower = $allowedNorm.ToLower()
                if ($allowedLower.EndsWith('.exe')) {
                    if ($actualLower -eq $allowedLower) {
                        $isMatch = $true
                        break
                    }
                } else {
                    if ($actualLower.StartsWith($allowedLower)) {
                        $isMatch = $true
                        break
                    }
                }
            }

            if (-not $isMatch) {
                $isSuspiciousLoc = $actualLower -like "*\users\*" -or $actualLower -like "*\appdata\*" -or $actualLower -like "*\temp\*" -or $actualLower -like "*\downloads\*" -or $actualLower -like "*\desktop\*" -or $actualLower -like "*\programdata\*" -or $actualLower -like "*\perflogs\*" -or $actualLower -like "*\intel\*"

                $masquerading += @{
                    pid = $proc.ProcessId
                    name = $proc.Name
                    expected_paths = $knownSystemProcesses[$procNameLower]
                    actual_path = $actualNorm
                    is_suspicious_location = $isSuspiciousLoc
                    command_line = if ($proc.CommandLine.Length -gt 300) { $proc.CommandLine.Substring(0, 300) } else { $proc.CommandLine }
                }

                $result.findings += @{
                    id = "MEM-001"
                    severity = "HIGH"
                    mitre = "T1036.005"
                    title = "Process Masquerading"
                    detail = "masquerading|$($proc.Name)|PID:$($proc.ProcessId)|$actualNorm"
                }
            }
        }
    }
    $result.data.masquerading = $masquerading

    $parentChildAnomalies = @()
    foreach ($proc in $processes) {
        if (-not $proc.ParentProcessId) { continue }
        $parent = $processMap[$proc.ParentProcessId]
        if (-not $parent) { continue }

        $isPidRecycled = $false
        if ($parent.CreationDate -and $proc.CreationDate) {
            if ($parent.CreationDate -gt $proc.CreationDate) {
                $isPidRecycled = $true
            }
        }
        if ($isPidRecycled) { continue }

        $parentNameLower = $parent.Name.Trim().ToLower()
        $childNameLower = $proc.Name.Trim().ToLower()

        if ($suspiciousParents.ContainsKey($parentNameLower)) {
            if ($childNameLower -in $suspiciousParents[$parentNameLower]) {
                $parentChildAnomalies += @{
                    child_pid = $proc.ProcessId
                    child_name = $proc.Name
                    child_path = $proc.ExecutablePath
                    parent_pid = $parent.ProcessId
                    parent_name = $parent.Name
                    command_line = if ($proc.CommandLine.Length -gt 300) { $proc.CommandLine.Substring(0, 300) } else { $proc.CommandLine }
                }

                $result.findings += @{
                    id = "MEM-002"
                    severity = "HIGH"
                    mitre = "T1059"
                    title = "Suspicious Parent-Child"
                    detail = "parent_child|$($parent.Name)->$($proc.Name)|PID:$($proc.ProcessId)"
                }
            }
        }

        if ($childNameLower -eq 'svchost.exe') {
            if ($parentNameLower -ne 'services.exe') {
                $parentChildAnomalies += @{
                    child_pid = $proc.ProcessId
                    child_name = $proc.Name
                    parent_pid = $parent.ProcessId
                    parent_name = $parent.Name
                    anomaly = "svchost_wrong_parent"
                }

                $result.findings += @{
                    id = "MEM-003"
                    severity = "HIGH"
                    mitre = "T1036.005"
                    title = "Svchost Wrong Parent"
                    detail = "svchost_parent|$($parent.Name)|PID:$($proc.ProcessId)"
                }
            }
        }

        if ($childNameLower -eq 'lsass.exe') {
            if ($parentNameLower -ne 'wininit.exe') {
                $parentChildAnomalies += @{
                    child_pid = $proc.ProcessId
                    child_name = $proc.Name
                    parent_pid = $parent.ProcessId
                    parent_name = $parent.Name
                    anomaly = "lsass_wrong_parent"
                }

                $result.findings += @{
                    id = "MEM-002"
                    severity = "HIGH"
                    mitre = "T1059"
                    title = "Suspicious Parent-Child"
                    detail = "lsass_parent|$($parent.Name)|PID:$($proc.ProcessId)"
                }
            }
        }
    }
    $result.data.parent_child_anomalies = $parentChildAnomalies

    $lolbinHits = @()
    foreach ($proc in $processes) {
        if (-not $proc.CommandLine) { continue }
        $cmdRaw = $proc.CommandLine
        if ($cmdRaw -like "*\collectors\*" -or $cmdRaw -like "*sdec_run.bat*" -or $cmdRaw -like "*analyzer\engine.py*" -or $cmdRaw -like "*scratch\*") {
            continue
        }

        $cmdLower = $cmdRaw.ToLower()
        $procNameLower = $proc.Name.Trim().ToLower()

        foreach ($lol in $lolbinsPatterns) {
            if ($procNameLower -eq $lol.binary) {
                foreach ($pattern in $lol.patterns) {
                    if ($cmdLower -like "*$($pattern.ToLower())*") {
                        $lolbinHits += @{
                            pid = $proc.ProcessId
                            name = $proc.Name
                            path = $proc.ExecutablePath
                            matched_pattern = $pattern
                            command_line = if ($proc.CommandLine.Length -gt 500) { $proc.CommandLine.Substring(0, 500) } else { $proc.CommandLine }
                        }

                        $result.findings += @{
                            id = "MEM-004"
                            severity = "HIGH"
                            mitre = "T1218"
                            title = "LOLBin Activity"
                            detail = "lolbin|$($proc.Name)|pattern:$pattern|PID:$($proc.ProcessId)"
                        }
                        break
                    }
                }
            }
        }

        if ($procNameLower -eq 'powershell.exe' -or $procNameLower -eq 'pwsh.exe') {
            $psPatterns = @(
                '-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{10,}'
                '(DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|iwr|irm).*(\||;).*(IEX|Invoke-Expression)'
                '\[System\.Runtime\.InteropServices\.Marshal\]::'
                "$sigVirtualAlloc|$sigWriteMem|$sigCreateThread"
                "$sigAmsiUtils|$sigAmsiFailed|$sigAmsiScan"
                'FromBase64String.*DeflateStream|FromBase64String.*GZipStream'
                "$sigMimikatz|$sigShellcode|$sigReflective"
            )
            foreach ($psp in $psPatterns) {
                if ($cmdRaw -match $psp) {
                    $lolbinHits += @{
                        pid = $proc.ProcessId
                        name = $proc.Name
                        path = $proc.ExecutablePath
                        matched_pattern = $psp
                        command_line = if ($proc.CommandLine.Length -gt 500) { $proc.CommandLine.Substring(0, 500) } else { $proc.CommandLine }
                    }

                    $result.findings += @{
                        id = "MEM-004"
                        severity = "HIGH"
                        mitre = "T1218"
                        title = "LOLBin Activity"
                        detail = "lolbin|$($proc.Name)|pattern:$psp|PID:$($proc.ProcessId)"
                    }
                    break
                }
            }
        }
    }
    $result.data.lolbin_detections = $lolbinHits

    $hollowingSuspects = @()
    $allowedWrappers = @{
        'conhost' = @('cmd', 'powershell', 'pwsh', 'wsl', 'bash')
    }
    foreach ($proc in $processes) {
        if (-not $proc.ExecutablePath -or -not $proc.CommandLine) { continue }

        $cmdBinRaw = ""
        $trimmedCmd = $proc.CommandLine.Trim()
        if ($trimmedCmd -match '^"([^"]+)"') {
            $cmdBinRaw = $Matches[1]
        } elseif ($trimmedCmd -match '^(\S+)') {
            $cmdBinRaw = $Matches[1]
        }

        if ($cmdBinRaw) {
            $cmdBinNorm = Normalize-PathStr $cmdBinRaw
            $cmdBase = [System.IO.Path]::GetFileNameWithoutExtension($cmdBinNorm).ToLower()
            $exeNorm = Normalize-PathStr $proc.ExecutablePath
            $exeBase = [System.IO.Path]::GetFileNameWithoutExtension($exeNorm).ToLower()

            if ($cmdBase -and $exeBase -and ($cmdBase -ne $exeBase)) {
                $isAllowed = $false
                if ($allowedWrappers.ContainsKey($exeBase) -and ($cmdBase -in $allowedWrappers[$exeBase])) {
                    $isAllowed = $true
                }
                if (-not $isAllowed -and ($cmdBinNorm.EndsWith('.exe') -or [System.IO.File]::Exists($cmdBinNorm))) {
                    $hollowingSuspects += @{
                        pid = $proc.ProcessId
                        name = $proc.Name
                        executable_path = $exeNorm
                        command_line_binary = $cmdBinNorm
                        full_command = if ($proc.CommandLine.Length -gt 300) { $proc.CommandLine.Substring(0, 300) } else { $proc.CommandLine }
                    }

                    $result.findings += @{
                        id = "MEM-001"
                        severity = "HIGH"
                        mitre = "T1036.005"
                        title = "Process Masquerading"
                        detail = "hollowing_mismatch|$($proc.Name)|exe:$exeBase|cmd:$cmdBase|PID:$($proc.ProcessId)"
                    }
                }
            }
        }
    }
    $result.data.hollowing_suspects = $hollowingSuspects

    $suspiciousDlls = @()
    $sigCache = @{}
    $coreServices = @('lsass', 'services', 'csrss', 'wininit', 'winlogon', 'dwm', 'spoolsv')
    $criticalProcesses = Get-Process -Name explorer, svchost, services, lsass, winlogon, dwm, csrss, wininit, spoolsv -ErrorAction SilentlyContinue

    foreach ($p in $criticalProcesses) {
        try {
            $pNameLower = $p.Name.ToLower()
            $modules = $p.Modules
            foreach ($mod in $modules) {
                $modPath = $mod.FileName
                if (-not $modPath) { continue }

                $modNorm = Normalize-PathStr $modPath
                $modLower = $modNorm.ToLower()

                $isHighRiskDir = $modLower -like "*\temp\*" -or $modLower -like "*\downloads\*" -or $modLower -like "*\users\public\*" -or $modLower -like "*\perflogs\*" -or $modLower -like "*\windows\temp\*"
                $isUserDir = $modLower -like "*\users\*" -or $modLower -like "*\appdata\*"

                if ($pNameLower -in $coreServices) {
                    if ($isHighRiskDir -or $isUserDir) {
                        $suspiciousDlls += @{
                            process_name = $p.Name
                            process_pid = $p.Id
                            dll_path = $modNorm
                            dll_name = $mod.ModuleName
                            reason = "core_service_loaded_user_dll"
                        }

                        $result.findings += @{
                            id = "MEM-005"
                            severity = "HIGH"
                            mitre = "T1055.001"
                            title = "Suspicious DLL Load"
                            detail = "suspicious_dll|$($p.Name)|$modNorm"
                        }
                    }
                } else {
                    if ($isHighRiskDir) {
                        $suspiciousDlls += @{
                            process_name = $p.Name
                            process_pid = $p.Id
                            dll_path = $modNorm
                            dll_name = $mod.ModuleName
                            reason = "untrusted_temp_or_download_path"
                        }

                        $result.findings += @{
                            id = "MEM-005"
                            severity = "HIGH"
                            mitre = "T1055.001"
                            title = "Suspicious DLL Load"
                            detail = "suspicious_dll|$($p.Name)|$modNorm"
                        }
                    } elseif ($isUserDir) {
                        if (-not $sigCache.ContainsKey($modLower)) {
                            $sig = Get-AuthenticodeSignature -FilePath $modNorm
                            $sigCache[$modLower] = @{
                                IsValid = ($sig.Status -eq 'Valid')
                                Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
                            }
                        }

                        $cachedSig = $sigCache[$modLower]
                        if (-not $cachedSig.IsValid) {
                            $suspiciousDlls += @{
                                process_name = $p.Name
                                process_pid = $p.Id
                                dll_path = $modNorm
                                dll_name = $mod.ModuleName
                                reason = "unsigned_or_invalid_signature_in_appdata"
                            }

                            $result.findings += @{
                                id = "MEM-005"
                                severity = "HIGH"
                                mitre = "T1055.001"
                                title = "Suspicious DLL Load"
                                detail = "suspicious_dll|$($p.Name)|$modNorm"
                            }
                        }
                    }
                }
            }
        } catch {}
    }
    $result.data.suspicious_dll_loads = $suspiciousDlls

    try {
        $scriptBlockLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 50
        $suspiciousScripts = @()
        $dangerousPatterns = @(
            $sigMimikatz
            $sigDumpCreds
            $sigShellcode
            $sigReflective
            $sigAmsiUtils
            $sigAmsiFailed
            $sigAmsiScan
            '\[System\.Runtime\.InteropServices\.Marshal\]::'
            $sigVirtualAlloc
            $sigWriteMem
            $sigCreateThread
            'Set-MpPreference\s+-(DisableRealtimeMonitoring|DisableIOAVProtection|DisableBehaviorMonitoring)'
            $sigSafetyKatz
            $sigRubeus
            $sigSharpHound
        )

        foreach ($evt in $scriptBlockLogs) {
            $scriptText = if ($evt.Properties.Count -gt 2) { $evt.Properties[2].Value } else { $evt.Message }
            if (-not $scriptText) { continue }

            if ($scriptText -like "*chunk_0*" -or $scriptText -like "*\collectors\*" -or $scriptText -like "*sdec_run*" -or $scriptText -like "*chunk_id = `"03_memory`"*" -or $scriptText -like "*scratch\*" -or $scriptText -like "*test_03*" -or $scriptText -like "*mockProcesses*" -or $scriptText -like "*Get-SigStr*") {
                continue
            }

            foreach ($pattern in $dangerousPatterns) {
                if ($scriptText -match $pattern) {
                    $suspiciousScripts += @{
                        time = $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                        event_id = $evt.Id
                        matched_pattern = $pattern
                        script_preview = if ($scriptText.Length -gt 300) { $scriptText.Substring(0, 300) } else { $scriptText }
                    }

                    $result.findings += @{
                        id = "MEM-006"
                        severity = "HIGH"
                        mitre = "T1059.001"
                        title = "Suspicious PowerShell"
                        detail = "ps_script|pattern:$pattern|time:$($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))"
                    }
                    break
                }
            }
        }
        $result.data.suspicious_powershell = $suspiciousScripts
    } catch [System.UnauthorizedAccessException] {
        $result.data.suspicious_powershell = @{ status = "skipped"; reason = "elevation_required" }
    } catch {
        $result.data.suspicious_powershell = @{ status = "skipped"; reason = "log_unavailable" }
    }

} catch {
    $result.status = "error"
    $result.data.error = $_.Exception.Message
}

$json = $result | ConvertTo-Json -Depth 10 -Compress
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText("$PSScriptRoot\..\chunks\chunk_03_memory.json", $json, $utf8NoBom)
