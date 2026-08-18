$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$result = @{
    chunk_id = "07_optimization"
    timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    layer_name = "Optimization & Hygiene"
    status = "completed"
    data = @{}
    findings = @()
}

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $result.data.is_admin = $isAdmin

    $totalRam = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
    $cores = (Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    if (-not $cores -or $cores -lt 1) { $cores = [Environment]::ProcessorCount }
    if (-not $cores -or $cores -lt 1) { $cores = 1 }

    $processes = Get-Process | ForEach-Object {
        $cpuSeconds = if ($_.CPU) { [Math]::Round([double]$_.CPU, 2) } else { 0 }
        $ramMB = [Math]::Round($_.WorkingSet64 / 1MB, 2)
        $ramPercent = if ($totalRam -gt 0) { [Math]::Round(($_.WorkingSet64 / $totalRam) * 100, 2) } else { 0 }
        @{
            name = $_.ProcessName
            pid = $_.Id
            cpu_seconds = $cpuSeconds
            ram_mb = $ramMB
            ram_percent = $ramPercent
            path = $_.Path
            responding = $_.Responding
        }
    } | Sort-Object { $_.ram_mb } -Descending

    $result.data.top_ram = @($processes | Select-Object -First 20)
    $result.data.top_cpu = @($processes | Sort-Object { $_.cpu_seconds } -Descending | Select-Object -First 20)

    $notResponding = @($processes | Where-Object { $_.responding -eq $false })
    if ($notResponding.Count -gt 0) {
        $result.findings += @{
            id = "OPT-001"
            severity = "LOW"
            mitre = "N/A"
            title = "Not Responding Processes"
            detail = "not_responding|count:$($notResponding.Count)|$($notResponding[0].name)"
        }
    }
    $result.data.not_responding = $notResponding

    $os = Get-CimInstance Win32_OperatingSystem
    $result.data.memory_overview = @{
        total_gb = if ($totalRam) { [Math]::Round($totalRam / 1GB, 2) } else { 0 }
        visible_gb = if ($os.TotalVisibleMemorySize) { [Math]::Round($os.TotalVisibleMemorySize / 1MB, 2) } else { 0 }
        free_gb = if ($os.FreePhysicalMemory) { [Math]::Round($os.FreePhysicalMemory / 1MB, 2) } else { 0 }
        used_percent = if ($os.TotalVisibleMemorySize -gt 0) { [Math]::Round((1 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize)) * 100, 1) } else { 0 }
    }

    if ($result.data.memory_overview.used_percent -gt 85) {
        $result.findings += @{
            id = "OPT-002"
            severity = "MEDIUM"
            mitre = "N/A"
            title = "High Memory Usage"
            detail = "high_ram|$($result.data.memory_overview.used_percent)%"
        }
    }

    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -or $_.Free }
    $result.data.disk_usage = @($drives | ForEach-Object {
        $totalBytes = $_.Used + $_.Free
        $usedPercent = if ($totalBytes -gt 0) { [Math]::Round(($_.Used / $totalBytes) * 100, 1) } else { 0 }
        $info = @{
            drive = $_.Name
            root = $_.Root
            total_gb = [Math]::Round($totalBytes / 1GB, 2)
            used_gb = [Math]::Round($_.Used / 1GB, 2)
            free_gb = [Math]::Round($_.Free / 1GB, 2)
            used_percent = $usedPercent
        }

        if ($usedPercent -gt 90) {
            $result.findings += @{
                id = "OPT-003"
                severity = "MEDIUM"
                mitre = "N/A"
                title = "Disk Almost Full"
                detail = "disk_full|$($_.Name)|$usedPercent%"
            }
        }
        $info
    })

    $knownDisableable = @(
        'DiagTrack', 'dmwappushservice', 'RetailDemo', 'MapsBroker',
        'lfsvc', 'SharedAccess', 'RemoteRegistry', 'TrkWks',
        'WMPNetworkSvc', 'WSearch', 'SysMain', 'Fax',
        'TabletInputService', 'wisvc', 'icssvc'
    )

    $autoServices = Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' }
    $disableableServices = @()

    foreach ($svc in $autoServices) {
        if ($svc.Name -in $knownDisableable) {
            $disableableServices += @{
                name = $svc.Name
                display_name = $svc.DisplayName
                path = $svc.PathName
                start_mode = $svc.StartMode
                state = $svc.State
            }
        }
    }

    $result.data.disableable_services = $disableableServices
    $result.data.total_auto_services = $autoServices.Count

    $startupItems = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
    $result.data.startup_programs = @($startupItems | ForEach-Object {
        @{
            name = $_.Name
            command = $_.Command
            location = $_.Location
            user = $_.User
        }
    })

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Ready' -and $_.TaskPath -notmatch '^\\Microsoft' } | Select-Object -First 30 | ForEach-Object {
            @{
                name = $_.TaskName
                path = $_.TaskPath
                state = [string]$_.State
            }
        }
        $result.data.custom_scheduled_tasks = @($tasks)
    } catch {
        $result.data.custom_scheduled_tasks = @()
    }

    try {
        $activePlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -Filter "IsActive = True" -ErrorAction SilentlyContinue
        if ($activePlan -and $activePlan.ElementName) {
            $result.data.power_plan = [string]$activePlan.ElementName
        } else {
            $pcfg = (powercfg /getactivescheme 2>&1 | Out-String)
            $pMatch = [regex]::Match($pcfg, '\(([^)]+)\)')
            $result.data.power_plan = if ($pMatch.Success) { $pMatch.Groups[1].Value.Trim() } else { "unknown" }
        }
    } catch {
        $result.data.power_plan = "unknown"
    }

    $eventLogs = @('Application', 'System', 'Security') | ForEach-Object {
        try {
            $log = Get-WinEvent -ListLog $_ -ErrorAction SilentlyContinue
            if ($log) {
                @{
                    log_name = $log.LogName
                    file_size_mb = if ($log.FileSize) { [Math]::Round($log.FileSize / 1MB, 2) } else { 0 }
                    record_count = if ($log.RecordCount) { $log.RecordCount } else { 0 }
                }
            }
        } catch {}
    }
    $result.data.event_logs = @($eventLogs)

    $netStats = Get-NetAdapterStatistics | Select-Object Name, ReceivedBytes, SentBytes, ReceivedUnicastPackets, SentUnicastPackets, OutboundDiscardedPackets, InboundDiscardedPackets, InboundErrors, OutboundErrors
    $result.data.network_stats = @($netStats | ForEach-Object {
        $inErrors = if ($_.InboundErrors) { [int64]$_.InboundErrors } else { 0 }
        $outErrors = if ($_.OutboundErrors) { [int64]$_.OutboundErrors } else { 0 }
        $inDiscarded = if ($_.InboundDiscardedPackets) { [int64]$_.InboundDiscardedPackets } else { 0 }
        $outDiscarded = if ($_.OutboundDiscardedPackets) { [int64]$_.OutboundDiscardedPackets } else { 0 }
        $rxBytes = if ($_.ReceivedBytes) { [int64]$_.ReceivedBytes } else { 0 }
        $txBytes = if ($_.SentBytes) { [int64]$_.SentBytes } else { 0 }
        $rxPackets = if ($_.ReceivedUnicastPackets) { [int64]$_.ReceivedUnicastPackets } else { 0 }
        $txPackets = if ($_.SentUnicastPackets) { [int64]$_.SentUnicastPackets } else { 0 }

        $info = @{
            adapter = $_.Name
            received_mb = [Math]::Round($rxBytes / 1MB, 2)
            sent_mb = [Math]::Round($txBytes / 1MB, 2)
            in_packets = $rxPackets
            out_packets = $txPackets
            in_errors = $inErrors
            out_errors = $outErrors
            in_discarded = $inDiscarded
            out_discarded = $outDiscarded
        }

        if ($inErrors -gt 100 -or $outErrors -gt 100) {
            $result.findings += @{
                id = "OPT-004"
                severity = "LOW"
                mitre = "N/A"
                title = "Network Errors"
                detail = "net_errors|$($_.Name)|in:$inErrors|out:$outErrors"
            }
        }
        $info
    })

    try {
        $lastUpdate = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results
        $lastSearchDate = $lastUpdate.LastSearchSuccessDate
        $lastInstallDate = $lastUpdate.LastInstallationSuccessDate
        $result.data.windows_update = @{
            last_search = if ($lastSearchDate) { $lastSearchDate.ToString('yyyy-MM-dd HH:mm:ss') } else { "unknown" }
            last_install = if ($lastInstallDate) { $lastInstallDate.ToString('yyyy-MM-dd HH:mm:ss') } else { "unknown" }
        }
        if ($lastSearchDate) {
            $daysSinceSearch = [Math]::Round(((Get-Date) - $lastSearchDate).TotalDays, 0)
            if ($daysSinceSearch -gt 60) {
                $result.findings += @{
                    id = "OPT-006"
                    severity = "LOW"
                    mitre = "N/A"
                    title = "Outdated System"
                    detail = "outdated_wu|days:$daysSinceSearch|last:$($result.data.windows_update.last_search)"
                }
            }
        }
    } catch {
        $result.data.windows_update = @{ status = "skipped"; reason = "com_object_failed" }
    }

    $tempPaths = @($env:TEMP, $env:TMP, "$env:LOCALAPPDATA\Temp", "$env:SystemRoot\Temp") | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object { (Get-Item $_).FullName.TrimEnd('\') } | Select-Object -Unique
    $tempSize = 0
    foreach ($tPath in $tempPaths) {
        $subSum = (Get-ChildItem -Path $tPath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($subSum) {
            $tempSize += $subSum
        }
    }
    $tempSizeMB = [Math]::Round($tempSize / 1MB, 2)
    $result.data.temp_size_mb = $tempSizeMB

    if ($tempSizeMB -gt 5000) {
        $result.findings += @{
            id = "OPT-005"
            severity = "LOW"
            mitre = "N/A"
            title = "High Temp Junk"
            detail = "high_temp|$($tempSizeMB)MB"
        }
    }

    $doPath = "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization"
    $doSize = 0
    if (Test-Path $doPath) {
        $doSize = (Get-ChildItem -Path $doPath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    }
    $result.data.delivery_optimization_mb = [Math]::Round($doSize / 1MB, 2)

    $dumpPath = "$env:SystemRoot\MEMORY.DMP"
    $dumpSizeMB = 0
    if (Test-Path $dumpPath) {
        try {
            $dumpItem = Get-Item $dumpPath -ErrorAction SilentlyContinue
            if ($dumpItem) { $dumpSizeMB = [Math]::Round($dumpItem.Length / 1MB, 2) }
        } catch {}
    }

    $minidumpPath = "$env:SystemRoot\Minidump"
    $minidumpSizeMB = 0
    if (Test-Path $minidumpPath) {
        try {
            $miniSum = (Get-ChildItem -Path $minidumpPath -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            if ($miniSum) { $minidumpSizeMB = [Math]::Round($miniSum / 1MB, 2) }
        } catch {}
    }

    $result.data.memory_dump = @{
        memory_dmp_mb = $dumpSizeMB
        minidump_mb = $minidumpSizeMB
        total_dump_mb = [Math]::Round($dumpSizeMB + $minidumpSizeMB, 2)
    }

    if ($isAdmin) {
        try {
            $vss = vssadmin list shadowstorage 2>&1 | Out-String
            $vssUsedMatch = [regex]::Match($vss, '(?i)(?:Used Shadow Copy Storage space|Kullanılan Gölge Kopya Depolama alanı|Espace de stockage de cliché instantané utilisé).*?:\s*([\d.,]+\s*\w+)')
            $result.data.vss_allocated = if ($vssUsedMatch.Success) { $vssUsedMatch.Groups[1].Value.Trim() } else { "unknown" }
        } catch {
            $result.data.vss_allocated = "unknown"
        }
    } else {
        $result.data.vss_allocated = "elevation_required"
    }

    if ($isAdmin) {
        try {
            $dismOutput = dism /online /cleanup-image /analyzecomponentstore 2>&1 | Out-String
            $winsxsMatch = [regex]::Match($dismOutput, '(?i)(?:Actual Size of Component Store|Component Store|Bileşen Deposu|Taille réelle|Tatsächliche Größe).*?:\s*([\d.,]+\s*\w+)')
            if (-not $winsxsMatch.Success) {
                $winsxsMatch = [regex]::Match($dismOutput, '(?i)(?:WinSxS|Size|Boyut).*?:\s*([\d.,]+\s*\w+)')
            }
            $reclaimMatch = [regex]::Match($dismOutput, '(?i)(?:Reclaimable|Geri Kazanılabilir|Recuperable|Wiederherstellbar).*?:\s*([\d.,]+\s*\w+|\w+)')
            $cleanupMatch = [regex]::Match($dismOutput, '(?i)(?:Cleanup Recommended|Temizleme Önerilir|Bereinigung empfohlen).*?:\s*(\w+)')
            
            $sizeVal = if ($winsxsMatch.Success) { $winsxsMatch.Groups[1].Value.Trim() } else { "unknown" }
            $reclaimVal = if ($reclaimMatch.Success) { $reclaimMatch.Groups[1].Value.Trim() } else { "unknown" }
            $cleanupRec = if ($cleanupMatch.Success) { $cleanupMatch.Groups[1].Value.Trim() } else { "unknown" }

            $result.data.component_store = @{
                raw_output = if ($dismOutput.Length -gt 500) { $dismOutput.Substring(0, 500) } else { $dismOutput }
                size = $sizeVal
                reclaimable = $reclaimVal
                cleanup_recommended = $cleanupRec
            }

            if ($cleanupRec -match '^(?i)(Yes|Evet|Oui|Ja|True)$') {
                $result.findings += @{
                    id = "OPT-007"
                    severity = "LOW"
                    mitre = "N/A"
                    title = "WinSxS Bloat"
                    detail = "winsxs_bloat|size:$sizeVal|reclaim:$reclaimVal"
                }
            }
        } catch {
            $result.data.component_store = @{ status = "skipped"; reason = "dism_failed" }
        }
    } else {
        try {
            $winsxsPath = "$env:SystemRoot\WinSxS"
            if (Test-Path $winsxsPath) {
                $winsxsInfo = Get-Item $winsxsPath
                $result.data.component_store = @{
                    note = "approximate_size_only"
                    last_modified = $winsxsInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
            }
        } catch {
            $result.data.component_store = @{ status = "skipped"; reason = "elevation_required" }
        }
    }

    $sviPath = "C:\System Volume Information"
    try {
        if (Test-Path $sviPath) {
            $result.data.system_volume_info = @{
                exists = $true
                note = "requires_system_access_for_size"
            }
        }
    } catch {}

    $recycleBinSize = 0
    try {
        $recycleBin = (New-Object -ComObject Shell.Application).NameSpace(0xa)
        $recycleBinSize = ($recycleBin.Items() | Measure-Object -Property Size -Sum).Sum
    } catch {}
    $result.data.recycle_bin_mb = [Math]::Round($recycleBinSize / 1MB, 2)

    $pagefiles = @(Get-CimInstance Win32_PageFileUsage)
    if ($pagefiles.Count -gt 0) {
        $result.data.pagefile = @($pagefiles | ForEach-Object {
            @{
                name = $_.Name
                allocated_mb = [int]$_.AllocatedBaseSize
                current_usage_mb = [int]$_.CurrentUsage
                peak_usage_mb = [int]$_.PeakUsage
            }
        })
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
$chunkPath = Join-Path $chunkDir "chunk_07_optimization.json"
[System.IO.File]::WriteAllText($chunkPath, $json, $utf8NoBom)
