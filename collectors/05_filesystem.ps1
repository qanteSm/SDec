$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$result = @{
    chunk_id = "05_filesystem"
    timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    layer_name = "Filesystem & Hidden"
    status = "completed"
    data = @{}
    findings = @()
}

function Get-FilesFast {
    param(
        [string]$Path,
        [int]$MaxFiles = 2500,
        [string[]]$Extensions = $null
    )
    $results = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $Path)) { return $results }

    $dirs = New-Object System.Collections.Generic.Queue[string]
    $dirs.Enqueue($Path)

    while ($dirs.Count -gt 0 -and $results.Count -lt $MaxFiles) {
        $currentDir = $dirs.Dequeue()

        try {
            $dirInfo = New-Object System.IO.DirectoryInfo($currentDir)
            if ($dirInfo.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
                continue
            }
        } catch {
            continue
        }

        try {
            $files = [System.IO.Directory]::GetFiles($currentDir)
            foreach ($file in $files) {
                if ($Extensions) {
                    $ext = [System.IO.Path]::GetExtension($file).ToLower()
                    if ($Extensions -contains $ext) {
                        $results.Add($file)
                        if ($results.Count -ge $MaxFiles) { break }
                    }
                } else {
                    $results.Add($file)
                    if ($results.Count -ge $MaxFiles) { break }
                }
            }
        } catch {}

        if ($results.Count -ge $MaxFiles) { break }

        try {
            $subDirs = [System.IO.Directory]::GetDirectories($currentDir)
            foreach ($sub in $subDirs) {
                $dirs.Enqueue($sub)
            }
        } catch {}
    }
    return $results
}

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $result.data.is_admin = $isAdmin

    $programData = if ($env:ProgramData) { $env:ProgramData } else { "C:\ProgramData" }

    $adsTargetPaths = @(
        [System.IO.Path]::Combine($env:USERPROFILE, "Downloads"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Desktop"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Documents"),
        $env:TEMP,
        "$env:LOCALAPPDATA\Temp",
        "C:\Users\Public",
        "C:\Users\Public\Downloads",
        $programData,
        "$env:SystemRoot\Temp",
        $env:APPDATA
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | ForEach-Object { [System.IO.Path]::GetFullPath($_) } | Select-Object -Unique

    $adsFindings = @()
    $adsScanned = 0
    $seenAdsFiles = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($scanPath in $adsTargetPaths) {
        $files = Get-FilesFast -Path $scanPath -MaxFiles 2000
        foreach ($filePath in $files) {
            if (-not $seenAdsFiles.Add($filePath)) { continue }
            $adsScanned++
            try {
                $streams = $null
                try {
                    $streams = Get-Item -LiteralPath $filePath -Stream * -ErrorAction Stop | Where-Object {
                        $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier'
                    }
                } catch {
                    $escaped = [Management.Automation.WildcardPattern]::Escape($filePath)
                    $streams = Get-Item -Path $escaped -Stream * -ErrorAction SilentlyContinue | Where-Object {
                        $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier'
                    }
                }

                if ($streams) {
                    $fileInfo = New-Object System.IO.FileInfo($filePath)
                    foreach ($stream in $streams) {
                        $adsFindings += @{
                            file = $filePath
                            stream_name = $stream.Stream
                            stream_size = $stream.Length
                            file_last_modified = if ($fileInfo.Exists) { $fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } else { "" }
                        }
                    }
                }
            } catch {}
        }
    }

    $result.data.ads = @{
        scanned_files = $adsScanned
        findings = $adsFindings
    }

    if ($adsFindings.Count -gt 0) {
        $result.findings += @{
            id = "FS-001"
            severity = "MEDIUM"
            mitre = "T1564.004"
            title = "NTFS ADS Found"
            detail = "ads_found|count:$($adsFindings.Count)"
        }
    }

    $startupPaths = @(
        [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs\Startup"),
        [System.IO.Path]::Combine($programData, "Microsoft\Windows\Start Menu\Programs\StartUp")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | ForEach-Object { [System.IO.Path]::GetFullPath($_) } | Select-Object -Unique

    $startupItems = @()
    foreach ($sp in $startupPaths) {
        try {
            $itemPaths = [System.IO.Directory]::GetFiles($sp)
            foreach ($ip in $itemPaths) {
                $item = New-Object System.IO.FileInfo($ip)
                if (-not $item.Exists) { continue }
                $ext = $item.Extension.ToLower()

                $entry = @{
                    name = $item.Name
                    path = $item.FullName
                    size_kb = [Math]::Round($item.Length / 1KB, 2)
                    last_modified = $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    extension = $ext
                    startup_path = $sp
                }

                if ($ext -eq '.lnk') {
                    try {
                        $shell = New-Object -ComObject WScript.Shell
                        $lnk = $shell.CreateShortcut($item.FullName)
                        $entry.lnk_target = $lnk.TargetPath
                        $entry.lnk_arguments = $lnk.Arguments
                        $entry.lnk_working_dir = $lnk.WorkingDirectory

                        $targetLower = "$($lnk.TargetPath)".ToLower()
                        $argsLower = "$($lnk.Arguments)".ToLower()
                        $combined = "$targetLower $argsLower"

                        if ($combined -match '(powershell|cmd\.exe|wscript|cscript|mshta|certutil|http://|https://|-enc |-encodedcommand|downloadstring|iex )') {
                            $result.findings += @{
                                id = "FS-002"
                                severity = "HIGH"
                                mitre = "T1547.001"
                                title = "Suspicious Startup LNK"
                                detail = "suspicious_lnk|$($item.Name)|target:$($lnk.TargetPath)"
                            }
                        }

                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($lnk) | Out-Null
                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
                    } catch {}
                }

                if ($ext -in @('.exe', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.wsf', '.hta', '.scr')) {
                    $result.findings += @{
                        id = "FS-003"
                        severity = "MEDIUM"
                        mitre = "T1547.001"
                        title = "Executable In Startup"
                        detail = "startup_executable|$($item.Name)|$sp"
                    }
                }

                $startupItems += $entry
            }
        } catch {}
    }
    $result.data.startup_items = $startupItems

    $tempPaths = @($env:TEMP, "$env:LOCALAPPDATA\Temp", "$env:SystemRoot\Temp") |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        ForEach-Object { [System.IO.Path]::GetFullPath($_) } |
        Select-Object -Unique

    $executableExtensions = @('.exe', '.dll', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.wsf', '.hta', '.scr', '.pif', '.com')
    $tempExecutables = @()
    $seenTempFiles = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($tp in $tempPaths) {
        $exePaths = Get-FilesFast -Path $tp -MaxFiles 100 -Extensions $executableExtensions
        foreach ($ep in $exePaths) {
            if (-not $seenTempFiles.Add($ep)) { continue }
            try {
                $ef = New-Object System.IO.FileInfo($ep)
                if ($ef.Exists) {
                    $tempExecutables += @{
                        name = $ef.Name
                        path = $ef.FullName
                        size_kb = [Math]::Round($ef.Length / 1KB, 2)
                        last_modified = $ef.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                        extension = $ef.Extension.ToLower()
                    }
                }
            } catch {}
        }
    }

    $result.data.temp_executables = @{
        count = $tempExecutables.Count
        items = $tempExecutables
    }

    $scriptDroppers = @($tempExecutables | Where-Object { $_.extension -in @('.vbs', '.js', '.ps1', '.hta', '.wsf', '.scr') })
    if ($scriptDroppers.Count -gt 0) {
        $result.findings += @{
            id = "FS-004"
            severity = "MEDIUM"
            mitre = "T1059"
            title = "Suspicious Scripts In Temp"
            detail = "temp_scripts|count:$($scriptDroppers.Count)"
        }
    } elseif ($tempExecutables.Count -gt 150) {
        $result.findings += @{
            id = "FS-004"
            severity = "LOW"
            mitre = "T1059"
            title = "High Volume Executables In Temp"
            detail = "temp_executables|count:$($tempExecutables.Count)"
        }
    }

    $writableSystemPaths = @(
        "$env:SystemRoot\Fonts",
        "$env:SystemRoot\System32\spool\drivers\color",
        "$env:SystemRoot\Temp",
        "$env:SystemRoot\debug",
        "$env:SystemRoot\tracing",
        "$env:SystemRoot\Registration\CRMLog",
        "$env:SystemRoot\System32\FxsTmp",
        "$env:SystemRoot\System32\Tasks",
        "$env:SystemRoot\System32\com\dmp",
        "$env:SystemRoot\System32\Microsoft\Crypto\RSA\MachineKeys",
        "C:\Users\Public",
        "C:\Users\Public\Downloads"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | ForEach-Object { [System.IO.Path]::GetFullPath($_) } | Select-Object -Unique

    $hiddenExeFindings = @()
    $expectedExtensions = @{
        "$env:SystemRoot\Fonts" = @('.ttf', '.otf', '.fon', '.ttc', '.fnt')
        "$env:SystemRoot\System32\spool\drivers\color" = @('.icm', '.icc')
    }
    $suspExts = @('.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.scr')

    foreach ($wsp in $writableSystemPaths) {
        try {
            $files = [System.IO.Directory]::GetFiles($wsp)
            $count = 0
            foreach ($fp in $files) {
                if ($count -ge 50) { break }
                try {
                    $sf = New-Object System.IO.FileInfo($fp)
                    if (-not $sf.Exists) { continue }
                    $ext = $sf.Extension.ToLower()
                    $isSusp = ($ext -in $suspExts) -or ($ext -eq '' -and $sf.Length -gt 10KB)

                    if ($isSusp) {
                        $isExpected = $false
                        $normWsp = $wsp.TrimEnd('\')
                        foreach ($key in $expectedExtensions.Keys) {
                            if ($key.TrimEnd('\') -ieq $normWsp) {
                                if ($expectedExtensions[$key] -contains $ext) {
                                    $isExpected = $true
                                }
                                break
                            }
                        }

                        if (-not $isExpected) {
                            $count++
                            $hiddenExeFindings += @{
                                path = $sf.FullName
                                name = $sf.Name
                                size_kb = [Math]::Round($sf.Length / 1KB, 2)
                                last_modified = $sf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                                parent_dir = $wsp
                            }

                            $result.findings += @{
                                id = "FS-005"
                                severity = "HIGH"
                                mitre = "T1036.005"
                                title = "Executable In System Path"
                                detail = "known_path_masquerading|$($sf.Name)|$wsp"
                            }
                        }
                    }
                } catch {}
            }
        } catch {}
    }
    $result.data.known_path_masquerading = $hiddenExeFindings

    try {
        $shadowCopies = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Select-Object ID, InstallDate, VolumeName, DeviceObject)
        $result.data.shadow_copies = @{
            count = $shadowCopies.Count
            copies = @($shadowCopies | ForEach-Object {
                @{
                    id = $_.ID
                    install_date = if ($_.InstallDate) {
                        try { (Get-Date $_.InstallDate).ToString('yyyy-MM-dd HH:mm:ss') } catch { [string]$_.InstallDate }
                    } else {
                        "unknown"
                    }
                    volume = $_.VolumeName
                    device_object = $_.DeviceObject
                }
            })
        }
    } catch {
        $result.data.shadow_copies = @{ status = "skipped"; reason = "access_denied_or_unsupported" }
    }

    if ($isAdmin) {
        try {
            $amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
            if (Test-Path -LiteralPath $amcachePath) {
                $amcacheInfo = Get-Item -LiteralPath $amcachePath -ErrorAction SilentlyContinue
                $result.data.amcache = @{
                    exists = $true
                    size_kb = if ($amcacheInfo) { [Math]::Round($amcacheInfo.Length / 1KB, 2) } else { 0 }
                    last_modified = if ($amcacheInfo) { $amcacheInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } else { "unknown" }
                    note = "amcache_available_for_forensics"
                }
            } else {
                $result.data.amcache = @{ exists = $false }
            }

            $shimcachePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
            try {
                $shimcache = Get-ItemProperty -Path $shimcachePath -ErrorAction Stop
                $result.data.shimcache = @{
                    exists = $true
                    data_size_bytes = if ($shimcache.AppCompatCache) { $shimcache.AppCompatCache.Length } else { 0 }
                    note = "shimcache_available_for_forensics"
                }
            } catch {
                $result.data.shimcache = @{ exists = $false }
            }
        } catch {
            $result.data.amcache = @{ status = "skipped"; reason = "access_failed" }
            $result.data.shimcache = @{ status = "skipped"; reason = "access_failed" }
        }
    } else {
        $result.data.amcache = @{ status = "skipped"; reason = "elevation_required" }
        $result.data.shimcache = @{ status = "skipped"; reason = "elevation_required" }
    }

} catch {
    $result.status = "error"
    $result.data.error = $_.Exception.Message
}

$json = $result | ConvertTo-Json -Depth 10 -Compress
$utf8NoBom = New-Object System.Text.UTF8Encoding $false

$baseDir = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    (Get-Location).Path
}

$chunkDir = if (Test-Path (Join-Path $baseDir "..\chunks")) {
    [System.IO.Path]::GetFullPath((Join-Path $baseDir "..\chunks"))
} elseif (Test-Path (Join-Path $baseDir "chunks")) {
    [System.IO.Path]::GetFullPath((Join-Path $baseDir "chunks"))
} else {
    [System.IO.Path]::GetFullPath((Join-Path $baseDir "..\chunks"))
}

if (-not (Test-Path $chunkDir)) {
    New-Item -ItemType Directory -Path $chunkDir -Force | Out-Null
}
$chunkPath = Join-Path $chunkDir "chunk_05_filesystem.json"
[System.IO.File]::WriteAllText($chunkPath, $json, $utf8NoBom)
