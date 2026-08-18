$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$result = @{
    chunk_id = "02_boot"
    timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    layer_name = "Boot & Startup"
    status = "completed"
    data = @{}
    findings = @()
}

$is64BitOS = [Environment]::Is64BitOperatingSystem
$is64BitProcess = [Environment]::Is64BitProcess
$isWoW64 = $is64BitOS -and (-not $is64BitProcess)

$nativeSys32 = if ($isWoW64) {
    Join-Path $env:SystemRoot "Sysnative"
} else {
    Join-Path $env:SystemRoot "System32"
}

$driversDir = Join-Path $nativeSys32 "drivers"
$bcdeditCmd = if ($isWoW64 -and (Test-Path (Join-Path $nativeSys32 "bcdedit.exe"))) {
    Join-Path $nativeSys32 "bcdedit.exe"
} else {
    "bcdedit.exe"
}

if (-not ([System.Management.Automation.PSTypeName]'DriverVerifier').Type) {
    $typeDef = @"
using System;
using System.Runtime.InteropServices;
using System.IO;

public class DriverVerifier {
    [StructLayout(LayoutKind.Sequential)]
    struct WINTRUST_FILE_INFO {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WINTRUST_CATALOG_INFO {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedHash;
        public uint cbCalculatedHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WINTRUST_DATA {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CryptCATAdminAcquireContext(ref IntPtr phCatAdmin, [MarshalAs(UnmanagedType.LPStruct)] Guid pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, IntPtr pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatalogInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CATALOG_INFO {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
    static readonly Guid DRIVER_ACTION_VERIFY = new Guid("{F750E6C3-38EE-11d1-85E5-00C04FC295EE}");

    const uint WTD_CHOICE_FILE = 1;
    const uint WTD_CHOICE_CATALOG = 2;
    const uint WTD_UI_NONE = 2;
    const uint WTD_REVOKE_NONE = 0x00000000;
    const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
    const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;
    const uint WTD_DISABLE_MD2_MD4 = 0x00002000;
    const uint WTD_STATEACTION_IGNORE = 0x00000000;

    static string ResolvePath(string path) {
        if (File.Exists(path)) return path;
        if (IntPtr.Size == 4 && Environment.Is64BitOperatingSystem) {
            string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string sys32 = Path.Combine(sysRoot, "System32");
            string sysnative = Path.Combine(sysRoot, "Sysnative");
            if (path.StartsWith(sys32, StringComparison.OrdinalIgnoreCase)) {
                string alt = sysnative + path.Substring(sys32.Length);
                if (File.Exists(alt)) return alt;
            }
        }
        return path;
    }

    public static int VerifyFile(string filePath, bool checkCatalog = true) {
        string targetPath = ResolvePath(filePath);
        if (!File.Exists(targetPath)) return -1;

        WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO {
            cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
            pcwszFilePath = targetPath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
        int hr = -1;
        try {
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);
            WINTRUST_DATA wvtData = new WINTRUST_DATA {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFileInfo,
                dwStateAction = WTD_STATEACTION_IGNORE,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = null,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };
            hr = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref wvtData);
        } finally {
            Marshal.FreeHGlobal(pFileInfo);
        }

        if (hr == 0) return 0;
        if (!checkCatalog) return hr;

        IntPtr hCatAdmin = IntPtr.Zero;
        Guid driverAction = DRIVER_ACTION_VERIFY;
        if (!CryptCATAdminAcquireContext(ref hCatAdmin, driverAction, 0)) {
            if (!CryptCATAdminAcquireContext(ref hCatAdmin, Guid.Empty, 0)) return hr;
        }

        try {
            using (FileStream fs = new FileStream(targetPath, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                uint hashSize = 0;
                CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle.DangerousGetHandle(), ref hashSize, IntPtr.Zero, 0);
                if (hashSize == 0) return hr;

                byte[] hash = new byte[hashSize];
                IntPtr pHash = Marshal.AllocHGlobal((int)hashSize);
                try {
                    if (CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle.DangerousGetHandle(), ref hashSize, pHash, 0)) {
                        Marshal.Copy(pHash, hash, 0, (int)hashSize);
                        string memberTag = BitConverter.ToString(hash).Replace("-", "");

                        IntPtr hPrevCatInfo = IntPtr.Zero;
                        IntPtr hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, ref hPrevCatInfo);
                        while (hCatInfo != IntPtr.Zero) {
                            CATALOG_INFO catInfo = new CATALOG_INFO {
                                cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO))
                            };
                            if (CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0)) {
                                WINTRUST_CATALOG_INFO wtc = new WINTRUST_CATALOG_INFO {
                                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)),
                                    dwCatalogVersion = 0,
                                    pcwszCatalogFilePath = catInfo.wszCatalogFile,
                                    pcwszMemberTag = memberTag,
                                    pcwszMemberFilePath = targetPath,
                                    hMemberFile = IntPtr.Zero,
                                    pbCalculatedHash = pHash,
                                    cbCalculatedHash = hashSize,
                                    pcCatalogContext = IntPtr.Zero,
                                    hCatAdmin = hCatAdmin
                                };

                                IntPtr pWtc = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)));
                                try {
                                    Marshal.StructureToPtr(wtc, pWtc, false);
                                    WINTRUST_DATA catWvtData = new WINTRUST_DATA {
                                        cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                                        dwUIChoice = WTD_UI_NONE,
                                        fdwRevocationChecks = WTD_REVOKE_NONE,
                                        dwUnionChoice = WTD_CHOICE_CATALOG,
                                        pFile = pWtc,
                                        dwStateAction = WTD_STATEACTION_IGNORE,
                                        dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4
                                    };
                                    hr = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref catWvtData);
                                } finally {
                                    Marshal.FreeHGlobal(pWtc);
                                }

                                if (hr == 0) {
                                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                                    break;
                                }
                            }
                            IntPtr nextCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, ref hCatInfo);
                            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                            hCatInfo = nextCatInfo;
                        }
                    }
                } finally {
                    Marshal.FreeHGlobal(pHash);
                }
            }
        } catch {
        } finally {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }

        return hr;
    }
}
"@
    try {
        Add-Type -TypeDefinition $typeDef -ErrorAction SilentlyContinue
    } catch {}
}

function Resolve-DriverPath {
    param([string]$RawPath)
    if (-not $RawPath) { return $null }
    $cleaned = $RawPath -replace '\\SystemRoot\\', "$env:SystemRoot\" -replace '^\\\?\?\\', ''
    $expanded = [Environment]::ExpandEnvironmentVariables($cleaned)
    if ($isWoW64) {
        $sys32Prefix = "$env:SystemRoot\System32"
        if ($expanded.StartsWith($sys32Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $nativePath = Join-Path (Join-Path $env:SystemRoot "Sysnative") $expanded.Substring($sys32Prefix.Length).TrimStart('\')
            if (Test-Path $nativePath) {
                try { return [System.IO.Path]::GetFullPath($nativePath) } catch { return $nativePath }
            }
        }
    }
    if (Test-Path $expanded) {
        try { return [System.IO.Path]::GetFullPath($expanded) } catch { return $expanded }
    }
    return $expanded
}

function Test-DriverSignature {
    param([string]$FilePath)
    $target = Resolve-DriverPath -RawPath $FilePath
    if ([System.Management.Automation.PSTypeName]'DriverVerifier'.Type) {
        try {
            $code = [DriverVerifier]::VerifyFile($target, $true)
            if ($code -eq 0) {
                return @{ IsValid = $true; Status = "Valid" }
            } else {
                return @{ IsValid = $false; Status = "InvalidOrUnsigned($code)" }
            }
        } catch {}
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $target -ErrorAction SilentlyContinue
        return @{ IsValid = ($sig.Status -eq 'Valid'); Status = [string]$sig.Status }
    } catch {
        return @{ IsValid = $false; Status = "Error" }
    }
}

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $result.data.is_admin = $isAdmin

    try {
        $disks = Get-Disk -ErrorAction Stop | Select-Object Number, FriendlyName, PartitionStyle, BootFromDisk, IsBoot, IsSystem, OperationalStatus
        $result.data.disk_partitions = @($disks | ForEach-Object {
            @{
                number = $_.Number
                name = $_.FriendlyName
                partition_style = [string]$_.PartitionStyle
                is_boot = $_.BootFromDisk
                is_system = $_.IsSystem
                status = [string]$_.OperationalStatus
            }
        })
    } catch {
        $result.data.disk_partitions = @()
    }

    $efiPartitions = @(Get-Partition -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'System' -or $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' } | Select-Object DiskNumber, PartitionNumber, Size, Type)
    $efiList = @($efiPartitions | ForEach-Object {
        @{
            disk_number = $_.DiskNumber
            partition_number = $_.PartitionNumber
            size_mb = if ($_.Size) { [Math]::Round($_.Size / 1MB, 2) } else { 0 }
            type = [string]$_.Type
        }
    })
    $result.data.efi_partitions = $efiList
    $result.data.efi_partition = if ($efiList.Count -gt 0) {
        @{
            exists = $true
            disk_number = $efiList[0].disk_number
            partition_number = $efiList[0].partition_number
            size_mb = $efiList[0].size_mb
            total_efi_count = $efiList.Count
        }
    } else {
        @{ exists = $false; total_efi_count = 0 }
    }

    if ($isAdmin) {
        try {
            $bcdedit = & $bcdeditCmd /enum all 2>&1 | Out-String
            $entries = @()
            $currentEntry = $null
            $lastProp = $null
            $lines = $bcdedit -split "`r?`n"
            for ($i = 0; $i -lt $lines.Length; $i++) {
                $line = $lines[$i]
                $trimmed = $line.Trim()
                if ($trimmed -match '^[-=—_]{3,}$') {
                    if ($currentEntry) { $entries += $currentEntry }
                    $entryTitle = if ($i -gt 0) { $lines[$i - 1].Trim() } else { "Unknown" }
                    $currentEntry = @{ type = $entryTitle; properties = @{} }
                    $lastProp = $null
                } elseif ($currentEntry -and $trimmed.Length -gt 0) {
                    if ($line -match '^\s{2,}(\S.*)$') {
                        if ($lastProp) {
                            $currentEntry.properties[$lastProp] = "$($currentEntry.properties[$lastProp]) $($Matches[1].Trim())"
                        }
                    } elseif ($line -match '^([^\s]+)\s{2,}(.+)$' -or $line -match '^([^\s]+)\s+(.+)$') {
                        $propKey = $Matches[1].Trim()
                        $propVal = $Matches[2].Trim()
                        $currentEntry.properties[$propKey] = $propVal
                        $lastProp = $propKey
                    }
                }
            }
            if ($currentEntry) { $entries += $currentEntry }
            $result.data.boot_entries = $entries
        } catch {
            $result.data.boot_entries = @{ status = "skipped"; reason = "bcdedit_failed" }
        }
    } else {
        $result.data.boot_entries = @{ status = "skipped"; reason = "elevation_required" }
    }

    $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, PathName, State, StartMode, ServiceType, Started)
    $suspiciousDrivers = @()

    $result.data.system_drivers = @{
        total_count = $drivers.Count
        running_count = @($drivers | Where-Object { $_.State -eq 'Running' }).Count
        suspicious = @()
    }

    $normalPrefixes = @(
        [System.IO.Path]::GetFullPath("$env:SystemRoot\System32\drivers"),
        [System.IO.Path]::GetFullPath("$env:SystemRoot\System32\DriverStore"),
        [System.IO.Path]::GetFullPath("$env:SystemRoot\System32"),
        [System.IO.Path]::GetFullPath("$env:SystemRoot\SysWOW64"),
        [System.IO.Path]::GetFullPath("$env:SystemRoot\WinSxS"),
        [System.IO.Path]::GetFullPath("${env:ProgramFiles}"),
        [System.IO.Path]::GetFullPath("${env:ProgramFiles(x86)}")
    )
    if ($isWoW64) {
        $normalPrefixes += [System.IO.Path]::GetFullPath("$env:SystemRoot\Sysnative\drivers")
        $normalPrefixes += [System.IO.Path]::GetFullPath("$env:SystemRoot\Sysnative\DriverStore")
        $normalPrefixes += [System.IO.Path]::GetFullPath("$env:SystemRoot\Sysnative")
    }

    foreach ($drv in $drivers) {
        $isSuspicious = $false
        $reasons = @()

        if ($drv.PathName) {
            $drvPath = Resolve-DriverPath -RawPath $drv.PathName

            if (Test-Path $drvPath) {
                $sigInfo = Test-DriverSignature -FilePath $drvPath
                if (-not $sigInfo.IsValid) {
                    $isSuspicious = $true
                    $reasons += "unsigned_or_invalid_signature|$($sigInfo.Status)"
                }
            } else {
                if ($drv.State -eq 'Running') {
                    $isSuspicious = $true
                    $reasons += "missing_file_for_running_driver|$drvPath"
                }
            }

            $inNormalPath = $false
            foreach ($np in $normalPrefixes) {
                if ($drvPath.StartsWith($np, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $inNormalPath = $true
                    break
                }
            }
            if (-not $inNormalPath) {
                $isSuspicious = $true
                $reasons += "unusual_path|$drvPath"
            }
        }

        if ($isSuspicious) {
            $finding = @{
                name = $drv.Name
                display_name = $drv.DisplayName
                path = $drv.PathName
                state = [string]$drv.State
                start_mode = [string]$drv.StartMode
                reasons = $reasons
            }
            $result.data.system_drivers.suspicious += $finding

            $result.findings += @{
                id = "BOOT-001"
                severity = "HIGH"
                mitre = "T1014"
                title = "Suspicious System Driver"
                detail = "suspicious_driver|$($drv.Name)|$($reasons -join ',')"
            }
        }
    }

    if ($isAdmin) {
        try {
            $bootEvents = Get-WinEvent -LogName 'Microsoft-Windows-Kernel-Boot/Operational' -MaxEvents 50 -ErrorAction Stop |
                Select-Object TimeCreated, Id, LevelDisplayName, Message
            $result.data.boot_events = @($bootEvents | ForEach-Object {
                @{
                    time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    event_id = $_.Id
                    level = $_.LevelDisplayName
                    message = if ($_.Message -and $_.Message.Length -gt 200) { $_.Message.Substring(0, 200) } else { $_.Message }
                }
            })

            $errorEvents = @($bootEvents | Where-Object { $_.LevelDisplayName -eq 'Error' -or $_.LevelDisplayName -eq 'Critical' })
            if ($errorEvents.Count -gt 0) {
                $result.findings += @{
                    id = "BOOT-002"
                    severity = "MEDIUM"
                    mitre = "T1542"
                    title = "Boot Error Events"
                    detail = "boot_errors_found|count:$($errorEvents.Count)"
                }
            }
        } catch {
            $result.data.boot_events = @{ status = "skipped"; reason = "log_access_failed" }
        }
    } else {
        $result.data.boot_events = @{ status = "skipped"; reason = "elevation_required" }
    }

    $sys32Drivers = @(Get-ChildItem (Join-Path $driversDir "*.sys") -ErrorAction SilentlyContinue)
    $unsignedSys = @()

    foreach ($sysFile in $sys32Drivers) {
        $sigInfo = Test-DriverSignature -FilePath $sysFile.FullName
        if (-not $sigInfo.IsValid) {
            $unsignedSys += @{
                file = $sysFile.Name
                path = $sysFile.FullName
                size_kb = [Math]::Round($sysFile.Length / 1KB, 2)
                last_modified = $sysFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                signature_status = [string]$sigInfo.Status
            }
        }
    }

    $result.data.unsigned_sys_files = @{
        total_scanned = $sys32Drivers.Count
        unsigned_count = $unsignedSys.Count
        unsigned = $unsignedSys
    }

    if ($unsignedSys.Count -gt 0) {
        $result.findings += @{
            id = "BOOT-003"
            severity = "HIGH"
            mitre = "T1014"
            title = "Unsigned SYS Files"
            detail = "unsigned_sys|count:$($unsignedSys.Count)|scanned:$($sys32Drivers.Count)"
        }
    }

} catch {
    $result.status = "error"
    $result.data.error = $_.Exception.Message
}

$json = $result | ConvertTo-Json -Depth 10 -Compress
$utf8NoBom = New-Object System.Text.UTF8Encoding $false

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { (Get-Location).Path }
$chunkDir = Join-Path $scriptDir "..\chunks"
if (-not (Test-Path $chunkDir)) {
    New-Item -ItemType Directory -Path $chunkDir -Force | Out-Null
}
$chunkPath = Join-Path $chunkDir "chunk_02_boot.json"
[System.IO.File]::WriteAllText($chunkPath, $json, $utf8NoBom)
