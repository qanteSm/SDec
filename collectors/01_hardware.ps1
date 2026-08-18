$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$result = @{
    chunk_id = "01_hardware"
    timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    layer_name = "Hardware & Firmware"
    status = "completed"
    data = @{}
    findings = @()
}

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $result.data.is_admin = $isAdmin

    $secureBoot = $null
    try {
        $secureBoot = Confirm-SecureBootUEFI
    } catch {}

    $result.data.secure_boot = @{
        enabled = $secureBoot
        status = if ($secureBoot -eq $true) { "enabled" } elseif ($secureBoot -eq $false) { "disabled" } else { "unavailable" }
    }

    if ($secureBoot -eq $false) {
        $result.findings += @{
            id = "HW-001"
            severity = "HIGH"
            mitre = "T1542"
            title = "Secure Boot Disabled"
            detail = "secure_boot_disabled"
        }
    }

    if (-not $isAdmin) {
        $result.data.tpm = @{ status = "skipped"; reason = "elevation_required" }
    } else {
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            $result.data.tpm = @{
                present = $tpm.TpmPresent
                ready = $tpm.TpmReady
                enabled = $tpm.TpmEnabled
                activated = $tpm.TpmActivated
                owned = $tpm.TpmOwned
                manufacturer_version = $tpm.ManufacturerVersion
            }

            if ($tpm.TpmPresent -eq $false) {
                $result.findings += @{
                    id = "HW-008"
                    severity = "HIGH"
                    mitre = "T1542"
                    title = "TPM Not Present"
                    detail = "tpm_not_present"
                }
            } elseif ($tpm.TpmReady -eq $false -or $tpm.TpmEnabled -eq $false) {
                $result.findings += @{
                    id = "HW-008"
                    severity = "MEDIUM"
                    mitre = "T1542"
                    title = "TPM Not Ready"
                    detail = "tpm_not_ready|ready:$($tpm.TpmReady)|enabled:$($tpm.TpmEnabled)"
                }
            }
        } catch {
            $result.data.tpm = @{ status = "skipped"; reason = "elevation_required" }
        }
    }

    $disks = Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, Size, FirmwareVersion
    $result.data.physical_disks = @($disks | ForEach-Object {
        $d = $_
        $health = @{
            device_id = $d.DeviceId
            name = $d.FriendlyName
            media_type = [string]$d.MediaType
            bus_type = [string]$d.BusType
            health_status = [string]$d.HealthStatus
            operational_status = [string]$d.OperationalStatus
            size_gb = [Math]::Round($d.Size / 1GB, 2)
            firmware = $d.FirmwareVersion
        }

        if ($d.HealthStatus -ne 'Healthy') {
            $result.findings += @{
                id = "HW-002"
                severity = "HIGH"
                mitre = "N/A"
                title = "Disk Health Warning"
                detail = "disk_unhealthy|$($d.FriendlyName)|$($d.HealthStatus)"
            }
        }
        $health
    })

    try {
        $relList = @()
        $pDisks = Get-PhysicalDisk
        foreach ($pd in $pDisks) {
            $rel = $null
            try {
                $rel = $pd | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
            } catch {}

            if ($rel) {
                $info = @{
                    device_id = $pd.DeviceId
                    friendly_name = $pd.FriendlyName
                    temperature_c = $rel.Temperature
                    read_errors = $rel.ReadErrorsTotal
                    write_errors = $rel.WriteErrorsTotal
                    wear_percentage = $rel.Wear
                    power_on_hours = $rel.PowerOnHours
                }

                if ($rel.Temperature -and $rel.Temperature -gt 55) {
                    $result.findings += @{
                        id = "HW-003"
                        severity = "MEDIUM"
                        mitre = "N/A"
                        title = "Disk High Temperature"
                        detail = "disk_temp_high|$($pd.DeviceId)|$($rel.Temperature)C"
                    }
                }

                if (($rel.ReadErrorsTotal -and $rel.ReadErrorsTotal -gt 0) -or ($rel.WriteErrorsTotal -and $rel.WriteErrorsTotal -gt 0)) {
                    $result.findings += @{
                        id = "HW-004"
                        severity = "MEDIUM"
                        mitre = "N/A"
                        title = "Disk IO Errors"
                        detail = "disk_io_errors|$($pd.DeviceId)|R:$($rel.ReadErrorsTotal)|W:$($rel.WriteErrorsTotal)"
                    }
                }

                if ($rel.Wear -and $rel.Wear -gt 80) {
                    $result.findings += @{
                        id = "HW-005"
                        severity = "HIGH"
                        mitre = "N/A"
                        title = "Disk Wear Critical"
                        detail = "disk_wear_critical|$($pd.DeviceId)|$($rel.Wear)%"
                    }
                }
                $relList += $info
            }
        }
        $result.data.disk_reliability = $relList
    } catch {
        $result.data.disk_reliability = @{ status = "skipped"; reason = "access_denied_or_unsupported" }
    }

    $cpu = Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, CurrentClockSpeed, LoadPercentage, L2CacheSize, L3CacheSize, Architecture
    $result.data.cpu = @($cpu | ForEach-Object {
        @{
            name = $_.Name
            cores = $_.NumberOfCores
            logical_processors = $_.NumberOfLogicalProcessors
            max_clock_mhz = $_.MaxClockSpeed
            current_clock_mhz = $_.CurrentClockSpeed
            load_percent = $_.LoadPercentage
            l2_cache_kb = $_.L2CacheSize
            l3_cache_kb = $_.L3CacheSize
            architecture = switch ($_.Architecture) { 0 {"x86"} 5 {"ARM"} 9 {"x64"} 12 {"ARM64"} default {"unknown"} }
        }
    })

    try {
        $thermalZones = Get-CimInstance -Namespace "root/WMI" -ClassName MSAcpi_ThermalZoneTemperature
        $result.data.cpu_temperature = @($thermalZones | ForEach-Object {
            $tempC = [Math]::Round(($_.CurrentTemperature - 2732) / 10, 1)
            if ($tempC -gt 85) {
                $result.findings += @{
                    id = "HW-006"
                    severity = "HIGH"
                    mitre = "N/A"
                    title = "CPU High Temperature"
                    detail = "cpu_temp_high|$($_.InstanceName)|${tempC}C"
                }
            }
            @{
                zone = $_.InstanceName
                temperature_c = $tempC
            }
        })
    } catch {
        $result.data.cpu_temperature = @{ status = "skipped"; reason = "elevation_required" }
    }

    $ram = Get-CimInstance Win32_PhysicalMemory | Select-Object DeviceLocator, Manufacturer, Capacity, Speed, MemoryType, SMBIOSMemoryType, ConfiguredClockSpeed
    $totalRamGB = [Math]::Round(($ram | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
    $result.data.memory = @{
        total_gb = $totalRamGB
        modules = @($ram | ForEach-Object {
            @{
                slot = $_.DeviceLocator
                manufacturer = $_.Manufacturer
                capacity_gb = [Math]::Round($_.Capacity / 1GB, 2)
                speed_mhz = $_.Speed
                configured_speed_mhz = $_.ConfiguredClockSpeed
                type = switch ($_.SMBIOSMemoryType) { 20 {"DDR"} 21 {"DDR2"} 24 {"DDR3"} 26 {"DDR4"} 34 {"DDR5"} default {"Unknown($($_.SMBIOSMemoryType))"} }
            }
        })
    }

    $gpuRegEntries = @{}
    try {
        Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\00*' -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.DriverDesc) {
                $mem = $_.'HardwareInformation.qwMemorySize'
                if ($mem -and $mem -gt 0) {
                    $gpuRegEntries[$_.DriverDesc] = [int64]$mem
                }
            }
        }
    } catch {}

    $gpu = Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, DriverDate, AdapterRAM, VideoProcessor, Status, CurrentRefreshRate
    $result.data.gpu = @($gpu | ForEach-Object {
        $vramBytes = [int64]$_.AdapterRAM
        if ($gpuRegEntries.ContainsKey($_.Name) -and $gpuRegEntries[$_.Name] -gt 0) {
            $vramBytes = $gpuRegEntries[$_.Name]
        }
        $vramMB = if ($vramBytes -gt 0) { [Math]::Round($vramBytes / 1MB, 0) } else { 0 }

        $info = @{
            name = $_.Name
            driver_version = $_.DriverVersion
            driver_date = if ($_.DriverDate -is [DateTime]) { $_.DriverDate.ToString('yyyy-MM-dd') } elseif ($_.DriverDate) { [string]$_.DriverDate } else { "unknown" }
            vram_mb = $vramMB
            video_processor = $_.VideoProcessor
            status = $_.Status
            refresh_rate = $_.CurrentRefreshRate
        }

        if ($_.Status -ne 'OK') {
            $result.findings += @{
                id = "HW-007"
                severity = "MEDIUM"
                mitre = "N/A"
                title = "GPU Status Abnormal"
                detail = "gpu_status|$($_.Name)|$($_.Status)"
            }
        }
        $info
    })

    $nics = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed, DriverVersion, DriverProvider, DriverDate
    $result.data.network_adapters = @($nics | ForEach-Object {
        @{
            name = $_.Name
            description = $_.InterfaceDescription
            mac = $_.MacAddress
            link_speed = $_.LinkSpeed
            driver_version = $_.DriverVersion
            driver_provider = $_.DriverProvider
            driver_date = if ($_.DriverDate -is [DateTime]) { $_.DriverDate.ToString('yyyy-MM-dd') } elseif ($_.DriverDate) { [string]$_.DriverDate } else { "unknown" }
        }
    })

    $batteries = @(Get-CimInstance Win32_Battery)
    if ($batteries.Count -gt 0) {
        $result.data.battery = @($batteries | ForEach-Object {
            $b = $_
            $chem = switch ($b.Chemistry) {
                1 { "Other" }
                2 { "Unknown" }
                3 { "Lead Acid" }
                4 { "Nickel Cadmium" }
                5 { "Nickel Metal Hydride" }
                6 { "Lithium-ion" }
                7 { "Zinc air" }
                8 { "Lithium Polymer" }
                default { "Unknown" }
            }
            $runtime = if ($b.EstimatedRunTime -and $b.EstimatedRunTime -lt 71582788) { $b.EstimatedRunTime } else { "ac_power" }
            @{
                name = $b.Name
                device_id = $b.DeviceId
                status = [string]$b.BatteryStatus
                estimated_charge = $b.EstimatedChargeRemaining
                estimated_runtime_min = $runtime
                chemistry = $chem
            }
        })
    } else {
        $result.data.battery = @{ status = "not_present" }
    }

    $bios = Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Name, Version, SMBIOSBIOSVersion, ReleaseDate, SerialNumber
    $result.data.bios = @{
        manufacturer = $bios.Manufacturer
        name = $bios.Name
        version = $bios.Version
        smbios_version = $bios.SMBIOSBIOSVersion
        release_date = if ($bios.ReleaseDate -is [DateTime]) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } elseif ($bios.ReleaseDate) { [string]$bios.ReleaseDate } else { "unknown" }
    }

    $mb = Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product, Version, SerialNumber
    $result.data.motherboard = @{
        manufacturer = $mb.Manufacturer
        product = $mb.Product
        version = $mb.Version
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
$chunkPath = Join-Path $chunkDir "chunk_01_hardware.json"
[System.IO.File]::WriteAllText($chunkPath, $json, $utf8NoBom)
