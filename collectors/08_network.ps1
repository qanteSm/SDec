$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$result = @{
    chunk_id = "08_network"
    timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    layer_name = "Network & Sockets"
    status = "completed"
    data = @{}
    findings = [System.Collections.Generic.List[hashtable]]::new()
}

$suspiciousPorts = @(4444, 1337, 1234, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321, 4445, 5554, 6667, 6697, 1080, 3128, 8080, 8443, 9090, 2222, 4443, 8081, 8082, 9001, 9050, 9051, 1723, 3389)
$knownC2Ports = @(4444, 1337, 31337, 12345, 54321, 5554, 6667, 6697, 9001, 9050, 9051)
$systemProcessesThatShouldNotConnect = @('csrss', 'smss', 'wininit', 'winlogon', 'fontdrvhost', 'dwm')
$svchostAllowedPorts = @(53, 80, 88, 123, 135, 389, 443, 445, 500, 636, 3268, 3269, 4500, 5353)
$privateIpRegex = '^(127\.|10\.|192\.168\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|fe80:|fc00:|fd00:|0\.0\.0\.0$|::$)'
$suspiciousHostnames = @('windowsupdate', 'microsoft.com', 'google.com', 'virustotal', 'malwarebytes', 'kaspersky', 'avast', 'norton', 'mcafee', 'defender', 'eset')

try {
    $tcpConnections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' -or $_.State -eq 'Listen' }
    $processCache = @{}

    try {
        Get-CimInstance Win32_Process -Property ProcessId, Name, ExecutablePath -ErrorAction SilentlyContinue | ForEach-Object {
            $processCache[$_.ProcessId] = @{
                ProcessName = if ($_.Name) { $_.Name -replace '\.exe$', '' } else { "unknown" }
                Path = $_.ExecutablePath
            }
        }
    } catch {}

    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        if (-not $processCache.ContainsKey($_.Id)) {
            $procPath = $null
            try { $procPath = $_.Path } catch {}
            $processCache[$_.Id] = @{
                ProcessName = $_.ProcessName
                Path = $procPath
            }
        } elseif (-not $processCache[$_.Id].Path) {
            try { $processCache[$_.Id].Path = $_.Path } catch {}
        }
    }

    $connectionData = [System.Collections.Generic.List[hashtable]]::new()
    $suspiciousConnections = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($conn in $tcpConnections) {
        $proc = $processCache[$conn.OwningProcess]
        $procName = if ($proc -and $proc.ProcessName) { $proc.ProcessName } else { "unknown" }
        $procPath = if ($proc -and $proc.Path) { $proc.Path } else { "unknown" }
        $procBase = if ($procName -match '^(.*?)\.exe$') { $matches[1].ToLower() } else { $procName.ToLower() }

        $connInfo = @{
            protocol = "TCP"
            state = [string]$conn.State
            local_address = $conn.LocalAddress
            local_port = $conn.LocalPort
            remote_address = $conn.RemoteAddress
            remote_port = $conn.RemotePort
            pid = $conn.OwningProcess
            process_name = $procName
            process_path = $procPath
        }

        $isSuspicious = $false
        $reasons = [System.Collections.Generic.List[string]]::new()

        if ($conn.State -eq 'Established') {
            $remoteIP = $conn.RemoteAddress
            $isLocalOrReserved = $remoteIP -match $privateIpRegex

            if ($conn.RemotePort -in $knownC2Ports) {
                $isSuspicious = $true
                $reasons.Add("known_c2_port|$($conn.RemotePort)")
            }

            if ($conn.RemotePort -in $suspiciousPorts -and -not ($conn.RemotePort -in $knownC2Ports)) {
                $isSuspicious = $true
                $reasons.Add("suspicious_port|$($conn.RemotePort)")
            }

            if ($procBase -in $systemProcessesThatShouldNotConnect -and -not $isLocalOrReserved) {
                $isSuspicious = $true
                $reasons.Add("system_process_external_connection|$procName")
            }

            if ($procBase -eq 'svchost' -and -not $isLocalOrReserved) {
                $isAllowedSvchostPort = ($conn.RemotePort -in $svchostAllowedPorts) -or ($conn.RemotePort -ge 49152 -and $conn.RemotePort -le 65535)
                if (-not $isAllowedSvchostPort) {
                    $isSuspicious = $true
                    $reasons.Add("svchost_unusual_remote_port|$($conn.RemotePort)")
                }
            }

            if ($procBase -eq 'explorer' -and -not $isLocalOrReserved) {
                $isSuspicious = $true
                $reasons.Add("explorer_external_connection")
            }

            if ($procPath -and ($procPath -like "*\Temp\*" -or $procPath -like "*\AppData\Local\Temp\*" -or $procPath -like "*\Downloads\*")) {
                $isSuspicious = $true
                $reasons.Add("connection_from_temp_binary")
            }
        }

        if ($conn.State -eq 'Listen') {
            if ($conn.LocalPort -in $suspiciousPorts) {
                if ($conn.LocalPort -eq 3389 -and ($procBase -eq 'svchost' -or $procBase -eq 'system')) {
                } else {
                    $isSuspicious = $true
                    $reasons.Add("listening_suspicious_port|$($conn.LocalPort)")
                }
            }

            if ($conn.LocalAddress -ne '127.0.0.1' -and $conn.LocalAddress -ne '::1') {
                if ($procPath -and ($procPath -like "*\Temp\*" -or $procPath -like "*\AppData\Local\Temp\*" -or $procPath -like "*\Downloads\*")) {
                    $isSuspicious = $true
                    $reasons.Add("temp_binary_listening")
                }
            }
        }

        if ($isSuspicious) {
            $connInfo.reasons = @($reasons)
            $suspiciousConnections.Add($connInfo)

            $reasonsJoined = $reasons -join ','
            $severity = if ($reasonsJoined -match 'c2_port|system_process_external|explorer_external|connection_from_temp_binary') { "HIGH" } else { "MEDIUM" }

            $result.findings.Add(@{
                id = "NET-001"
                severity = $severity
                mitre = "T1071"
                title = "Suspicious Connection"
                detail = "suspicious_conn|$procName|$($conn.RemoteAddress):$($conn.RemotePort)|$reasonsJoined"
            })
        }

        $connectionData.Add($connInfo)
    }

    $result.data.tcp_connections = @{
        total = $connectionData.Count
        established = ($connectionData | Where-Object { $_.state -eq 'Established' }).Count
        listening = ($connectionData | Where-Object { $_.state -eq 'Listen' }).Count
        suspicious = @($suspiciousConnections)
        all = @($connectionData)
    }

    $udpEndpoints = Get-NetUDPEndpoint
    $udpData = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($udp in $udpEndpoints) {
        $proc = $processCache[$udp.OwningProcess]
        $udpInfo = @{
            protocol = "UDP"
            local_address = $udp.LocalAddress
            local_port = $udp.LocalPort
            pid = $udp.OwningProcess
            process_name = if ($proc -and $proc.ProcessName) { $proc.ProcessName } else { "unknown" }
            process_path = if ($proc -and $proc.Path) { $proc.Path } else { "unknown" }
        }
        $udpData.Add($udpInfo)
    }
    $result.data.udp_endpoints = @{
        total = $udpData.Count
        items = @($udpData)
    }

    try {
        $dnsCache = Get-DnsClientCache | Select-Object Entry, Name, Type, Status, Data, TimeToLive
        $result.data.dns_cache = @{
            total_entries = $dnsCache.Count
            entries = @($dnsCache | ForEach-Object {
                @{
                    entry = $_.Entry
                    name = $_.Name
                    type = [string]$_.Type
                    status = [string]$_.Status
                    data = $_.Data
                    ttl = $_.TimeToLive
                }
            })
        }
    } catch {
        $result.data.dns_cache = @{ status = "skipped"; reason = "access_failed" }
    }

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsFindings = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $hostsContent = Get-Content $hostsPath -ErrorAction Stop
        $hostsEntries = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($line in $hostsContent) {
            $cleanLine = ($line -replace '#.*', '').Trim()
            if ($cleanLine -eq '') { continue }

            $tokens = $cleanLine -split '\s+'
            if ($tokens.Count -ge 2) {
                $ip = $tokens[0]
                $hostnames = $tokens[1..($tokens.Count - 1)]

                foreach ($hostname in $hostnames) {
                    $hostname = $hostname.Trim()
                    if ($hostname -eq '') { continue }

                    $entry = @{
                        ip = $ip
                        hostname = $hostname
                        raw_line = $line.Trim()
                    }
                    $hostsEntries.Add($entry)

                    $isSecurityService = $false
                    foreach ($sh in $suspiciousHostnames) {
                        if ($hostname.ToLower() -like "*$sh*") {
                            $isSecurityService = $true
                            break
                        }
                    }

                    if ($isSecurityService) {
                        $hostsFindings.Add($entry)
                        $result.findings.Add(@{
                            id = "NET-003"
                            severity = "HIGH"
                            mitre = "T1562.001"
                            title = "Security Service Blocked"
                            detail = "hosts_block|$hostname|$ip"
                        })
                    } elseif ($ip -ne '127.0.0.1' -and $ip -ne '::1' -and $ip -ne '0.0.0.0' -and $ip -ne '::') {
                        $hostsFindings.Add($entry)
                        $result.findings.Add(@{
                            id = "NET-002"
                            severity = "HIGH"
                            mitre = "T1565.001"
                            title = "Hosts File Redirect"
                            detail = "hosts_redirect|$hostname|$ip"
                        })
                    }
                }
            }
        }
        $result.data.hosts_file = @{
            path = $hostsPath
            total_entries = $hostsEntries.Count
            entries = @($hostsEntries)
            suspicious_redirects = @($hostsFindings)
        }
    } catch {
        $result.data.hosts_file = @{ status = "skipped"; reason = "access_failed" }
    }

    $firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName
    $result.data.firewall = @{
        profiles = @($firewallProfiles | ForEach-Object {
            $info = @{
                name = $_.Name
                enabled = $_.Enabled
                inbound_default = [string]$_.DefaultInboundAction
                outbound_default = [string]$_.DefaultOutboundAction
                log_file = $_.LogFileName
            }

            if (-not $_.Enabled) {
                $result.findings.Add(@{
                    id = "NET-004"
                    severity = "HIGH"
                    mitre = "T1562.004"
                    title = "Firewall Disabled"
                    detail = "firewall_off|$($_.Name)"
                })
            }
            $info
        })
    }

    try {
        $hkcuProxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        $hklmProxy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue

        $hkcuEnabled = [bool]($hkcuProxy -and $hkcuProxy.ProxyEnable -eq 1)
        $hklmEnabled = [bool]($hklmProxy -and $hklmProxy.ProxyEnable -eq 1)
        $hkcuServer = if ($hkcuProxy -and $hkcuProxy.ProxyServer) { [string]$hkcuProxy.ProxyServer } else { "" }
        $hklmServer = if ($hklmProxy -and $hklmProxy.ProxyServer) { [string]$hklmProxy.ProxyServer } else { "" }
        $hkcuPac = if ($hkcuProxy -and $hkcuProxy.AutoConfigURL) { [string]$hkcuProxy.AutoConfigURL } else { "" }
        $hklmPac = if ($hklmProxy -and $hklmProxy.AutoConfigURL) { [string]$hklmProxy.AutoConfigURL } else { "" }
        $hkcuOverride = if ($hkcuProxy -and $hkcuProxy.ProxyOverride) { [string]$hkcuProxy.ProxyOverride } else { "" }
        $hklmOverride = if ($hklmProxy -and $hklmProxy.ProxyOverride) { [string]$hklmProxy.ProxyOverride } else { "" }

        $winHttpProxy = $null
        try {
            $connKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name "WinHttpSettings" -ErrorAction SilentlyContinue
            if ($connKey -and $connKey.WinHttpSettings) {
                $bytes = $connKey.WinHttpSettings
                if ($bytes.Length -gt 16) {
                    $proxyLen = [BitConverter]::ToInt32($bytes, 12)
                    if ($proxyLen -gt 0 -and ($bytes.Length -ge (16 + $proxyLen))) {
                        $rawProxy = [System.Text.Encoding]::ASCII.GetString($bytes, 16, $proxyLen).Trim()
                        if ($rawProxy -ne '') {
                            $winHttpProxy = $rawProxy
                        }
                    }
                }
            }
        } catch {}

        $result.data.proxy = @{
            hkcu = @{
                enabled = $hkcuEnabled
                server = $hkcuServer
                override = $hkcuOverride
                auto_config = $hkcuPac
            }
            hklm = @{
                enabled = $hklmEnabled
                server = $hklmServer
                override = $hklmOverride
                auto_config = $hklmPac
            }
            winhttp = @{
                server = if ($winHttpProxy) { $winHttpProxy } else { "" }
            }
        }

        if ($hkcuEnabled -and -not [string]::IsNullOrWhiteSpace($hkcuServer)) {
            $result.findings.Add(@{
                id = "NET-005"
                severity = "MEDIUM"
                mitre = "T1090"
                title = "Proxy Configured"
                detail = "hkcu_proxy|$hkcuServer"
            })
        }

        if (-not [string]::IsNullOrWhiteSpace($hkcuPac)) {
            $result.findings.Add(@{
                id = "NET-006"
                severity = "MEDIUM"
                mitre = "T1090"
                title = "PAC URL Configured"
                detail = "hkcu_pac_url|$hkcuPac"
            })
        }

        if ($hklmEnabled -and -not [string]::IsNullOrWhiteSpace($hklmServer)) {
            $result.findings.Add(@{
                id = "NET-005"
                severity = "MEDIUM"
                mitre = "T1090"
                title = "Proxy Configured"
                detail = "hklm_proxy|$hklmServer"
            })
        }

        if (-not [string]::IsNullOrWhiteSpace($hklmPac)) {
            $result.findings.Add(@{
                id = "NET-006"
                severity = "MEDIUM"
                mitre = "T1090"
                title = "PAC URL Configured"
                detail = "hklm_pac_url|$hklmPac"
            })
        }

        if (-not [string]::IsNullOrWhiteSpace($winHttpProxy)) {
            $result.findings.Add(@{
                id = "NET-005"
                severity = "MEDIUM"
                mitre = "T1090"
                title = "Proxy Configured"
                detail = "winhttp_proxy|$winHttpProxy"
            })
        }
    } catch {
        $result.data.proxy = @{ status = "skipped"; reason = "access_failed" }
    }

} catch {
    $result.status = "error"
    $result.data.error = $_.Exception.Message
}

$targetDir = [System.IO.Path]::GetFullPath("$PSScriptRoot\..\chunks")
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

$json = $result | ConvertTo-Json -Depth 10 -Compress
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText("$targetDir\chunk_08_network.json", $json, $utf8NoBom)
