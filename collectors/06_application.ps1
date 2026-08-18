$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

$result = @{
    chunk_id = "06_application"
    timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    layer_name = "Application Layer"
    status = "completed"
    data = @{}
    findings = @()
}

function Get-ParsedVersion {
    param([string]$verStr)
    try {
        $cleanVer = ($verStr -split '_')[0]
        $cleanVer = ($cleanVer -replace '[^\d\.]', '')
        $parts = $cleanVer.Split('.')
        while ($parts.Count -lt 2) { $parts += "0" }
        if ($parts.Count -gt 4) { $parts = $parts[0..3] }
        return [version]($parts -join '.')
    } catch {
        return [version]"0.0.0.0"
    }
}

function Resolve-ExtensionName {
    param(
        [string]$Name,
        [string]$VersionDirPath,
        [string]$DefaultLocale
    )
    if (-not $Name) { return "unknown" }
    if ($Name -match '^__MSG_(?<key>[A-Za-z0-9_@]+)__$') {
        $key = $Matches['key']
        $candidateLocales = @()
        if ($DefaultLocale) { $candidateLocales += $DefaultLocale }
        $candidateLocales += @('en', 'en_US', 'en_GB')

        $localesDir = Join-Path $VersionDirPath "_locales"
        if (Test-Path -LiteralPath $localesDir) {
            foreach ($loc in $candidateLocales) {
                $msgFile = Join-Path $localesDir "$loc\messages.json"
                if (Test-Path -LiteralPath $msgFile) {
                    try {
                        $msgData = Get-Content -LiteralPath $msgFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                        if ($msgData) {
                            $prop = $msgData.PSObject.Properties | Where-Object { $_.Name -ieq $key } | Select-Object -First 1
                            if ($prop -and $prop.Value -and $prop.Value.message) {
                                return [string]$prop.Value.message
                            }
                        }
                    } catch {}
                }
            }

            try {
                $allLocales = Get-ChildItem -LiteralPath $localesDir -Directory -ErrorAction SilentlyContinue
                foreach ($ld in $allLocales) {
                    $msgFile = Join-Path $ld.FullName "messages.json"
                    if (Test-Path -LiteralPath $msgFile) {
                        try {
                            $msgData = Get-Content -LiteralPath $msgFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                            if ($msgData) {
                                $prop = $msgData.PSObject.Properties | Where-Object { $_.Name -ieq $key } | Select-Object -First 1
                                if ($prop -and $prop.Value -and $prop.Value.message) {
                                    return [string]$prop.Value.message
                                }
                            }
                        } catch {}
                    }
                }
            } catch {}
        }
    }
    return $Name
}

function Test-OfficeMacro {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) { return @{ has_macro = $false; method = "none" } }

    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()

    if ($ext -in @('.dotm', '.docm', '.xlsm', '.xltm', '.potm', '.pptm', '.dotx', '.docx', '.xlsx', '.xltx', '.potx', '.pptx')) {
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
            try {
                $hasVba = $false
                foreach ($entry in $zip.Entries) {
                    if ($entry.FullName -like "*vbaProject.bin*" -or $entry.FullName -like "*vbaData.xml*") {
                        $hasVba = $true
                        break
                    }
                }
                return @{ has_macro = $hasVba; method = "zip_vba_entry" }
            } finally {
                $zip.Dispose()
            }
        } catch {
            return @{ has_macro = $false; method = "zip_error" }
        }
    }

    if ($ext -in @('.xlsb', '.xls', '.doc', '.dot', '.ppt', '.pot')) {
        try {
            $stream = [System.IO.File]::OpenRead($FilePath)
            try {
                $maxBytesToRead = [Math]::Min($stream.Length, 8MB)
                $buffer = New-Object byte[] $maxBytesToRead
                $bytesRead = $stream.Read($buffer, 0, $maxBytesToRead)
                $strAscii = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                $strUnicode = [System.Text.Encoding]::Unicode.GetString($buffer, 0, $bytesRead)
                if ($strAscii -match 'vbaProject|VBA|_VBA_PROJECT|Attribut\x00e' -or $strUnicode -match 'vbaProject|VBA|_VBA_PROJECT|Attribute') {
                    return @{ has_macro = $true; method = "binary_vba_signature" }
                }
                return @{ has_macro = $false; method = "binary_scan" }
            } finally {
                $stream.Dispose()
            }
        } catch {
            return @{ has_macro = $false; method = "read_error" }
        }
    }

    return @{ has_macro = $false; method = "unsupported_ext" }
}

try {
    $browserShortcutPaths = @(
        "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        "$env:PUBLIC\Desktop"
        "$env:USERPROFILE\Desktop"
        [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs")
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
    )

    $suspiciousLnkParams = @('--load-extension', '--proxy-server', '--disable-extensions', '--user-data-dir', '--restore-last-session', '--disable-web-security', '--allow-file-access-from-files', '--disable-default-apps')
    $browserLnkFindings = @()

    $shell = $null
    try {
        $shell = New-Object -ComObject WScript.Shell
        foreach ($lnkPath in $browserShortcutPaths) {
            if (-not (Test-Path -LiteralPath $lnkPath)) { continue }
            try {
                $lnkFiles = Get-ChildItem -LiteralPath $lnkPath -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 100
                foreach ($lnkFile in $lnkFiles) {
                    $shortcut = $null
                    try {
                        $shortcut = $shell.CreateShortcut($lnkFile.FullName)
                        $targetLower = "$($shortcut.TargetPath)".ToLower()

                        $isBrowser = $targetLower -match '(chrome|firefox|msedge|brave|opera|iexplore|vivaldi)\.exe'
                        if (-not $isBrowser) { continue }

                        $args = $shortcut.Arguments
                        if (-not $args) { continue }

                        $argsLower = $args.ToLower()
                        $matchedParams = @()
                        foreach ($param in $suspiciousLnkParams) {
                            if ($argsLower -like "*$param*") {
                                $matchedParams += $param
                            }
                        }

                        if ($matchedParams.Count -gt 0) {
                            $browserLnkFindings += @{
                                lnk_path = $lnkFile.FullName
                                target = $shortcut.TargetPath
                                arguments = $args
                                suspicious_params = $matchedParams
                            }

                            $result.findings += @{
                                id = "APP-001"
                                severity = "HIGH"
                                mitre = "T1176"
                                title = "Browser Shortcut Hijack"
                                detail = "browser_lnk|$($lnkFile.Name)|params:$($matchedParams -join ',')"
                            }
                        }
                    } catch {} finally {
                        if ($shortcut) {
                            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null
                            $shortcut = $null
                        }
                    }
                }
            } catch {}
        }
    } catch {} finally {
        if ($shell) {
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
            $shell = $null
        }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
    $result.data.browser_shortcut_hijacks = $browserLnkFindings

    $browserBases = @(
        @{ browser = "Chrome"; userData = "$env:LOCALAPPDATA\Google\Chrome\User Data" }
        @{ browser = "Chrome_Beta"; userData = "$env:LOCALAPPDATA\Google\Chrome Beta\User Data" }
        @{ browser = "Edge"; userData = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }
        @{ browser = "Brave"; userData = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
        @{ browser = "Opera"; userData = "$env:APPDATA\Opera Software\Opera Stable" }
        @{ browser = "Opera_GX"; userData = "$env:APPDATA\Opera Software\Opera GX Stable" }
        @{ browser = "Vivaldi"; userData = "$env:LOCALAPPDATA\Vivaldi\User Data" }
    )

    $extensions = @()
    foreach ($bb in $browserBases) {
        if (-not (Test-Path -LiteralPath $bb.userData)) { continue }
        try {
            $profileDirs = @()
            $directExt = Join-Path $bb.userData "Extensions"
            if (Test-Path -LiteralPath $directExt) {
                $profileDirs += @{ profile_name = "Default"; ext_path = $directExt }
            }

            $subDirs = Get-ChildItem -LiteralPath $bb.userData -Directory -ErrorAction SilentlyContinue |
                Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "Extensions") }

            foreach ($sd in $subDirs) {
                $subExt = Join-Path $sd.FullName "Extensions"
                $alreadyAdded = $profileDirs | Where-Object { $_.ext_path -ieq $subExt }
                if (-not $alreadyAdded) {
                    $profileDirs += @{ profile_name = $sd.Name; ext_path = $subExt }
                }
            }

            foreach ($pd in $profileDirs) {
                $extDirs = Get-ChildItem -LiteralPath $pd.ext_path -Directory -ErrorAction SilentlyContinue
                foreach ($extDir in $extDirs) {
                    $versionDirs = Get-ChildItem -LiteralPath $extDir.FullName -Directory -ErrorAction SilentlyContinue |
                        Sort-Object { Get-ParsedVersion $_.Name } -Descending |
                        Select-Object -First 1

                    $manifest = $null
                    $selectedVersionDir = $null
                    foreach ($vd in $versionDirs) {
                        $selectedVersionDir = $vd
                        $manifestPath = Join-Path $vd.FullName "manifest.json"
                        if (Test-Path -LiteralPath $manifestPath) {
                            try {
                                $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                            } catch {}
                        }
                    }

                    $rawName = if ($manifest -and $manifest.name) { [string]$manifest.name } else { "unknown" }
                    $resolvedName = if ($selectedVersionDir -and $manifest) {
                        Resolve-ExtensionName -Name $rawName -VersionDirPath $selectedVersionDir.FullName -DefaultLocale $manifest.default_locale
                    } else {
                        $rawName
                    }

                    $extInfo = @{
                        browser = $bb.browser
                        profile = $pd.profile_name
                        extension_id = $extDir.Name
                        name = $resolvedName
                        raw_name = $rawName
                        version = if ($manifest -and $manifest.version) { [string]$manifest.version } else { "unknown" }
                        permissions = if ($manifest -and $manifest.permissions) { @($manifest.permissions) } else { @() }
                        content_scripts = if ($manifest -and $manifest.content_scripts) { $true } else { $false }
                    }

                    $criticalPerms = @('debugger', 'proxy', 'webRequestBlocking')
                    $hasCritical = @($extInfo.permissions | Where-Object { $_ -in $criticalPerms })
                    $monitoringPerms = @('nativeMessaging', 'cookies', 'clipboardRead', 'management')
                    $hasMonitoring = @($extInfo.permissions | Where-Object { $_ -in $monitoringPerms })

                    if ($hasCritical.Count -gt 0) {
                        $result.findings += @{
                            id = "APP-002"
                            severity = "MEDIUM"
                            mitre = "T1176"
                            title = "Extension Critical Permissions"
                            detail = "ext_perms|$($bb.browser)|$($pd.profile_name)|$($extInfo.name)|$($hasCritical -join ',')"
                        }
                    } elseif ($hasMonitoring.Count -gt 0) {
                        $result.findings += @{
                            id = "APP-002"
                            severity = "LOW"
                            mitre = "T1176"
                            title = "Extension Sensitive Permissions"
                            detail = "ext_perms|$($bb.browser)|$($pd.profile_name)|$($extInfo.name)|$($hasMonitoring -join ',')"
                        }
                    }

                    $extensions += $extInfo
                }
            }
        } catch {}
    }
    $result.data.browser_extensions = @{
        total = $extensions.Count
        items = $extensions
    }

    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    $firefoxExtensions = @()
    if (Test-Path -LiteralPath $firefoxPath) {
        try {
            $profiles = Get-ChildItem -LiteralPath $firefoxPath -Directory -ErrorAction SilentlyContinue
            foreach ($profile in $profiles) {
                $extJsonPath = Join-Path $profile.FullName "extensions.json"
                if (Test-Path -LiteralPath $extJsonPath) {
                    try {
                        $extData = Get-Content -LiteralPath $extJsonPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                        if ($extData -and $extData.addons) {
                            foreach ($addon in $extData.addons) {
                                $addonName = if ($addon.defaultLocale -and $addon.defaultLocale.name) {
                                    $addon.defaultLocale.name
                                } elseif ($addon.name) {
                                    $addon.name
                                } else {
                                    $addon.id
                                }

                                $firefoxExtensions += @{
                                    browser = "Firefox"
                                    profile = $profile.Name
                                    name = $addonName
                                    id = $addon.id
                                    version = $addon.version
                                    active = $addon.active
                                    type = $addon.type
                                    signed = if ($addon.signedState -eq 2) { $true } else { $false }
                                }

                                if ($addon.signedState -ne 2 -and $addon.active) {
                                    $result.findings += @{
                                        id = "APP-003"
                                        severity = "MEDIUM"
                                        mitre = "T1176"
                                        title = "Unsigned Firefox Extension"
                                        detail = "ff_unsigned|$addonName|$($addon.id)"
                                    }
                                }
                            }
                        }
                    } catch {}
                }
            }
        } catch {}
    }
    $result.data.firefox_extensions = $firefoxExtensions

    $officeTemplates = @()
    $templatePaths = @(
        @{ type = "Word"; path = "$env:APPDATA\Microsoft\Templates\Normal.dotm" }
        @{ type = "Word_Email"; path = "$env:APPDATA\Microsoft\Templates\NormalEmail.dotm" }
        @{ type = "Excel"; path = "$env:APPDATA\Microsoft\Excel\XLSTART\Personal.xlsb" }
        @{ type = "PowerPoint"; path = "$env:APPDATA\Microsoft\Templates\Blank.potx" }
        @{ type = "PowerPoint_Macro"; path = "$env:APPDATA\Microsoft\Templates\Blank.potm" }
    )

    $extraTemplateDirs = @(
        "$env:APPDATA\Microsoft\Word\STARTUP",
        "$env:APPDATA\Microsoft\Excel\XLSTART"
    )

    foreach ($ed in $extraTemplateDirs) {
        if (Test-Path -LiteralPath $ed) {
            try {
                $extraFiles = Get-ChildItem -LiteralPath $ed -File -ErrorAction SilentlyContinue
                foreach ($ef in $extraFiles) {
                    $ext = $ef.Extension.ToLower()
                    if ($ext -in @('.dotm', '.xltm', '.xlsb', '.dot', '.xla', '.xlam', '.wll')) {
                        $alreadyIn = $templatePaths | Where-Object { $_.path -ieq $ef.FullName }
                        if (-not $alreadyIn) {
                            $templatePaths += @{ type = "Startup_Addin"; path = $ef.FullName }
                        }
                    }
                }
            } catch {}
        }
    }

    foreach ($tp in $templatePaths) {
        if (Test-Path -LiteralPath $tp.path) {
            try {
                $fileInfo = Get-Item -LiteralPath $tp.path -ErrorAction SilentlyContinue
                if (-not $fileInfo) { continue }

                $macroCheck = Test-OfficeMacro -FilePath $tp.path
                $templateInfo = @{
                    type = $tp.type
                    path = $tp.path
                    size_kb = [Math]::Round($fileInfo.Length / 1KB, 2)
                    last_modified = $fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    has_macro = $macroCheck.has_macro
                    macro_detection_method = $macroCheck.method
                }
                $officeTemplates += $templateInfo

                if ($macroCheck.has_macro) {
                    $result.findings += @{
                        id = "APP-004"
                        severity = "HIGH"
                        mitre = "T1137.001"
                        title = "Office Template Macro Found"
                        detail = "office_macro|$($tp.type)|$($tp.path)|size:$([Math]::Round($fileInfo.Length / 1KB, 2))KB"
                    }
                } elseif ($fileInfo.Length -gt 50KB) {
                    $result.findings += @{
                        id = "APP-007"
                        severity = "MEDIUM"
                        mitre = "T1137.001"
                        title = "Large Office Template"
                        detail = "large_template|$($tp.type)|$($tp.path)|size:$([Math]::Round($fileInfo.Length / 1KB, 2))KB"
                    }
                }
            } catch {}
        }
    }
    $result.data.office_templates = $officeTemplates

    $gitHookFindings = @()
    $targetDevPaths = @(
        "$env:USERPROFILE\source",
        "$env:USERPROFILE\projects",
        "$env:USERPROFILE\repos",
        "$env:USERPROFILE\workspace",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\go",
        "$env:USERPROFILE\IdeaProjects",
        "C:\Projects",
        "C:\src",
        "C:\dev"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $skipDirs = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    @('AppData', 'node_modules', '.cache', 'target', 'bin', 'obj', 'venv', '.env', 'packages', 'vendor', '.nuget') | ForEach-Object { $skipDirs.Add($_) | Out-Null }

    foreach ($devPath in $targetDevPaths) {
        try {
            $dirsQueue = New-Object System.Collections.Generic.Queue[string]
            $dirsQueue.Enqueue($devPath)
            $depthMap = New-Object 'System.Collections.Generic.Dictionary[string, int]'
            $depthMap[$devPath] = 0

            while ($dirsQueue.Count -gt 0 -and $gitHookFindings.Count -lt 20) {
                $curr = $dirsQueue.Dequeue()
                $currDepth = $depthMap[$curr]

                $gitHookDir = Join-Path $curr ".git\hooks"
                if (Test-Path -LiteralPath $gitHookDir) {
                    try {
                        $hookFiles = Get-ChildItem -LiteralPath $gitHookDir -File -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -notlike "*.sample" -and $_.Length -gt 0 }

                        foreach ($hf in $hookFiles) {
                            $gitHookFindings += @{
                                repo = $curr
                                hook_name = $hf.Name
                                path = $hf.FullName
                                size_bytes = $hf.Length
                            }
                        }
                    } catch {}
                }

                if ($currDepth -lt 3) {
                    try {
                        $subDirs = [System.IO.Directory]::GetDirectories($curr)
                        foreach ($sd in $subDirs) {
                            $sdName = [System.IO.Path]::GetFileName($sd)
                            if ($sdName.StartsWith('.') -or $skipDirs.Contains($sdName)) {
                                continue
                            }
                            $dirsQueue.Enqueue($sd)
                            $depthMap[$sd] = $currDepth + 1
                        }
                    } catch {}
                }
            }
        } catch {}
    }
    $result.data.git_hooks = $gitHookFindings

    if ($gitHookFindings.Count -gt 0) {
        $result.findings += @{
            id = "APP-005"
            severity = "LOW"
            mitre = "T1554"
            title = "Git Hooks Found"
            detail = "git_hooks|count:$($gitHookFindings.Count)"
        }
    }

    $profileFiles = @(
        @{ name = ".bashrc"; path = "$env:USERPROFILE\.bashrc" }
        @{ name = ".zshrc"; path = "$env:USERPROFILE\.zshrc" }
        @{ name = ".profile"; path = "$env:USERPROFILE\.profile" }
        @{ name = "profile.ps1"; path = "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1" }
        @{ name = "profile.ps1_old"; path = "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" }
        @{ name = "profile_allusers.ps1"; path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1" }
    )

    $profileFindings = @()
    foreach ($pf in $profileFiles) {
        if (Test-Path -LiteralPath $pf.path) {
            try {
                $fileInfo = Get-Item -LiteralPath $pf.path -ErrorAction SilentlyContinue
                if (-not $fileInfo) { continue }
                $content = Get-Content -LiteralPath $pf.path -Raw -ErrorAction SilentlyContinue
                $profileFindings += @{
                    name = $pf.name
                    path = $pf.path
                    size_kb = [Math]::Round($fileInfo.Length / 1KB, 2)
                    last_modified = $fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    has_download_commands = if ($content) { [bool]($content -match '(?s)(curl|wget|Invoke-WebRequest|DownloadString|DownloadFile|Start-BitsTransfer)') } else { $false }
                    has_encoded_content = if ($content) { [bool]($content -match '(base64|FromBase64String|-EncodedCommand)') } else { $false }
                }

                if ($content -match '(?s)(curl|wget|Invoke-WebRequest|DownloadString|DownloadFile|Start-BitsTransfer).*https?://') {
                    $result.findings += @{
                        id = "APP-006"
                        severity = "MEDIUM"
                        mitre = "T1546.004"
                        title = "Profile Download Command"
                        detail = "profile_download|$($pf.name)|$($pf.path)"
                    }
                }
            } catch {}
        }
    }
    $result.data.shell_profiles = $profileFindings

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

if (-not (Test-Path -LiteralPath $chunkDir)) {
    New-Item -ItemType Directory -Path $chunkDir -Force | Out-Null
}
$chunkPath = Join-Path $chunkDir "chunk_06_application.json"
[System.IO.File]::WriteAllText($chunkPath, $json, $utf8NoBom)
