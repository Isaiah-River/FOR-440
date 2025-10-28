<#
.SYNOPSIS
    Threat Hunting Script for Thug Lyfe Campaign 2
   
.DESCRIPTION
    Comprehensive threat hunting script to identify artifacts from the Thug Lyfe Campaign 2
    based on the malware analysis report findings.
   
.NOTES
    Run as Administrator
    Compatible with: Windows 10/11, PowerShell 7+
   
    Known IOCs:
    - frontpage.jpg (Base64 encoded PowerShell in EXIF)
    - image_downloader.exe (Malicious downloader)
    - SecurityAdvisory.docm (VBA macro document)
    - asefa.bat (Downloaded batch file - NOT in original analysis!)
    - Malicious IPs: 108.181.155.31, 192.168.1.2
#>


#Requires -RunAsAdministrator


Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Thug Lyfe Campaign 2 - Threat Hunt" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""


# Create output directory
$OutputDir = ".\ThreatHunt_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Write-Host "[+] Created output directory: $OutputDir" -ForegroundColor Green
}


# Initialize findings array
$Findings = @()


# Known IOCs from malware report
$KnownMaliciousIPs = @("108.181.155.31", "192.168.1.2")
$KnownMaliciousFiles = @("frontpage.jpg", "image_downloader.exe", "SecurityAdvisory.docm", "asefa.bat")


# ============================================
# HUNT 1: FILE SYSTEM ARTIFACTS
# ============================================
Write-Host "`n[+] HUNT 1: Searching for malicious files..." -ForegroundColor Yellow


foreach ($fileName in $KnownMaliciousFiles) {
    Write-Host "  [*] Searching for: $fileName" -ForegroundColor Cyan
   
    $files = Get-ChildItem -Path C:\ -Recurse -Filter $fileName -ErrorAction SilentlyContinue
   
    if ($files) {
        foreach ($file in $files) {
            $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
           
            $finding = [PSCustomObject]@{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Category = "Malicious File"
                Artifact = $fileName
                Location = $file.FullName
                FileSize = $file.Length
                CreationTime = $file.CreationTime
                LastWriteTime = $file.LastWriteTime
                LastAccessTime = $file.LastAccessTime
                SHA256 = $hash.Hash
                Severity = if ($fileName -eq "asefa.bat") {"CRITICAL - Not in original analysis!"} else {"HIGH"}
                Notes = "Found on filesystem"
            }
           
            $Findings += $finding
            Write-Host "    [✓] FOUND: $($file.FullName)" -ForegroundColor Red
            Write-Host "        Size: $($file.Length) bytes" -ForegroundColor Gray
            Write-Host "        Created: $($file.CreationTime)" -ForegroundColor Gray
            Write-Host "        SHA256: $($hash.Hash)" -ForegroundColor Gray
        }
    } else {
        Write-Host "    [-] Not found: $fileName" -ForegroundColor Gray
    }
}


# ============================================
# HUNT 2: SPECIFIC SUSPICIOUS LOCATIONS
# ============================================
Write-Host "`n[+] HUNT 2: Checking suspicious locations..." -ForegroundColor Yellow


$SuspiciousLocations = @{
    "C:\ProgramData" = "Common malware drop location (asefa.bat expected here)"
    "C:\Windows\Temp" = "Temporary execution location"
    "C:\Users\Public" = "Public access location"
}


foreach ($location in $SuspiciousLocations.Keys) {
    if (Test-Path $location) {
        Write-Host "  [*] Checking: $location" -ForegroundColor Cyan
       
        $suspiciousFiles = Get-ChildItem -Path $location -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -like "*asefa*" -or
                $_.Name -like "*thug*" -or
                $_.Name -like "*image_downloader*" -or
                $_.Extension -in @(".bat", ".ps1", ".exe", ".docm", ".jpg")
            }
       
        foreach ($file in $suspiciousFiles) {
            $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
           
            $finding = [PSCustomObject]@{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Category = "Suspicious Location"
                Artifact = $file.Name
                Location = $file.FullName
                FileSize = $file.Length
                CreationTime = $file.CreationTime
                LastWriteTime = $file.LastWriteTime
                LastAccessTime = $file.LastAccessTime
                SHA256 = $hash.Hash
                Severity = "MODERATE"
                Notes = "Found in: $($SuspiciousLocations[$location])"
            }
           
            $Findings += $finding
            Write-Host "    [!] Suspicious file: $($file.Name)" -ForegroundColor Yellow
        }
    }
}


# ============================================
# HUNT 3: NETWORK INDICATORS
# ============================================
Write-Host "`n[+] HUNT 3: Checking network indicators..." -ForegroundColor Yellow


# Active connections to malicious IPs
$activeConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Where-Object {$_.RemoteAddress -in $KnownMaliciousIPs}


if ($activeConnections) {
    foreach ($conn in $activeConnections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
       
        $finding = [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Category = "Network Connection"
            Artifact = "Active connection to $($conn.RemoteAddress)"
            Location = "Port: $($conn.RemotePort)"
            FileSize = "N/A"
            CreationTime = "N/A"
            LastWriteTime = "N/A"
            LastAccessTime = "N/A"
            SHA256 = "N/A"
            Severity = "CRITICAL"
            Notes = "Process: $($process.Name) (PID: $($conn.OwningProcess))"
        }
       
        $Findings += $finding
        Write-Host "  [✓] Active connection found to: $($conn.RemoteAddress)" -ForegroundColor Red
    }
} else {
    Write-Host "  [-] No active connections to known malicious IPs" -ForegroundColor Gray
}


# DNS cache check
Write-Host "  [*] Checking DNS cache..." -ForegroundColor Cyan
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
    Where-Object {$_.Entry -like "*108.181.155.31*" -or $_.Entry -like "*192.168.1.2*"}


foreach ($entry in $dnsCache) {
    $finding = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = "DNS Cache"
        Artifact = $entry.Entry
        Location = "DNS Cache"
        FileSize = "N/A"
        CreationTime = "N/A"
        LastWriteTime = "N/A"
        LastAccessTime = "N/A"
        SHA256 = "N/A"
        Severity = "HIGH"
        Notes = "Found in DNS cache - indicates recent lookup"
    }
   
    $Findings += $finding
    Write-Host "  [!] DNS cache entry: $($entry.Entry)" -ForegroundColor Yellow
}


# ============================================
# HUNT 4: POWERSHELL EXECUTION EVIDENCE
# ============================================
Write-Host "`n[+] HUNT 4: Checking PowerShell execution evidence..." -ForegroundColor Yellow


# PowerShell history
$psHistoryPath = (Get-PSReadlineOption).HistorySavePath
if (Test-Path $psHistoryPath) {
    $suspiciousCommands = Get-Content $psHistoryPath |
        Select-String -Pattern "invoke-webrequest|108.181.155.31|192.168.1.2|asefa"
   
    foreach ($cmd in $suspiciousCommands) {
        $finding = [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Category = "PowerShell History"
            Artifact = "Suspicious command"
            Location = $psHistoryPath
            FileSize = "N/A"
            CreationTime = "N/A"
            LastWriteTime = "N/A"
            LastAccessTime = "N/A"
            SHA256 = "N/A"
            Severity = "HIGH"
            Notes = "Command: $($cmd.Line)"
        }
       
        $Findings += $finding
        Write-Host "  [!] Suspicious PowerShell command found" -ForegroundColor Yellow
    }
}


# PowerShell event logs (Script Block Logging)
Write-Host "  [*] Checking PowerShell event logs..." -ForegroundColor Cyan
try {
    $psEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-PowerShell/Operational'
        ID=4104
    } -MaxEvents 100 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Message -like "*invoke-webrequest*" -or
            $_.Message -like "*108.181.155.31*" -or
            $_.Message -like "*asefa*"
        }
   
    foreach ($event in $psEvents) {
        $finding = [PSCustomObject]@{
            Timestamp = $event.TimeCreated
            Category = "PowerShell Event Log"
            Artifact = "Script Block Execution"
            Location = "Event ID 4104"
            FileSize = "N/A"
            CreationTime = $event.TimeCreated
            LastWriteTime = "N/A"
            LastAccessTime = "N/A"
            SHA256 = "N/A"
            Severity = "HIGH"
            Notes = "Script execution logged: $($event.Message.Substring(0, 100))..."
        }
       
        $Findings += $finding
        Write-Host "  [✓] PowerShell script execution event found" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] Could not access PowerShell event logs" -ForegroundColor Gray
}


# ============================================
# HUNT 5: OFFICE MACRO EXECUTION
# ============================================
Write-Host "`n[+] HUNT 5: Checking for Office macro execution..." -ForegroundColor Yellow


try {
    $processEvents = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4688
    } -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Message -like "*WINWORD.EXE*" -and
            ($_.Message -like "*powershell*" -or $_.Message -like "*cmd.exe*")
        }
   
    foreach ($event in $processEvents) {
        $finding = [PSCustomObject]@{
            Timestamp = $event.TimeCreated
            Category = "Process Creation"
            Artifact = "Office spawned PowerShell/CMD"
            Location = "Event ID 4688"
            FileSize = "N/A"
            CreationTime = $event.TimeCreated
            LastWriteTime = "N/A"
            LastAccessTime = "N/A"
            SHA256 = "N/A"
            Severity = "CRITICAL"
            Notes = "WINWORD.EXE spawned suspicious child process"
        }
       
        $Findings += $finding
        Write-Host "  [✓] Office macro execution detected!" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] Could not access Security event logs" -ForegroundColor Gray
}


# Check recent Office files
$recentOffice = Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Office\Recent" -Recurse -ErrorAction SilentlyContinue


foreach ($file in $recentOffice) {
    if ($file.Name -like "*SecurityAdvisory*") {
        $finding = [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Category = "Office Recent Files"
            Artifact = $file.Name
            Location = $file.FullName
            FileSize = $file.Length
            CreationTime = $file.CreationTime
            LastWriteTime = $file.LastWriteTime
            LastAccessTime = $file.LastAccessTime
            SHA256 = "N/A"
            Severity = "HIGH"
            Notes = "Malicious document in recent files"
        }
       
        $Findings += $finding
        Write-Host "  [!] Malicious document in recent files" -ForegroundColor Yellow
    }
}


# ============================================
# HUNT 6: PREFETCH ANALYSIS
# ============================================
Write-Host "`n[+] HUNT 6: Analyzing Prefetch files..." -ForegroundColor Yellow


$prefetchFiles = Get-ChildItem C:\Windows\Prefetch -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -like "*IMAGE_DOWNLOADER*" -or
        $_.Name -like "*ASEFA*" -or
        $_.Name -like "*POWERSHELL*" -or
        $_.Name -like "*CMD*"
    }


foreach ($pf in $prefetchFiles) {
    $finding = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = "Prefetch"
        Artifact = $pf.Name
        Location = $pf.FullName
        FileSize = $pf.Length
        CreationTime = $pf.CreationTime
        LastWriteTime = $pf.LastWriteTime
        LastAccessTime = $pf.LastAccessTime
        SHA256 = "N/A"
        Severity = "MODERATE"
        Notes = "Execution evidence in Prefetch"
    }
   
    $Findings += $finding
    Write-Host "  [!] Execution evidence: $($pf.Name)" -ForegroundColor Yellow
}


# ============================================
# HUNT 7: PERSISTENCE MECHANISMS
# ============================================
Write-Host "`n[+] HUNT 7: Checking persistence mechanisms..." -ForegroundColor Yellow


# Registry Run keys
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)


foreach ($key in $runKeys) {
    try {
        $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
       
        foreach ($prop in $entries.PSObject.Properties) {
            if ($prop.Value -like "*asefa*" -or $prop.Value -like "*thug*" -or $prop.Value -like "*image_downloader*") {
                $finding = [PSCustomObject]@{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Category = "Registry Persistence"
                    Artifact = $prop.Name
                    Location = $key
                    FileSize = "N/A"
                    CreationTime = "N/A"
                    LastWriteTime = "N/A"
                    LastAccessTime = "N/A"
                    SHA256 = "N/A"
                    Severity = "CRITICAL"
                    Notes = "Value: $($prop.Value)"
                }
               
                $Findings += $finding
                Write-Host "  [✓] Persistence found: $($prop.Name)" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "  [-] Could not access: $key" -ForegroundColor Gray
    }
}


# Scheduled Tasks
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object {
        $_.TaskName -like "*asefa*" -or
        $_.TaskName -like "*thug*" -or
        $_.TaskName -like "*image*"
    }


foreach ($task in $tasks) {
    $finding = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = "Scheduled Task"
        Artifact = $task.TaskName
        Location = $task.TaskPath
        FileSize = "N/A"
        CreationTime = "N/A"
        LastWriteTime = "N/A"
        LastAccessTime = "N/A"
        SHA256 = "N/A"
        Severity = "HIGH"
        Notes = "Action: $($task.Actions.Execute)"
    }
   
    $Findings += $finding
    Write-Host "  [!] Suspicious scheduled task: $($task.TaskName)" -ForegroundColor Yellow
}


# ============================================
# SPECIAL: ANALYZE asefa.bat (if found)
# ============================================
Write-Host "`n[+] SPECIAL: Detailed analysis of asefa.bat..." -ForegroundColor Yellow


$asefaPath = "C:\ProgramData\asefa.bat"
if (Test-Path $asefaPath) {
    Write-Host "  [✓✓✓] CRITICAL: asefa.bat FOUND!" -ForegroundColor Red
    Write-Host "  [!] This file was NOT in the original malware analysis report!" -ForegroundColor Red
   
    $asefaFile = Get-Item $asefaPath
    $asefaHash = Get-FileHash -Path $asefaPath -Algorithm SHA256
    $asefaContent = Get-Content $asefaPath -Raw
   
    # Save detailed analysis
    $asefaAnalysis = [PSCustomObject]@{
        FileName = $asefaFile.Name
        FullPath = $asefaFile.FullName
        FileSize = $asefaFile.Length
        CreationTime = $asefaFile.CreationTime
        LastWriteTime = $asefaFile.LastWriteTime
        LastAccessTime = $asefaFile.LastAccessTime
        MD5 = (Get-FileHash -Path $asefaPath -Algorithm MD5).Hash
        SHA256 = $asefaHash.Hash
        FileContent = $asefaContent
        Significance = "CRITICAL - Not included in original malware analysis!"
    }
   
    $asefaAnalysis | Export-Csv -Path "$OutputDir\CRITICAL_asefa_bat_analysis.csv" -NoTypeInformation
    $asefaContent | Out-File -FilePath "$OutputDir\CRITICAL_asefa_bat_content.txt"
   
    Write-Host "  [+] Detailed analysis saved to: CRITICAL_asefa_bat_analysis.csv" -ForegroundColor Green
    Write-Host "  [+] File content saved to: CRITICAL_asefa_bat_content.txt" -ForegroundColor Green
   
    Write-Host "`n  === asefa.bat Details ===" -ForegroundColor Cyan
    Write-Host "  Path: $($asefaFile.FullName)" -ForegroundColor White
    Write-Host "  Size: $($asefaFile.Length) bytes" -ForegroundColor White
    Write-Host "  Created: $($asefaFile.CreationTime)" -ForegroundColor White
    Write-Host "  SHA256: $($asefaHash.Hash)" -ForegroundColor White
    Write-Host "  Content Preview:" -ForegroundColor White
    Write-Host "  $($asefaContent.Substring(0, [Math]::Min(200, $asefaContent.Length)))..." -ForegroundColor Gray
} else {
    Write-Host "  [-] asefa.bat not found at expected location" -ForegroundColor Gray
}


# ============================================
# EXPORT RESULTS
# ============================================
Write-Host "`n[+] Exporting results..." -ForegroundColor Yellow


# Export all findings
$Findings | Export-Csv -Path "$OutputDir\All_Findings.csv" -NoTypeInformation
Write-Host "  [✓] All findings: $OutputDir\All_Findings.csv" -ForegroundColor Green


# Export by severity
$criticalFindings = $Findings | Where-Object {$_.Severity -like "*CRITICAL*"}
$highFindings = $Findings | Where-Object {$_.Severity -eq "HIGH"}
$moderateFindings = $Findings | Where-Object {$_.Severity -eq "MODERATE"}


if ($criticalFindings) {
    $criticalFindings | Export-Csv -Path "$OutputDir\CRITICAL_Findings.csv" -NoTypeInformation
    Write-Host "  [✓] Critical findings: $OutputDir\CRITICAL_Findings.csv" -ForegroundColor Red
}


if ($highFindings) {
    $highFindings | Export-Csv -Path "$OutputDir\HIGH_Findings.csv" -NoTypeInformation
    Write-Host "  [✓] High findings: $OutputDir\HIGH_Findings.csv" -ForegroundColor Yellow
}


# ============================================
# SUMMARY REPORT
# ============================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  THREAT HUNT SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""


$totalFindings = $Findings.Count
$criticalCount = ($Findings | Where-Object {$_.Severity -like "*CRITICAL*"}).Count
$highCount = ($Findings | Where-Object {$_.Severity -eq "HIGH"}).Count
$moderateCount = ($Findings | Where-Object {$_.Severity -eq "MODERATE"}).Count


Write-Host "Total Artifacts Found: $totalFindings" -ForegroundColor White
Write-Host "  CRITICAL: $criticalCount" -ForegroundColor Red
Write-Host "  HIGH: $highCount" -ForegroundColor Yellow
Write-Host "  MODERATE: $moderateCount" -ForegroundColor Gray
Write-Host ""


# Check for key artifacts
$foundAsefa = ($Findings | Where-Object {$_.Artifact -like "*asefa*"}).Count -gt 0
$foundFrontpage = ($Findings | Where-Object {$_.Artifact -like "*frontpage*"}).Count -gt 0
$foundDownloader = ($Findings | Where-Object {$_.Artifact -like "*image_downloader*"}).Count -gt 0
$foundDocm = ($Findings | Where-Object {$_.Artifact -like "*SecurityAdvisory*"}).Count -gt 0


Write-Host "Key Malicious Artifacts Status:" -ForegroundColor Cyan
Write-Host "  frontpage.jpg: $(if ($foundFrontpage) {'[✓] FOUND'} else {'[ ] NOT FOUND'})" -ForegroundColor $(if ($foundFrontpage) {'Red'} else {'Gray'})
Write-Host "  image_downloader.exe: $(if ($foundDownloader) {'[✓] FOUND'} else {'[ ] NOT FOUND'})" -ForegroundColor $(if ($foundDownloader) {'Red'} else {'Gray'})
Write-Host "  SecurityAdvisory.docm: $(if ($foundDocm) {'[✓] FOUND'} else {'[ ] NOT FOUND'})" -ForegroundColor $(if ($foundDocm) {'Red'} else {'Gray'})
Write-Host "  asefa.bat: $(if ($foundAsefa) {'[✓✓✓] FOUND (CRITICAL!)'} else {'[ ] NOT FOUND'})" -ForegroundColor $(if ($foundAsefa) {'Red'} else {'Gray'})
Write-Host ""


Write-Host "Results saved to: $OutputDir" -ForegroundColor Green
Write-Host ""

Write-Host ""








