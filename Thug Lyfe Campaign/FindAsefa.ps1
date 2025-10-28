<#
.SYNOPSIS
    Hunt for asefa.bat evidence using Sysmon logs
   
.DESCRIPTION
    Searches Sysmon event logs for any evidence of asefa.bat:
    - File creation (Event ID 11)
    - Process execution (Event ID 1)
    - Network connections (Event ID 3)
    - Registry modifications (Event ID 13)
   
.NOTES
    Requires Sysmon to be installed and logging
#>


#Requires -RunAsAdministrator


Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Sysmon Hunt: asefa.bat" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""


# Check if Sysmon is installed
$SysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if (-not $SysmonService) {
    Write-Host "[✗] Sysmon service not found!" -ForegroundColor Red
    Write-Host "    Install Sysmon first: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon" -ForegroundColor Yellow
    exit
}


Write-Host "[✓] Sysmon service found: $($SysmonService.Name)" -ForegroundColor Green
Write-Host "[*] Status: $($SysmonService.Status)" -ForegroundColor Cyan
Write-Host ""


# Create output directory
$OutputDir = ".\Sysmon_asefa_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null


$AllFindings = @()


# ============================================
# EVENT ID 11: FILE CREATION
# ============================================
Write-Host "[+] Hunting Event ID 11 (File Creation)..." -ForegroundColor Yellow


try {
    $FileCreationEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        ID=11
    } -ErrorAction Stop | Where-Object {
        $_.Message -like "*asefa*" -or
        $_.Message -like "*ProgramData*" -and $_.Message -like "*.bat*"
    }
   
    if ($FileCreationEvents) {
        Write-Host "  [✓] Found $($FileCreationEvents.Count) file creation event(s)" -ForegroundColor Green
       
        foreach ($Event in $FileCreationEvents) {
            # Parse XML for detailed info
            $EventXML = [xml]$Event.ToXml()
            $EventData = $EventXML.Event.EventData.Data
           
            $FileCreation = [PSCustomObject]@{
                TimeCreated = $Event.TimeCreated
                EventID = 11
                EventType = "File Creation"
                ProcessId = ($EventData | Where-Object {$_.Name -eq 'ProcessId'}).'#text'
                Image = ($EventData | Where-Object {$_.Name -eq 'Image'}).'#text'
                TargetFilename = ($EventData | Where-Object {$_.Name -eq 'TargetFilename'}).'#text'
                CreationUtcTime = ($EventData | Where-Object {$_.Name -eq 'CreationUtcTime'}).'#text'
                User = ($EventData | Where-Object {$_.Name -eq 'User'}).'#text'
            }
           
            $AllFindings += $FileCreation
           
            Write-Host "`n  === File Creation Event ===" -ForegroundColor Cyan
            Write-Host "  Time: $($FileCreation.TimeCreated)" -ForegroundColor White
            Write-Host "  File: $($FileCreation.TargetFilename)" -ForegroundColor Yellow
            Write-Host "  Process: $($FileCreation.Image)" -ForegroundColor White
            Write-Host "  PID: $($FileCreation.ProcessId)" -ForegroundColor White
            Write-Host "  User: $($FileCreation.User)" -ForegroundColor White
           
            # If it's asefa.bat, try to read it now
            if ($FileCreation.TargetFilename -like "*asefa.bat*") {
                Write-Host "`n  [!] CRITICAL: asefa.bat was created!" -ForegroundColor Red
                Write-Host "  [*] Attempting to read file..." -ForegroundColor Cyan
               
                if (Test-Path $FileCreation.TargetFilename) {
                    $FileContent = Get-Content $FileCreation.TargetFilename -Raw
                    $FileHash = Get-FileHash $FileCreation.TargetFilename -Algorithm SHA256
                    $FileMD5 = Get-FileHash $FileCreation.TargetFilename -Algorithm MD5
                   
                    Write-Host "  [✓] FILE FOUND AND READABLE!" -ForegroundColor Green
                    Write-Host "  SHA256: $($FileHash.Hash)" -ForegroundColor Yellow
                    Write-Host "  MD5: $($FileMD5.Hash)" -ForegroundColor Yellow
                    Write-Host "`n  File Contents:" -ForegroundColor Cyan
                    Write-Host "  =================" -ForegroundColor Gray
                    Write-Host $FileContent -ForegroundColor White
                    Write-Host "  =================" -ForegroundColor Gray
                   
                    # Save to output
                    $FileContent | Out-File -FilePath "$OutputDir\asefa_bat_CONTENTS.txt"
                   
                    [PSCustomObject]@{
                        FileName = "asefa.bat"
                        Path = $FileCreation.TargetFilename
                        SHA256 = $FileHash.Hash
                        MD5 = $FileMD5.Hash
                        FileSize = (Get-Item $FileCreation.TargetFilename).Length
                    } | Export-Csv -Path "$OutputDir\asefa_bat_FILE_DETAILS.csv" -NoTypeInformation
                   
                } else {
                    Write-Host "  [✗] File no longer exists at: $($FileCreation.TargetFilename)" -ForegroundColor Red
                    Write-Host "  [*] File may have been deleted or is in alternate location" -ForegroundColor Yellow
                }
            }
        }
    } else {
        Write-Host "  [-] No file creation events found for asefa.bat" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [!] Error accessing Sysmon file creation events: $($_.Exception.Message)" -ForegroundColor Red
}


# ============================================
# EVENT ID 1: PROCESS CREATION
# ============================================
Write-Host "`n[+] Hunting Event ID 1 (Process Creation)..." -ForegroundColor Yellow


try {
    $ProcessCreationEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        ID=1
    } -ErrorAction Stop | Where-Object {
        $_.Message -like "*asefa*" -or
        ($_.Message -like "*cmd.exe*" -and $_.Message -like "*.bat*" -and $_.Message -like "*ProgramData*")
    }
   
    if ($ProcessCreationEvents) {
        Write-Host "  [✓] Found $($ProcessCreationEvents.Count) process creation event(s)" -ForegroundColor Green
       
        foreach ($Event in $ProcessCreationEvents) {
            $EventXML = [xml]$Event.ToXml()
            $EventData = $EventXML.Event.EventData.Data
           
            $ProcessCreation = [PSCustomObject]@{
                TimeCreated = $Event.TimeCreated
                EventID = 1
                EventType = "Process Creation"
                ProcessId = ($EventData | Where-Object {$_.Name -eq 'ProcessId'}).'#text'
                Image = ($EventData | Where-Object {$_.Name -eq 'Image'}).'#text'
                CommandLine = ($EventData | Where-Object {$_.Name -eq 'CommandLine'}).'#text'
                ParentImage = ($EventData | Where-Object {$_.Name -eq 'ParentImage'}).'#text'
                ParentCommandLine = ($EventData | Where-Object {$_.Name -eq 'ParentCommandLine'}).'#text'
                User = ($EventData | Where-Object {$_.Name -eq 'User'}).'#text'
                Hashes = ($EventData | Where-Object {$_.Name -eq 'Hashes'}).'#text'
            }
           
            $AllFindings += $ProcessCreation
           
            Write-Host "`n  === Process Execution Event ===" -ForegroundColor Cyan
            Write-Host "  Time: $($ProcessCreation.TimeCreated)" -ForegroundColor White
            Write-Host "  Process: $($ProcessCreation.Image)" -ForegroundColor White
            Write-Host "  Command: $($ProcessCreation.CommandLine)" -ForegroundColor Yellow
            Write-Host "  Parent: $($ProcessCreation.ParentImage)" -ForegroundColor White
            Write-Host "  Parent Command: $($ProcessCreation.ParentCommandLine)" -ForegroundColor Gray
            Write-Host "  User: $($ProcessCreation.User)" -ForegroundColor White
           
            if ($ProcessCreation.CommandLine -like "*asefa.bat*") {
                Write-Host "`n  [!] CRITICAL: asefa.bat was EXECUTED!" -ForegroundColor Red
                Write-Host "  [*] This batch file ran on the system!" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  [-] No process creation events found for asefa.bat" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [!] Error accessing Sysmon process creation events: $($_.Exception.Message)" -ForegroundColor Red
}


# ============================================
# EVENT ID 3: NETWORK CONNECTION
# ============================================
Write-Host "`n[+] Hunting Event ID 3 (Network Connections)..." -ForegroundColor Yellow


try {
    # Look for PowerShell making connection to 108.181.155.31 (asefa.bat download)
    $NetworkEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        ID=3
    } -ErrorAction Stop | Where-Object {
        $_.Message -like "*108.181.155.31*" -or
        $_.Message -like "*asefa*"
    }
   
    if ($NetworkEvents) {
        Write-Host "  [✓] Found $($NetworkEvents.Count) network connection event(s)" -ForegroundColor Green
       
        foreach ($Event in $NetworkEvents) {
            $EventXML = [xml]$Event.ToXml()
            $EventData = $EventXML.Event.EventData.Data
           
            $NetworkConnection = [PSCustomObject]@{
                TimeCreated = $Event.TimeCreated
                EventID = 3
                EventType = "Network Connection"
                ProcessId = ($EventData | Where-Object {$_.Name -eq 'ProcessId'}).'#text'
                Image = ($EventData | Where-Object {$_.Name -eq 'Image'}).'#text'
                Protocol = ($EventData | Where-Object {$_.Name -eq 'Protocol'}).'#text'
                SourceIp = ($EventData | Where-Object {$_.Name -eq 'SourceIp'}).'#text'
                SourcePort = ($EventData | Where-Object {$_.Name -eq 'SourcePort'}).'#text'
                DestinationIp = ($EventData | Where-Object {$_.Name -eq 'DestinationIp'}).'#text'
                DestinationPort = ($EventData | Where-Object {$_.Name -eq 'DestinationPort'}).'#text'
                User = ($EventData | Where-Object {$_.Name -eq 'User'}).'#text'
            }
           
            $AllFindings += $NetworkConnection
           
            Write-Host "`n  === Network Connection Event ===" -ForegroundColor Cyan
            Write-Host "  Time: $($NetworkConnection.TimeCreated)" -ForegroundColor White
            Write-Host "  Process: $($NetworkConnection.Image)" -ForegroundColor White
            Write-Host "  Connection: $($NetworkConnection.SourceIp):$($NetworkConnection.SourcePort) -> $($NetworkConnection.DestinationIp):$($NetworkConnection.DestinationPort)" -ForegroundColor Yellow
            Write-Host "  Protocol: $($NetworkConnection.Protocol)" -ForegroundColor White
            Write-Host "  User: $($NetworkConnection.User)" -ForegroundColor White
           
            if ($NetworkConnection.DestinationIp -eq "108.181.155.31") {
                Write-Host "`n  [!] CRITICAL: Connection to C2 server that hosts asefa.bat!" -ForegroundColor Red
                Write-Host "  [*] This is the PowerShell download attempt" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  [-] No network connection events found" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [!] Error accessing Sysmon network events: $($_.Exception.Message)" -ForegroundColor Red
}


# ============================================
# EVENT ID 13: REGISTRY MODIFICATION
# ============================================
Write-Host "`n[+] Hunting Event ID 13 (Registry Modifications)..." -ForegroundColor Yellow


try {
    $RegistryEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        ID=13
    } -MaxEvents 1000 -ErrorAction Stop | Where-Object {
        $_.Message -like "*asefa*"
    }
   
    if ($RegistryEvents) {
        Write-Host "  [✓] Found $($RegistryEvents.Count) registry modification event(s)" -ForegroundColor Green
       
        foreach ($Event in $RegistryEvents) {
            $EventXML = [xml]$Event.ToXml()
            $EventData = $EventXML.Event.EventData.Data
           
            $RegistryMod = [PSCustomObject]@{
                TimeCreated = $Event.TimeCreated
                EventID = 13
                EventType = "Registry Modification"
                ProcessId = ($EventData | Where-Object {$_.Name -eq 'ProcessId'}).'#text'
                Image = ($EventData | Where-Object {$_.Name -eq 'Image'}).'#text'
                TargetObject = ($EventData | Where-Object {$_.Name -eq 'TargetObject'}).'#text'
                Details = ($EventData | Where-Object {$_.Name -eq 'Details'}).'#text'
            }
           
            $AllFindings += $RegistryMod
           
            Write-Host "`n  === Registry Modification Event ===" -ForegroundColor Cyan
            Write-Host "  Time: $($RegistryMod.TimeCreated)" -ForegroundColor White
            Write-Host "  Process: $($RegistryMod.Image)" -ForegroundColor White
            Write-Host "  Registry Key: $($RegistryMod.TargetObject)" -ForegroundColor Yellow
            Write-Host "  Value: $($RegistryMod.Details)" -ForegroundColor White
        }
    } else {
        Write-Host "  [-] No registry modification events found for asefa" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [!] Error accessing Sysmon registry events: $($_.Exception.Message)" -ForegroundColor Red
}


# ============================================
# SEARCH ALL SYSMON EVENTS FOR "asefa"
# ============================================
Write-Host "`n[+] Performing comprehensive search of ALL Sysmon events..." -ForegroundColor Yellow


try {
    $AllSysmonEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
    } -MaxEvents 5000 -ErrorAction Stop | Where-Object {
        $_.Message -like "*asefa*"
    }
   
    if ($AllSysmonEvents) {
        Write-Host "  [✓] Found $($AllSysmonEvents.Count) total Sysmon event(s) mentioning 'asefa'" -ForegroundColor Green
       
        # Group by Event ID
        $EventGroups = $AllSysmonEvents | Group-Object Id
       
        Write-Host "`n  Event ID Breakdown:" -ForegroundColor Cyan
        foreach ($Group in $EventGroups) {
            $EventName = switch ($Group.Name) {
                1 { "Process Creation" }
                3 { "Network Connection" }
                11 { "File Creation" }
                13 { "Registry Modification" }
                default { "Event ID $($Group.Name)" }
            }
            Write-Host "    Event ID $($Group.Name) ($EventName): $($Group.Count) events" -ForegroundColor White
        }
    } else {
        Write-Host "  [-] No Sysmon events found mentioning 'asefa'" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [!] Error searching all Sysmon events: $($_.Exception.Message)" -ForegroundColor Red
}


# ============================================
# CHECK FILESYSTEM ONE MORE TIME
# ============================================
Write-Host "`n[+] Double-checking filesystem for asefa.bat..." -ForegroundColor Yellow


$PossibleLocations = @(
    "C:\ProgramData\asefa.bat",
    "C:\Windows\Temp\asefa.bat",
    "C:\Users\*\AppData\Local\Temp\asefa.bat",
    "C:\Users\*\Downloads\asefa.bat"
)


foreach ($Location in $PossibleLocations) {
    $Files = Get-ChildItem -Path $Location -ErrorAction SilentlyContinue
    if ($Files) {
        Write-Host "  [✓] FOUND: $($Files.FullName)" -ForegroundColor Green
       
        $FileContent = Get-Content $Files.FullName -Raw
        $FileHash = Get-FileHash $Files.FullName -Algorithm SHA256
       
        Write-Host "  SHA256: $($FileHash.Hash)" -ForegroundColor Yellow
        Write-Host "`n  File Contents:" -ForegroundColor Cyan
        Write-Host "  =================" -ForegroundColor Gray
        Write-Host $FileContent -ForegroundColor White
        Write-Host "  =================" -ForegroundColor Gray
    }
}


# Search entire C: drive as last resort
Write-Host "`n  [*] Performing deep search of C:\ drive..." -ForegroundColor Cyan
$DeepSearch = Get-ChildItem -Path C:\ -Recurse -Filter "asefa.bat" -ErrorAction SilentlyContinue


if ($DeepSearch) {
    Write-Host "  [✓] FOUND in deep search: $($DeepSearch.FullName)" -ForegroundColor Green
} else {
    Write-Host "  [-] asefa.bat not found on filesystem" -ForegroundColor Gray
}


# ============================================
# EXPORT ALL FINDINGS
# ============================================
Write-Host "`n[+] Exporting findings..." -ForegroundColor Yellow


if ($AllFindings.Count -gt 0) {
    $AllFindings | Export-Csv -Path "$OutputDir\All_Sysmon_Findings.csv" -NoTypeInformation
    Write-Host "  [✓] Exported $($AllFindings.Count) findings to: $OutputDir\All_Sysmon_Findings.csv" -ForegroundColor Green
   
    # Group by event type
    $AllFindings | Group-Object EventType | ForEach-Object {
        $_.Group | Export-Csv -Path "$OutputDir\Sysmon_$($_.Name -replace ' ','_').csv" -NoTypeInformation
    }
} else {
    Write-Host "  [-] No findings to export" -ForegroundColor Gray
}


# ============================================
# SUMMARY
# ============================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  SYSMON HUNT SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""


$FileCreationCount = ($AllFindings | Where-Object {$_.EventType -eq "File Creation"}).Count
$ProcessCount = ($AllFindings | Where-Object {$_.EventType -eq "Process Creation"}).Count
$NetworkCount = ($AllFindings | Where-Object {$_.EventType -eq "Network Connection"}).Count
$RegistryCount = ($AllFindings | Where-Object {$_.EventType -eq "Registry Modification"}).Count


Write-Host "Total Sysmon Events Found: $($AllFindings.Count)" -ForegroundColor White
Write-Host "  File Creation Events: $FileCreationCount" -ForegroundColor White
Write-Host "  Process Creation Events: $ProcessCount" -ForegroundColor White
Write-Host "  Network Connection Events: $NetworkCount" -ForegroundColor White
Write-Host "  Registry Modification Events: $RegistryCount" -ForegroundColor White
Write-Host ""


if ($AllFindings.Count -eq 0) {
    Write-Host "[!] NO EVIDENCE OF asefa.bat FOUND IN SYSMON LOGS" -ForegroundColor Red
    Write-Host ""
    Write-Host "Possible reasons:" -ForegroundColor Yellow
    Write-Host "  1. asefa.bat was never downloaded (network failure)" -ForegroundColor Gray
    Write-Host "  2. PowerShell command was blocked" -ForegroundColor Gray
    Write-Host "  3. Sysmon was not running during the attack" -ForegroundColor Gray
    Write-Host "  4. Sysmon logs were cleared" -ForegroundColor Gray
    Write-Host "  5. The simulator didn't complete the full attack chain" -ForegroundColor Gray
} else {
    Write-Host "[✓] EVIDENCE OF asefa.bat ACTIVITY FOUND!" -ForegroundColor Green
    Write-Host ""
}


Write-Host ""
Write-Host "Results saved to: $OutputDir" -ForegroundColor Cyan
Write-Host ""








