# Key Findings

This section summarizes the main findings from the investigation. Every finding is based on correlated evidence from PowerShell logging, Sysmon, Windows Security events, and process relationships.

---

## Finding 1 – Encoded PowerShell Used as the Initial Execution Method

The attack started when `autoupdate.vbs` launched an encoded PowerShell process. The command downloaded `news.php` from `10.0.10.106:8080` and executed it directly in memory.

The PowerShell script also attempted to bypass AMSI, disable Script Block Logging, and ignore certificate validation. These actions reduced the amount of telemetry available during the rest of the attack.

**Evidence**

* PowerShell command line
* PowerShell logging
* Browser download artifact *(add record number if available)*

---

## Finding 2 – The Actor Performed Broad Host and Domain Discovery

After the payload executed, the attacker collected information about the compromised machine and the Active Directory environment.

The activity included:

* user and group enumeration,
* Domain Admin enumeration,
* local administrator enumeration,
* running services,
* network shares,
* clipboard contents,
* listening ports,
* and UAC configuration.

This indicates the actor was collecting enough information before moving to other systems.

**Evidence**

* PowerShell Module Logging
* Process creation events

---

## Finding 3 – SMB Was Used for Remote Access and File Staging

PowerShell Module Logging showed multiple password candidates before repeated SMB authentication attempts using `net use`.

The logs show successful access to remote shares on `HFDC01`, including `ADMIN$`, `C$`, and `IT`.

Later, Security Event ID 5145 and Sysmon Event ID 11 confirmed that `autoupdate.vbs` was written to the remote system.

I also observed `recipe.txt` being accessed through the `IT` share before it was later archived into `old.7z`.

**Evidence**

* Security Event ID 5145
* Sysmon Event ID 11
* PowerShell Module Logging

---

## Finding 4 – Windows Accessibility Binary Was Hijacked

One of the strongest findings in this investigation is the modification of `Magnify.exe`.

The attacker first took ownership of the binary and changed its permissions using `takeown.exe` and `icacls.exe`.

Later, Sysmon Event ID 11 showed PowerShell writing a file to the `Magnify.exe` path. Hash analysis identified the file as `cmd.exe`, while Sysmon reported the executable description as **Windows Command Processor**.

When `Utilman.exe` launched `Magnify.exe`, the process spawned `cmd.exe` followed by `whoami.exe` under `NT AUTHORITY\SYSTEM`.

Based on the available evidence, I assess with high confidence that the attacker replaced the original Magnifier executable to gain privileged command execution.

**Evidence**

* `takeown.exe`
* `icacls.exe`
* Sysmon Event ID 11
* Process tree
* Hash validation

---

## Finding 5 – Data Was Prepared Before Leaving the Host

Toward the end of the attack, the actor created several files including `ftp.txt`, `recipe.txt`, and `old.7z`.

The archive was created using `recycler.exe` inside `C:\$Recycle.Bin`.

The dataset also shows FTP command files being dropped. Although the dataset does not fully confirm successful exfiltration, the available evidence suggests the actor was preparing files for transfer.

**Evidence**

* Process creation events
* File creation events
* Archive creation command
