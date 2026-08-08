# Investigation Report

## Executive Summary

This report documents my investigation of a Windows intrusion from the Empire APT3 dataset. The goal was to reconstruct the attack from the available logs and practice the kind of analysis expected in a SOC role.

The activity started with encoded PowerShell execution and moved through several stages, including defense evasion, host and domain discovery, SMB share access, file staging, and privilege escalation through accessibility binary hijacking. The most important finding was the abuse of Windows accessibility binaries, where `Magnify.exe` was modified and later launched through `Utilman.exe`, resulting in `cmd.exe` execution under `NT AUTHORITY\SYSTEM`.

I used PowerShell logging, Sysmon, Windows Security logs, hash analysis, and process correlation to build the timeline and validate the attack chain. The report focuses on the observed evidence, the attacker’s actions, and the techniques used at each stage.

## Investigation Scope

This investigation focused on reconstructing the attack path inside the Empire APT3 dataset and validating each stage using the available telemetry. The main objective was to understand what the actor did, how the activity progressed across hosts, and which logs best supported each conclusion.

The analysis was based on PowerShell logging, Sysmon telemetry, Windows Security events, and hash validation where available. I used these sources to correlate execution, discovery, SMB share activity, file staging, and privilege escalation behavior across the timeline.

The investigation centered on two hosts in particular: `HR001`, where the early PowerShell activity and SMB movement began, and `HFDC01`, where the later file share access and accessibility binary hijacking took place. I treated the dataset as a single attack chain, but I separated the findings by phase so the report would be easier to follow.

Where the logs were incomplete or logging had been reduced by the actor, I relied on the strongest available evidence and kept the conclusions conservative.

## Attack Timeline

This timeline follows the attack by linking PowerShell, Sysmon, and Windows Security logs. It starts with the initial script execution and then traces how the activity moved into discovery, SMB access, file staging, and finally privilege escalation.

### Phase 1 – Initial Execution

The earliest suspicious action was the execution of `C:\Users\nmartha\Downloads\autoupdate.vbs`, which launched encoded PowerShell and pulled content from `10.0.10.106:8080/news.php` for in-memory execution.

The PowerShell script also attempted to reduce visibility by bypassing AMSI, Disabling Script Block Logging, and bypassing certificate validation.

<img width="1850" height="891" alt="empire-initial-execution" src="https://github.com/user-attachments/assets/2202b08e-d9db-47d8-b091-457ada4ba7e5" /> <img width="453" height="129" alt="decode-ip" src="https://github.com/user-attachments/assets/a98a373d-374b-4627-8aa2-b9e9b7be2539" />
<img width="921" height="486" alt="empire-intial-decoded-execution" src="https://github.com/user-attachments/assets/c7397493-bc55-4dc5-bf2d-cf2b73183d9e" />


### Phase 2 – Host and Domain Discovery

After that, the attacker used PowerShell to enumerate the host and the Active Directory environment.

The activity included:

* user and group enumeration,
* Domain Admin enumeration,
* local administrator enumeration,
* domain computer enumeration,
* running services,
* network shares,
* clipboard contents,
* listening ports,
* and UAC configuration checks.

Several additional PowerShell payloads were downloaded and executed in memory during this phase, including:

* `update.ps1`
* `process.php`
* `get.php`

### Phase 3 – SMB Authentication and Lateral Movement

PowerShell Module Logging showed multiple password candidates being processed before repeated SMB authentication attempts using `net use`.

The attacker attempted access against multiple hosts, including:

* `IT001`
* `ACCT001`
* `HFDC01`

On `HFDC01`, the available evidence shows access to administrative and custom SMB shares, including:

* `ADMIN$`
* `C$`
* `IT`

Security Event ID 5145 confirmed access requests against multiple files over SMB, including `recipe.txt` under `C:\IT`.

Later events showed write access through the administrative share to:

* `C:\Users\pgustavo\AppData\Roaming\Adobe\Flash Player\autoupdate.vbs`

Sysmon Event ID 11 subsequently confirmed creation of that file on the target system.

### Phase 4 – Remote Execution and Persistence

After staging the payload, the attacker executed:

```text
cmd.exe /c autoupdate.vbs
```

Additional activity showed the creation of a Windows service named `AdobeUpdater` configured to execute the staged VBS script automatically.

This indicates the attacker established persistence while maintaining remote execution capability.

### Phase 5 – Accessibility Binary Hijacking

The investigation identified activity targeting the Windows Accessibility application `Magnify.exe`.

The attacker first executed:

```text
takeown.exe /F C:\Windows\System32\Magnify.exe
```

followed by:

```text
icacls.exe C:\Windows\System32\Magnify.exe /grant SYSTEM:F
```

These commands allowed modification of the protected system binary.

Sysmon Event ID 11 later showed PowerShell writing a file to the `Magnify.exe` path.

Hash analysis identified the resulting executable as `cmd.exe`, while Sysmon metadata reported the executable description as `Windows Command Processor`.

Later in the timeline:

```text
Utilman.exe
  ↓
Magnify.exe
  ↓
cmd.exe
  ↓
whoami.exe
```

executed under `NT AUTHORITY\SYSTEM`.

This behavior is consistent with abuse of the Windows Accessibility execution chain to obtain privileged command execution.

### Phase 6 – File Collection

Toward the end of the intrusion, the attacker created several additional artifacts, including:

* `recipe.txt`
* `old.7z`
* `ftp.txt`
* `recycler.exe`

The suspicious `recycler.exe` process archived `recipe.txt` into:

```text
C:\$Recycle.Bin\old.7z
```

The presence of archive creation, FTP command files, and staging inside `$Recycle.Bin` suggests the actor was preparing collected data for transfer or later retrieval.

## Key Findings

### Finding 1 – Encoded PowerShell Used as the Initial Execution Method

The attack started when `autoupdate.vbs` launched an encoded PowerShell process. The command downloaded `news.php` from `10.0.10.106:8080` and executed it directly in memory.

The PowerShell script also attempted to bypass AMSI, disable Script Block Logging, and ignore certificate validation. These actions reduced the amount of telemetry available during the rest of the attack.

### Finding 2 – The Actor Performed Broad Host and Domain Discovery

After the payload executed, the attacker collected information about both the local host and the Active Directory environment.

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

### Finding 3 – SMB Was Used for Remote Access and File Staging

PowerShell Module Logging showed multiple password candidates before repeated SMB authentication attempts using `net use`.

The logs show access to remote shares on `HFDC01`, including `ADMIN$`, `C$`, and `IT`.

Later, Security Event ID 5145 and Sysmon Event ID 11 confirmed that `autoupdate.vbs` was written to the remote system.

I also observed `recipe.txt` being accessed through the `IT` share before it was later archived into `old.7z`.

### Finding 4 – Windows Accessibility Binary Was Hijacked

One of the strongest findings in this investigation is the modification of `Magnify.exe`.

The attacker first took ownership of the binary and changed its permissions using `takeown.exe` and `icacls.exe`.

Later, Sysmon Event ID 11 showed PowerShell writing a file to the `Magnify.exe` path. Hash analysis identified the file as `cmd.exe`, while Sysmon reported the executable description as **Windows Command Processor**.

When `Utilman.exe` launched `Magnify.exe`, the process spawned `cmd.exe` followed by `whoami.exe` under `NT AUTHORITY\SYSTEM`.

Based on the available evidence, I assess with high confidence that the attacker replaced the original Magnifier executable to gain privileged command execution.

### Finding 5 – Data Was Prepared Before Leaving the Host

Toward the end of the attack, the actor created several files including `ftp.txt`, `recipe.txt`, and `old.7z`.

The archive was created using `recycler.exe` inside `C:\$Recycle.Bin`.

The dataset also shows FTP command files being dropped. Although the dataset does not fully confirm successful exfiltration, the available evidence suggests the actor was preparing files for transfer.

## MITRE ATT&CK Mapping

| ATT&CK Technique                            | ID        | Evidence                                           |
| ------------------------------------------- | --------- | -------------------------------------------------- |
| PowerShell                                  | T1059.001 | Encoded PowerShell execution                       |
| Visual Basic                                | T1059.005 | `autoupdate.vbs` execution                         |
| Ingress Tool Transfer                       | T1105     | `news.php`, `update.ps1`, `process.php`, `get.php` |
| System Information Discovery                | T1082     | Host discovery commands                            |
| Account Discovery                           | T1087     | User and group enumeration                         |
| Network Share Discovery                     | T1135     | SMB share enumeration                              |
| Clipboard Data                              | T1115     | Clipboard collection                               |
| SMB/Windows Admin Shares                    | T1021.002 | `ADMIN$`, `C$`, `IT` access                        |
| File and Directory Permissions Modification | T1222     | `takeown.exe`, `icacls.exe`                        |
| Accessibility Features                      | T1546.008 | `Utilman.exe` / `Magnify.exe`                      |
| System Binary Proxy Execution               | T1218     | Trusted Windows binary abuse                       |

## Indicators of Compromise

### IP Addresses

* `10.0.10.106:8080` — PowerShell payload hosting server

### Downloaded Resources

* `news.php`
* `update.ps1`
* `process.php`
* `get.php`

### Files

* `autoupdate.vbs`
* `ftp.txt`
* `recipe.txt`
* `old.7z`
* `Magnify.exe` *(modified)*
* `recycler.exe`

### Services

* `AdobeUpdater`

### Commands

* `takeown.exe`
* `icacls.exe`
* `net use`
* `whoami`
* `sc.exe`

### SMB Shares

* `ADMIN$`
* `C$`
* `IT`

## Conclusion and Recommendations

This investigation shows a complete post-compromise attack chain. The attacker used PowerShell for execution, reduced PowerShell visibility, collected information about the environment, moved through SMB shares, staged files, and finally gained SYSTEM-level command execution by abusing a Windows accessibility binary.

The strongest conclusion from this investigation is the replacement of `Magnify.exe`, supported by file creation events, process relationships, and hash validation. This allowed `Utilman.exe` to execute a command shell instead of the legitimate Magnifier application.

### Recommendations

* Monitor encoded PowerShell execution.
* Alert on AMSI and Script Block Logging bypass attempts.
* Monitor `takeown.exe` and `icacls.exe` targeting Windows system binaries.
* Investigate `Utilman.exe`, `Magnify.exe`, `sethc.exe`, and `osk.exe` spawning `cmd.exe` or PowerShell.
* Monitor write operations to `ADMIN$` and `C$`.
* Validate hashes of protected Windows binaries after suspicious permission changes.

## Lessons Learned

The biggest lesson from this case is that one log source is never enough. Reconstructing the attack required correlating PowerShell logging, Sysmon, Windows Security events, SMB activity, and hash analysis. Looking at these sources together made it possible to understand the attack as one connected workflow instead of isolated events.
