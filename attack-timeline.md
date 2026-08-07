# Attack Timeline

This timeline reconstructs the attack by correlating PowerShell logging, Sysmon telemetry, Windows Security events, and supporting evidence.
the timeline follows the attacker's actions from the initial execution through privilege escalation.

## Phase 1 – Initial Execution

The intrusion began when the user executed:

```text
C:\Users\nmartha\Downloads\autoupdate.vbs
```

The script spawned an encoded PowerShell process that downloaded a payload from `10.0.10.106:8080/news.php` and executed it directly in memory.

PowerShell logging also showed attempts to weaken visibility by:

* bypassing AMSI,
* disabling Script Block Logging,
* disabling Script Block Invocation Logging,
* and bypassing certificate validation.

## Phase 2 – Host and Domain Discovery

After execution, the attacker used PowerShell to enumerate the host and the Active Directory environment.

Observed discovery activity included:

* user enumeration,
* domain group enumeration,
* local administrator enumeration,
* domain computer enumeration,
* running service discovery,
* process discovery,
* network share discovery,
* network connection enumeration,
* listening port discovery,
* clipboard collection,
* and UAC checks.

Several additional PowerShell payloads were downloaded and executed in memory during this phase, including:

* `update.ps1`
* `process.php`
* `get.php`

## Phase 3 – SMB Authentication and Lateral Movement

PowerShell Module Logging showed multiple password candidates being processed before repeated SMB authentication attempts using `net use`.

The attacker attempted access against multiple hosts, including:

* `IT001`
* `ACCT001`
* `HFDC01`

On `HFDC01`, the available evidence shows successful access to administrative and custom SMB shares, including:

* `ADMIN$`
* `C$`
* `IT`

Security Event ID 5145 confirmed access requests against multiple files over SMB, including `recipe.txt` under `C:\IT`.

Later events showed write access through the administrative share to:

* `C:\Users\pgustavo\AppData\Roaming\Adobe\Flash Player\autoupdate.vbs`

Sysmon Event ID 11 subsequently confirmed creation of that file on the target system.

## Phase 4 – Remote Execution and Persistence

After staging the payload, the attacker executed:

```text
cmd.exe /c autoupdate.vbs
```

Additional activity showed the creation of a Windows service named `AdobeUpdater` configured to execute the staged VBS script automatically.

This indicates the attacker established persistence while maintaining remote execution capability.

## Phase 5 – Accessibility Binary Hijacking

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

## Phase 6 – File Collection

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
