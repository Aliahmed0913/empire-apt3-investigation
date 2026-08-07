This report documents my investigation of a Windows intrusion from the Empire APT3 dataset. 
The goal was to reconstruct the attack from the available logs and practice the kind of analysis expected in a SOC role.

The activity began with encoded PowerShell execution and moved through several stages, including defense evasion, host and domain discovery, SMB share access, file staging, 
and privilege escalation. The most important finding was the abuse of Windows accessibility binaries, where Magnify.exe was modified and later launched through Utilman.exe, 
resulting in cmd.exe execution under NT AUTHORITY\SYSTEM.

I used a mix of PowerShell logging, Sysmon, Windows Security logs, hash analysis, and process correlation to build the timeline and validate the attack chain.
The report focuses on the observed evidence, the attacker’s actions, and the techniques used at each stage.
