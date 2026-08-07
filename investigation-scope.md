This investigation focused on reconstructing the attack path inside the Empire APT3 dataset and validating each stage using the available telemetry.
The main objective was to understand what the actor did, how the activity progressed across hosts, and which logs best supported each conclusion.

The analysis was based on PowerShell logging, Sysmon telemetry, Windows Security events, and hash validation where available.
I used these sources to correlate execution, discovery, SMB share activity, file staging, and privilege escalation behavior across the timeline.

The investigation centered on two hosts in particular: 
HR001, where the early PowerShell activity and SMB movement began, 
and HFDC01, where the later file share access and accessibility binary hijacking took place.
I treated the dataset as a single attack chain, but I separated the findings by phase so the report would be easier to follow.

Where the logs were incomplete or logging had been reduced by the actor, I relied on the strongest available evidence and kept the conclusions conservative.
