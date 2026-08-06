# Empire APT3 Investigation

This project is my investigation of a Windows intrusion dataset from the Empire APT3 set. I used it to practice the kind of work a SOC analyst does every day: following a timeline, correlating logs, and turning noisy telemetry into a clear story.

## What I looked at

The main focus was on:

* encoded PowerShell execution
* defense evasion and logging bypass attempts
* host and domain discovery
* SMB share activity and file staging
* accessibility binary hijacking through `Utilman.exe` and `Magnify.exe`
* privileged command execution under `SYSTEM`

## What is in this repo

* the investigation write-up
* a timeline of the attack
* MITRE ATT&CK mapping
* key indicators and evidence
* short notes on the methods used during analysis

## Tools and approach

I worked through the logs the same way I would in a real investigation:

* Wazuh
* PowerShell logging
* Sysmon
* Windows Security logs
* hash and process-tree correlation
* timeline reconstruction
* manual pivoting across events

## Main takeaway

The most important part of the case was the abuse of a Windows accessibility binary. After ownership and permissions were changed on `Magnify.exe`, the binary was replaced and later launched through `Utilman.exe`, which led to `cmd.exe` execution as `NT AUTHORITY\SYSTEM`.

## Why I built this

I wanted a project that shows more than tool usage. The goal was to practice real investigation thinking, and document the evidence clearly.
