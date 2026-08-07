# MITRE ATT&CK Mapping

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
| Accessibility Features                      | T1546.008 | `Utilman.exe` → `Magnify.exe`                      |
| System Binary Proxy Execution               | T1218     | Trusted Windows binary abuse                       |
