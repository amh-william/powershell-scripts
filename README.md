# powershell-scripts
Misc scripts written during the work day that may be useful for others

## Contents
- [NetServicesCheck.ps1](/NetServicesCheck.ps1)
  - Checks the local network connections (netstat) for listening and established IPv4 ports.  PIDs for the listening processes are resolved to full file paths if applicable. Foreign addresses are filtered using RegEx for rfc 1918 addresses, but can be removed by modifying the RegEx string.
