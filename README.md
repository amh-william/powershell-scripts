# powershell-scripts
Misc scripts written during the work day that may be useful for others

## Contents
- [NetServicesCheck.ps1](/NetServicesCheck.ps1)
  - Checks the local network connections (netstat) for listening and established IPv4 ports.  PIDs for the listening processes are resolved to full file paths if applicable. Foreign addresses are filtered using RegEx for rfc 1918 addresses, but can be removed by modifying the RegEx string.
- [IvantiSolarWindsIntegration.ps1](/IvantiSolarWindsIntegration.ps1)
  - Creates an interface between Ivanti Security Controls patching and SolarWinds Orion monitoring.  The script requires an SQL instance to store the information for any upcoming patch windows that it processes, so they do not get processed multiple times.  The script reads the Ivanti tasks from Windows Task Scheduler and relies on the "Description" of the task to match the "Machine Group" in Ivanti.  The script will also poll vCenter for the IP Address and Hostname of VMs reported by the Machine Group.  After the IP is found by the script, the NodeID is retrieved from Orion's database and the Unmanage verb is used to set a scheduled Unamage window.  Requires modules: STProtect, VMware.VimAutomation.Vmc, SqlServer, SwisPowerShell
