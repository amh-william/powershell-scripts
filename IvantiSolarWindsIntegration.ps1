#Requires -Modules STProtect,VMware.VimAutomation.Vmc,SqlServer,SwisPowerShell
Import-Module STProtect, VMware.VimAutomation.Vmc, SqlServer, SwisPowerShell

<#
  .SYNOPSIS
  Checks for patch windows in Ivanti and updates maintenance windows in SolarWinds

  .DESCRIPTION
  This script checks for upcoming patch events prior to $LATER
  from Ivanti.  Ivanti schedules these tasks through the Windows Task Scheduler at the path
  "\Ivanti\Security Controls\Scans\".  The script check the database $SQL_DATABASE on $SQL_INSTANCE for
  windows that have already been set in SolarWinds.  If not, it will create an 'Unmanage' window for the
  NodeID of the server that is getting patched.  This window will start at the NextRunTime of the WIndows Task
  and will last for $PATCH_WINDOW_LENGTH minutes.  Every time the script runs, it will prune the database of tasks
  that have an end time that is before the run time of the script. (EndTime < [DateTime]::Now).  This script
  writes logs to the Windows Event Log in it's own log name $LOG_NAME.

  .INPUTS
  None.

  .OUTPUTS
  None.
#>



# # # # # # # # # # # # # # #
#                           #
#     STATIC VARIABLES      #
#                           #
# # # # # # # # # # # # # # #

# Maps the current "Description" property of the Windows Tasks created in Ivanti to the 
# Ivanti group that belongs to it.  Modify this to match the Description to the proper Ivanti
# machine group.
$IVANTI_TASK_MAP = @{
    "Example Description"   = "IvantiSCGroupName";
    "Example Description 2" = "IvantiSCGroupName2"
}

# The Windows Event Log log name for events related to this script
$LOG_NAME = "Patch Monitor"

# The path in Task Schedule that holds the scheduled patch jobs
$IVANTI_TASK_PATH = "\Ivanti\Security Controls\Scans\"

# Now at the start of the script
$NOW = [DateTime]::Now

# The time-frame checked for upcoming patches that need to be
# set in SolarWinds
$LATER = $NOW.AddHours(24)

# The duration in minutes of the SolarWinds Unmanage window
$PATCH_WINDOW_LENGTH = 45

# The SQL Instance that houses the database to keep track of processed
# patch windows
# ("servername" if default instance or "servername\instance" for a named instance)
$SQL_INSTANCE = "servername"

# The SQL Database within the SQL instance that holds the processed windows
$SQL_DATABASE = "PatchWindows"

# The column names within the SQL table
$SQL_COLUMNS = [PSCustomObject]@{NodeID = "nodeid"; IPAddress = "ipaddress"; Hostname = "hostname"; IvantiGroup = "grp"; StartDateTime = "startdt"; $EndDateTime = "enddt";}

# SQL Stored Procedure that selects all processed patch windows from the database 
$SQL_SELECT_ALL = "EXEC SelectAllWindows"

# SQL Stored Procedure that handles table INSERTs.  Expected parameter order:
# NodeID, IPAddress, Hostname, Group, Start, End
# The script will call "$SQL_INSERT_QUERY 'NodeID', 'IPAddress', 'Hostname', 'Group', 'Start', 'End'"
$SQL_INSERT_QUERY = "EXEC InsertWindows"

# SQL Stored Procedure that handles table DELETEs.  Expects a single argument:
# NodeID
# The script will call "$SQL_DELETE_QUERY 'NodeID'
$SQL_DELETE_QUERY = "EXEC DeleteNodeID"

# SQL Stored Procedure that handles table SELECT where the NodeID column equals the provided argument:
# NodeID
# The script will call "$SQL_CHECK_QUERY 'NodeID'
$SQL_CHECK_QUERY = "EXEC CheckWindow"



# # # # # # # # # # # # # # #
#                           #
#           CLASSES         #
#                           #
# # # # # # # # # # # # # # #

# This class is a template to hold all of the info that we need from the Scheduled Tasks in an
# easily identifiable way.
class IvantiTask {
    # The TaskName of the task from Windows Task Scheduler
    [string]    $Name
    # The Description of the task from Windows Task Scheduler
    [string]    $Description
    # The NextRunTime of the task from Windows Task Scheduler
    [DateTime]  $RunTime
    # The Ivanti MachineGroup that corresponds to the task Description
    [string]    $Group

    # This is the constructor for the class.  It initiates an IvantiTask
    # object with the values provided.  Properties are accessed by calling
    # $variableName.Property Example:
    # $task = [IvantiTask]::New("test task", "test description", "10/18/2022 11:00:00")
    #         ^Class Reference ^Constructor
    IvantiTask(
        [string] $i_name, 
        [string] $i_desc, 
        [DateTime] $i_date
    ) {
        $this.Name = $i_name
        $this.Description = $i_desc
        $this.RunTime = $i_date
    }

    [string] ToString() {
        return  "Name:`t$($this.Name)`n" + 
                "Description:`t$($this.Description)`n" +
                "RunTime:`t$($this.RunTime)`n" +
                "Group:`t$($this.Group)"
    }
}

# This class is a template to hold all of the info that is sent to SolarWinds and
# stored in SQL.
class PatchWindow {
    # The NodeID from SolarWinds
    [string]    $NodeID
    # The IP Address from vCenter or DNS
    [string]    $IPAddress
    # The hostname from vCenter or Ivanti
    [string]    $Hostname
    # The Ivanti Group from a related IvantiTask object
    [string]    $IvantiGroup
    # The NextRunTime from a related IvantiTask object
    [DateTime]  $StartTime
    # A time later than the NextRunTime
    [DateTime]  $EndTime
    
    PatchWindow(
        [string] $NodeID, 
        [string] $IPAddress, 
        [string] $Hostname, 
        [string] $IvantiGroup, 
        [DateTime] $StartTime, 
        [DateTime] $EndTime
    ) {

        $this.NodeID = $NodeID
        $this.IPAddress = $IPAddress
        $this.Hostname = $Hostname
        $this.IvantiGroup = $IvantiGroup
        $this.StartTime = $StartTime
        $this.EndTime = $EndTime
    }

    [string] ToString() {
        return  "NodeID:`t$($this.NodeID)`n" + 
                "IPAddress:`t$($this.IPAddress)`n" +
                "Hostname:`t$($this.Hostname)`n" +
                "IvantiGroup:`t$($this.IvantiGroup)`n" +
                "StartTime:`t$($this.StartTime)`n" +
                "EndTime:`t$($this.EndTime)"
    }
}



# # # # # # # # # # # # # # #
#                           #
#        FUNCTIONS          #
#                           #
# # # # # # # # # # # # # # #

# This function writes messages to a custom Event Log.  The default entry type is "Information"
# The Log Name in Event Log can be changed by changing the $LOG_NAME global variable at the 
# top of the script.
function Write-Event {
    param (
        # Message to write to Event Log
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Message,
        # Event source of the Message
        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $Source,
        # Type of Message (Information*, Warning, Error) *Default
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet("Information", "Warning", "Error", IgnoreCase = $true)]
        [string]
        $LogType = "Information"
    )
    
    # If the Log Name or Event Source do not exist in the Event Log
    if ( (-Not [System.Diagnostics.EventLog]::Exists($LOG_NAME)) -OR (-Not [System.Diagnostics.EventLog]::SourceExists($Source)) ) {
        # Create a new Event Log source/log name
        New-EventLog -Source $Source -LogName $LOG_NAME
    }
    # Write the message to the Event log with the specified Source and script-wide Log Name.
    Write-EventLog -Message $Message -EntryType $LogType -Source $Source -LogName $LOG_NAME -EventId 1
}

# This function pulls all of the Scheduled Tasks by Ivanti that are set to run before $LATER
function Get-IvantiTasks {
    param ()
    # Get all Ivanti Scan tasks from Tash Scheduler that have a NextRunTime that is before $LATER
    $tasks = Get-ScheduledTask -TaskPath $IVANTI_TASK_PATH | Get-ScheduledTaskInfo |`
        Where-Object { $_.NextRunTime -GT $NOW -AND $_.NextRunTime -LT $LATER } | Select-Object -Property TaskName | Get-ScheduledTask
    # Initialize an array that will hold the corresponding IvantiTask objects created from the Windows ScheduledTask objects
    $results = @()
    # Do the following for each task that was returned
    foreach ($task in $tasks) {
        # Create a new IvantiTask with the info from the scheduled task
        $i_task = [IvantiTask]::New($task.TaskName, $task.Description, ($task | Get-ScheduledTaskInfo).NextRunTime)
        # Add the Ivanti group that corresponds to the description of the Scheduled Task.
        $i_task.Group = $IVANTI_TASK_MAP[$task.Description]
        # Add the new IvantiTask object to the results array
        $results += $i_task
    }
    # Return the results
    return $results
}

# This function pulls all of the machines that are a member of the specified Ivanti MachineGroup
# If the machine is a VM, it will have the "Name" in the format "VM-Name: vcenter.server.name"
# Both of these are processed by replacing the space (' ') with nothing ('') and then splitting the string on
# the "delimiter" (':' in this case).  If the string does not have a colon, it will still return an array
# that looks like: ['hostname', $null] that we can test on later
function Get-IvantiMembers {
    param (
        # The Ivanti group from which to retrieve members
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Group
    )

    # Initialize a dictionary to hold the {Machine Name = vCenter Name} pairs
    # the value of 'vCenter Name' is $null if the machine is not a vm entry in Ivanti
    $members = @{}
    # Get-MachineGroup is an function from the Ivanti "STProtect" powershell module
    # It gets the info for the group.  The "filter" is the list of machines that are in the group
    Get-MachineGroup -Name $Group | Select-Object -ExpandProperty Filters | Select-Object -ExpandProperty Name | ForEach-Object {
        $members[$_.Replace(' ', '').Split(':')[0]] = $_.Replace(' ', '').Split(':')[1]
    } | Out-Null # make sure no output from this command is returned
    # Return the dictionary
    return $members
}

# This function utilizes the Stored Procedure on the PatchWindows DB to select all rows in the table 
# and converts each row into a PatchWindow object that we can use to check against later
function Get-ExistingSQLWindows {
    param ()

    # Initialize an array to hold the PatchWindow objects that are stored in SQL
    $windows = @()
    # Get the DataTable containing all of the rows in the PatchWindows table
    $data = Get-SQLWindows
    # Create a PatchWindow for each row in the PatchWindows table and add it to the array
    ForEach ($row in $data.Rows) {
        # Create a new PatchWindow object and add it to the array of PatchWindows
        $windows += [PatchWindow]::New($row."$($SQL_COLUMNS.NodeID)", $row."$($SQL_COLUMNS.IPAddress)", $row."$($SQL_COLUMNS.IPAddress)", $row."$($SQL_COLUMNS.IvantiGroup)", $row."$($SQL_COLUMNS.StartDateTime)", $row."$($SQL_COLUMNS.EndDateTime)")
    }
    # Return the array
    return $windows
}

# This function utilizes the Stored Procedure "DeleteNodeID" to remove the row in TblWindows
# that matches the NodeID specified.
function Remove-SQLWindow {
    param (
        # The PatchWindow to remove from SQL
        [Parameter(Mandatory = $true, Position = 0)]
        [PatchWindow]
        $Window
    )

    # Build the query by adding the NodeID of the PatchWindow to the Stored Procedure call
    $query = "$SQL_DELETE_QUERY '$($Window.NodeID)'"
    # Write an informational message to Event Logs that a SQL entry for this NodeID is being removed.  Includes the query that is being run
    Write-Event -Message "Running DELETE query for $($w.NodeID) from $($w.StartTime) to $($w.EndTime) `n$($query)" -Source "IvantiPatchWindows-Prune"
    # Send the SQL query to the DB
    Invoke-Sqlcmd -Query $query -ServerInstance $SQL_INSTANCE -Database $SQL_DATABASE
}

# This function gets the primary IP Address reported by VMware Tools for the specified VM
function Get-VmIPByName {
    param (
        # Name of the VM to find
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $VMName
    )
    # Get the VM by VM Name
    $vm = Get-VM -Name $VMName
    # Return the first IP Address reported by VMWare Tools
    return $vm.Guest.IPAddress[0]
}

# This function returns the FQDN reported by VMware tools for the specified VM
function Get-VMHostnameByName {
    param (
        # Name of the VM to find
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $VMName
    )
    
    # Get the VM by VM Name
    $vm = Get-VM -Name $VMName
    # Return the HostName reported by VMWare Tools
    return $vm.Guest.HostName
}

# This function uses the Swis PowerShell Module to ge the NodeID of a specified IP Address
# Returns $null if the IP Address is not found
function Get-NodeIDByIP {
    param (
        # IP Address of the Node
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $IPAddress
    )

    # Connect to SolarWinds with passthrough User Context credentials
    $Swis = Connect-Swis -Trusted -Hostname "solarwindsapp"
    # Build the Query with the provided IP Address
    $query = "SELECT NodeID FROM Orion.Nodes WHERE IPAddress LIKE '$($IPAddress)' OR IP_Address LIKE '$($IPAddress)'"
    # Return the NodeID as a string
    return [string](Get-SwisData $Swis $query)
}

# This function checks if the NodeID is already scheduled for a patch window by checking
# the SQL server for an entry with the specified NodeID
function Invoke-WindowCheck {
    param (
        # Window to check
        [Parameter(Mandatory = $true)]
        [PatchWindow]
        $Window
    )

    $query = "$SQL_CHECK_QUERY '$($Window.NodeID)'"
    # Get all of the existing PatchWindows in SQL
    $windows = Invoke-Sqlcmd -Query $query -ServerInstance $SQL_INSTANCE -Database $SQL_DATABASE -As DataTable
    # Check all of the PatchWindows to see if the provided PatchWindow is for the same NodeID
    if ($windows.Rows.Count -gt 0) {
        Write-Event -Message "Window exists for NodeID $($Window.NodeID) from $($Window.StartTime) to $($Window.EndTime)" -Source "IvantiPatchWindows-WindowCheck"
        # A patch window for this Node already exists
        return $false
    }
    # No patch window for this Node was found
    return $true
    
}

# This function check all of the entries in the table and removes any that
# have an EndTime that has already passed (is less than $NOW)
function Invoke-WindowPrune {
    param ()
    
    # Get all of the existing PatchWindows in SQL
    $windows = Get-ExistingSQLWindows
    # Check if the EndTime for each PatchWindow is before now
    foreach ($w in $windows) {
        # If the EndTime has elapsed (is less than now)
        if ($w.EndTime -lt $NOW) {
            # Log that we are removing the window from SQL
            Write-Event -Message "Pruning patch window for $($w.NodeID) from $($w.StartTime) to $($w.EndTime)" -Source "IvantiPatchWindows-Prune"
            # If the EndTime is before now, it has already ended and needs to be removed from SQL
            Remove-SQLWindow $w
        }
    }
}

# This function utilizes the Stored Procedure to insert a new PatchWindow into
# the SQL database if it does not already exist. If the NodeID of the PatchWindow is blank, then
# it does not need a window and is skipped.  If the NodeID is populated and the PatchWindow is not
# already in the table, then the PatchWindow is added to SQL and the NodeID has an unmanage window
# scheduled in SolarWinds.
function Add-Window {
    param (
        # Window object to add
        [Parameter(Mandatory = $true, Position = 0)]
        [PatchWindow]
        $Window
    )

    # Make sure the PatchWindow doesn't already exist
    if (Invoke-WindowCheck -Window $Window) {
        # Make sure that the server is being monitored by SolarWinds
        if ($Window.NodeID -eq "") {
            # Log that the server is not monitored
            Write-Event -Message "Device $($Window.Hostname) at IP Address $($Window.IPAddress) is not managed by SolarWinds.`n$($Window)" -Source "IvantiPatchWindows-AddWindow" -LogType Warning
        }
        # If the NodeID exists, add the PatchWindow to SQL
        else {
            # Build the arguments for the Stored Procedure
            $parameters = "'$($Window.NodeID)', '$($Window.IPAddress)', '$($Window.Hostname)', '$($Window.IvantiGroup)', '$($Window.StartTime.ToString())', '$($Window.EndTime.ToString())'"
            # Build the query with the Stored Procedure and its arguments
            $query = "$SQL_INSERT_QUERY $parameters"
            # Log the query that is being run
            Write-Event -Message "Adding patch window for $($Window.NodeID) from $($Window.StartTime) to $($Window.EndTime) `n$($query))" -Source "IvantiPatchWindows-AddWindow"
            # Send the query to the server
            Invoke-Sqlcmd -Query $query -ServerInstance $SQL_INSTANCE -Database $SQL_DATABASE

            # Add the PatchWindow to SolarWinds
            Add-SWWindow -Window $Window
        }
    }
}

# This function utilizes the Swis PowerShell module (SolarWinds SDK) to set a future
# "Unmanage" window for a Node using its NodeID and the "Unmanage" command.
function Add-SWWindow {
    param (
        # Window to add to SolarWinds
        [Parameter(Mandatory = $true, Position = 0)]
        [PatchWindow]
        $Window
    )

    # Send a request to unmanage the NodeID for the specified PatchWindow from the StartTime to the EndTime.
    # "false" here tells the "Unmanage" verb that the "EndTime" is not a delta
    # (If EndTime was a delta, it would be a value that is added to StartTime instead of the specific time that the window should end)
    $result = Invoke-SwisVerb $Swis Orion.Nodes Unmanage @($Window.NodeID, $Window.StartTime, $Window.EndTime, "false")
    # Record the results of the Unmanage request to the event log
    Write-Event -Source "IvantiPatchWindows-AddSWWindow" -Message "Added Unmanage window for $($Window.NodeID) from $($Window.StartTime) to $($Window.EndTime)`n$($result)"
}

# This function utilizes a Stored Procedure to get all rows from the table
function Get-SQLWindows {
    param ()

    # Return the entirety of the SQL table "tblWindows" as a DataTable
    return Invoke-Sqlcmd -Query $SQL_SELECT_ALL -ServerInstance $SQL_INSTANCE -Database $SQL_DATABASE -As DataTable
    
}

# This function contains the main execution block for this script.
# It will prune the SQL database, check for upcoming scheduled patch windows,
# and add the upcoming windows to SQL and SolarWinds.  All steps are logged in
# Event Log > Applications and Services Logs > Patch Monitor
function Invoke-IvantiPatchWindows {

    # Prune existing windows to start
    Invoke-WindowPrune

    # Get all tasks
    $tasks = Get-IvantiTasks

    # Check if there are any tasks to process
    if ($null -eq $tasks) {
        # Write information to the event logs that we took no actions
        Write-Event -Message "No pending tasks." -Source "IvantiPatchWindows-Main"
        # Exit if none
        exit 0
    }

    # Iterate over all tasks
    foreach ($task in $tasks) {
        # Get the members of the task group
        $members = Get-IvantiMembers $task.Group

        # Iterate over each member of the group
        foreach ($member in $members.Keys) {
            # Check if the member is a VM entry or not

            if (-NOT $null -eq $members[$member]) {

                # Use the credential to log in to vCenter
                $vcenter = Connect-VIServer -Server $members[$member] -Force

                # Get the Hostname and IP Address from vCenter if the member is a VM
                # Create the PatchWindow
                $ip = Get-VmIPByName -VMName $member 

                # If the IP is not reported by vCenter, write a warning to the logs - probably an issue with VMware Tools
                if ($ip -eq "") {
                    Write-Event -Message "VM $($member) in Ivanti group $($task.Group) does not return an IP Address`n$((Get-VM -Name $member).Guest.IPAddress)"`
                        -Source "IvantiPatchWindows-Main" -LogType Warning
                }

                $hostname = Get-VMHostnameByName -VMName $member

                # Build the PatchWindow object using the info that was gathered by the functions
                $window = [PatchWindow]::New((Get-NodeIDByIP -IPAddress $ip), $ip, $hostname, $task.Group, $task.RunTime, $task.RunTime.AddMinutes($PATCH_WINDOW_LENGTH))

                Disconnect-VIServer -Server $vcenter -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            }

            # If the member is not a VM
            else {
                # Resolve the hostname to an IP and create the PatchWindow
                $ip = [System.Net.Dns]::GetHostAddresses("$member")[0].ToString()

                # Build the PatchWindow object using the info that was gathered by the functions
                $window = [PatchWindow]::New((Get-NodeIDByIP -IPAddress $ip), $ip, $member, $task.Group, $task.RunTime, $task.RunTime.AddMinutes($PATCH_WINDOW_LENGTH))
            }

            # Add the PatchWindow to SQL and SolarWinds
            Add-Window -Window $window
        }
    }
}



# # # # # # # # # # # # # # #
#                           #
#       MAIN EXECUTION      #
#                           #
# # # # # # # # # # # # # # #

Invoke-IvantiPatchWindows
exit 0
