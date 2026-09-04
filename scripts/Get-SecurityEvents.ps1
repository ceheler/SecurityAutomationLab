<#
.SYNOPSIS
    This script is used to pull event logs from your computer, process them, and output a standardized json file with the relevant fields of those events.
.DESCRIPTION
    The script takes in WinEvents, filters them retaining only those based on the supplied parameters or defaults, and places relevant data into a standard format.
.PARAMETER Path
    The path your exported json file will export to. Defaults to user's Downloads folder with file name powershell_security_events.json.
.PARAMETER MaxEvents
    The maximum events to be output. Defaults to 100. Range allows 1 - 5000 events.
.PARAMETER EventIds
    The Event IDs to be processed by the script.
.EXAMPLE
    .\Get-SecurityEvents.ps1 -Path "C:\Users\jdoe\Downloads\output.json" -MaxEvents 50 -EventIds 4624, 4720
    Runs the script and processes 50 events containing events 4624 and 4720. Outputs C:\Users\jdoe\Downloads\output.json.
.NOTES
    Requires access to the Windows Security event log.
#>

Param(
    [string]$Path = "$env:USERPROFILE\Downloads\powershell_security_events.json",
    [ValidateRange(1, 5000)]
    [int]$MaxEvents = 100,
    [int[]]$EventIds = @(4624, 4625, 4672, 4720, 4728)
)

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = $EventIds
} | 
Select-Object -First $MaxEvents

function Get-EventDataValue {
    param (
        [xml] $Xml,
        [string] $FieldName
    )
    $value = ($Xml.event.EventData.Data | Where-Object{$_.Name -eq $FieldName}).'#text'
    
    if ($value -eq "-") {
        return $null
    }
    return $value
}

function Convert-WindowsSecurityEvent {
    param (
        [object] $SecurityEvent
    )
    $xml = [xml]$SecurityEvent.ToXml()
    $Username = $null
    $TargetUser = $null
    $TargetGroup = $null
    $SourceIp = $null
    $LogonId = $null
    $Privileges = $null
    switch ($SecurityEvent.Id) {
        4624 {  
            $Username = Get-EventDataValue -Xml $xml -FieldName "SubjectUserName"
            $TargetUser = Get-EventDataValue -Xml $xml -FieldName "TargetUserName"
            $SourceIp = Get-EventDataValue -Xml $xml -FieldName "IpAddress"
            $LogonId = Get-EventDataValue -Xml $xml -FieldName "TargetLogonId"
        }
        4625 {
            $Username = Get-EventDataValue -Xml $xml -FieldName "TargetUserName"
            $TargetUser = Get-EventDataValue -Xml $xml -FieldName "TargetUserName"
            $SourceIp = Get-EventDataValue -Xml $xml -FieldName "IpAddress"
            $LogonId = Get-EventDataValue -Xml $xml -FieldName "SubjectLogonId"
        }
        4672 {
            $Username = Get-EventDataValue -Xml $xml -FieldName "SubjectUserName"
            $LogonId = Get-EventDataValue -Xml $xml -FieldName "SubjectLogonId"
            $Privileges = Get-EventDataValue -Xml $xml -FieldName "PrivilegeList"
        }
        4720 {
            $Username = Get-EventDataValue -Xml $xml -FieldName "SubjectUserName"
            $TargetUser = Get-EventDataValue -Xml $xml -FieldName "TargetUserName"
            $LogonId = Get-EventDataValue -Xml $xml -FieldName "SubjectLogonId"
        }
        4728 {
            $Username = Get-EventDataValue -Xml $xml -FieldName "SubjectUserName"
            $TargetUser = Get-EventDataValue -Xml $xml -FieldName "MemberName"
            $TargetGroup = Get-EventDataValue -Xml $xml -FieldName "TargetUserName"
            $LogonId = Get-EventDataValue -Xml $xml -FieldName "SubjectLogonId"
        }
    }

    $normalizedEvent = [PSCustomObject]@{
        Timestamp = $SecurityEvent.TimeCreated.ToString("o")
        EventId = $SecurityEvent.Id
        Computer = $SecurityEvent.MachineName
        LogName = $SecurityEvent.LogName
        Level = $SecurityEvent.LevelDisplayName
        Message = $SecurityEvent.Message
        Username = $Username
        TargetUser = $TargetUser
        SourceIp = $SourceIp
        Privileges = $Privileges
        TargetGroup = $TargetGroup
        LogonId = $LogonId
    }
    return $normalizedEvent
}

$normalizedEvents = foreach($event in $events)
{
    Convert-WindowsSecurityEvent -SecurityEvent $event
}

$normalizedEvents | ConvertTo-Json -Depth 4 | Set-Content -Path $Path -Encoding utf8
"Exported $($normalizedEvents.Count) normalized events to $Path" 