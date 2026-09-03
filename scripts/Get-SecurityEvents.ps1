$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624, 4672
} | 
Select-Object -First 10

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
        4672 {
            $Username = Get-EventDataValue -Xml $xml -FieldName "SubjectUserName"
            $LogonId = Get-EventDataValue -Xml $xml -FieldName "SubjectLogonId"
            $Privileges = Get-EventDataValue -Xml $xml -FieldName "PrivilegeList"
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

$normalizedEvents | ConvertTo-Json -Depth 4 | Set-Content -Path "C:\Users\cehel\source\repos\SecurityAutomationLab\tests\powershell_security_events.json" -Encoding utf8