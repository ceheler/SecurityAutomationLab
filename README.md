# SecurityAutomationLab

## Get-SecurityEvents.ps1

### Purpose
This script queries Windows Security event logs, normalizes selected events into a consistent schema, and exports the results as JSON for downstream analysis with SecurityEventAnalyzer.

### Supported Event IDs
- 4624 Successful Logon
- 4625 Failed Logon
- 4672 Special privileges assigned to new logon
- 4720 A user account was created
- 4728 A member was added to a security-enabled group

### Parameters
All parameters are optional and have default values.
- `-Path` 
Path for the exported JSON file.
Default: `$env:USERPROFILE\Downloads\powershell_security_events.json`
- `-MaxEvents` 
Number of events to process. 
Default: 100
- `-EventIds` 
Specifies which Event IDs to query and normalize.
Default: 4624, 4625, 4672, 4720, 4728

### Requirements

- Windows
- PowerShell 5.1+ or PowerShell 7+
- Permission to read the Windows Security event log
- Administrator privileges may be required to access the Security event log

### Example Usage 
.\Get-SecurityEvents.ps1 -Path "C:\Users\jdoe\Downloads\output.json" -MaxEvents 10 -EventIds 4624, 4720

### Normalized Output Example 
```json

[
    {
        "Timestamp":  "2026-09-04T10:03:25.8449849-07:00",
        "EventId":  4624,
        "Computer":  "COMP1",
        "LogName":  "Security",
        "Level":  "Information",
        "Message":  "An account was successfully logged on...",
        "Username":  "Joe",
        "TargetUser":  "SYSTEM",
        "SourceIp":  null,
        "Privileges":  null,
        "TargetGroup":  null,
        "LogonId":  "0x3e7"
    }
]

```

### Normalization

Different Windows Event IDs expose different XML fields. The script maps event-specific data into a consistent output schema containing fields such as:

- Timestamp
- EventId
- Computer
- Username
- TargetUser
- SourceIp
- TargetGroup
- LogonId
- Privileges
- Message
- LogName
- Level

Fields that are not applicable to a particular event are exported as null.

### SecurityEventAnalyzer Integration
The exported JSON schema is designed to be compatible with the SecurityEventAnalyzer C# project. This allows the workflow:

```

Windows Security Log
→ Get-SecurityEvents.ps1
→ normalized JSON
→ SecurityEventAnalyzer
→ detection findings
```

### Future Improvements
- Path validation
- Support additional Windows Security Event IDs
- Expand the normalized schema as the SecurityEventAnalyzer model evolves