# SecurityAutomationLab

SecurityAutomationLab contains tools for collecting, normalizing, and analyzing security telemetry from multiple operating systems.

The project currently supports Windows Security Event collection through PowerShell and Linux SSH authentication normalization through Python. Normalized events are intended for downstream behavioral detection using SecurityEventAnalyzer.

## Get-SecurityEvents.ps1

### Purpose

This script queries Windows Security event logs, normalizes selected events into a consistent schema, and exports the results as JSON for downstream analysis with SecurityEventAnalyzer.

### Supported Event IDs
<<<<<<< HEAD

- 4624 — Successful Logon
- 4625 — Failed Logon
- 4672 — Special privileges assigned to new logon
- 4720 — A user account was created
- 4728 — A member was added to a security-enabled global group
- 4732 — A member was added to a security-enabled local group
=======
- 4624 Successful Logon
- 4625 Failed Logon
- 4672 Special privileges assigned to new logon
- 4720 A user account was created
- 4728 A member was added to a security-enabled group
- 4732 A member was added to a security-enabled local group
>>>>>>> 5e1ef3294dcfa810b511fb15e937f21d53a14192

### Parameters

All parameters are optional and have default values.
<<<<<<< HEAD

- `-Path`
  Path for the exported JSON file.
  Default: `$env:USERPROFILE\Downloads\powershell_security_events.json`

- `-MaxEvents`
  Number of events to process.
  Default: `100`

- `-EventIds`
  Specifies which Event IDs to query and normalize.
  Default: `4624, 4625, 4672, 4720, 4728, 4732`
=======
- `-Path` 
Path for the exported JSON file.
Default: `$env:USERPROFILE\Downloads\powershell_security_events.json`
- `-MaxEvents` 
Number of events to process. 
Default: 100
- `-EventIds` 
Specifies which Event IDs to query and normalize.
Default: 4624, 4625, 4672, 4720, 4728, 4732
>>>>>>> 5e1ef3294dcfa810b511fb15e937f21d53a14192

### Requirements

- Windows
- PowerShell 5.1+ or PowerShell 7+
- Permission to read the Windows Security event log
- Administrator privileges may be required to access the Security event log

### Example Usage

```powershell
.\Get-SecurityEvents.ps1 -Path "C:\Users\jdoe\Downloads\output.json" -MaxEvents 10 -EventIds 4624,4720
```

### Normalized Output Example

```json
[
    {
        "Timestamp": "2026-09-04T10:03:25.8449849-07:00",
        "EventId": 4624,
        "Computer": "COMP1",
        "LogName": "Security",
        "Level": "Information",
        "Message": "An account was successfully logged on...",
        "Username": "Joe",
        "TargetUser": "SYSTEM",
        "SourceIp": null,
        "Privileges": null,
        "TargetGroup": null,
        "LogonId": "0x3e7"
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
- TargetDomainName
- TargetSid
- MemberSid

Fields that are not applicable to a particular event are exported as `null`.

### SecurityEventAnalyzer Integration

The exported JSON schema is designed to be compatible with the SecurityEventAnalyzer C# project.

```text
Windows Security Log
        ↓
Get-SecurityEvents.ps1
        ↓
normalized JSON
        ↓
SecurityEventAnalyzer
        ↓
detection findings
```

### Future Improvements

- Path validation
- Support additional Windows Security Event IDs
- Expand the normalized schema as the SecurityEventAnalyzer model evolves

---

## event_summary.py

### Purpose

This script reads normalized Windows Security Event data from a JSON file and summarizes the events by EventId and occurrence count.

If an EventId filter is supplied, the script prints detailed information for matching events instead of the overall event summary.

### Parameters

- `-e`, `--events`
  Path to a JSON file containing normalized Windows Security Events.

- `-ei`, `--event-id`
  Optional EventId used to filter the input and display matching event details.

### Sample Input With Filtering

```powershell
python .\scripts\event_summary.py -e .\tests\test_events.json --event-id 4624
```

Loads `.\tests\test_events.json`, filters for EventId `4624`, and prints detailed information for matching events.

### Sample Output With Filtering

```text
Successfully loaded 40 events from .\tests\test_windows_security_events.json

Results filtered by 4624

Event ID: 4624
Timestamp: 2026-08-26T08:01:05
Computer: DC01
Username: jsmith
Source IP: 10.10.10.21
Message: An account was successfully logged on.
```

### Sample Input Without Filtering

```powershell
python .\scripts\event_summary.py -e .\tests\test_events.json
```

Loads `.\tests\test_events.json` and prints a summary showing each EventId and the number of occurrences.

### Sample Output Without Filtering

```text
Successfully loaded 40 events from .\tests\test_windows_security_events.json

Event ID 4104: 1
Event ID 4624: 12
Event ID 4625: 15
Event ID 4634: 3
Event ID 4672: 1
Event ID 4688: 1
Event ID 4719: 1
Event ID 4720: 1
Event ID 4728: 1
Event ID 5140: 2

Skipped 2 events with missing EventId.
```

---

## ssh_normalizer.py

### Purpose

This script reads SSH telemetry exported from `journalctl` in JSONL format, identifies supported authentication events, parses relevant fields, and exports normalized JSON for downstream analysis with SecurityEventAnalyzer.

The normalizer separates source-specific Linux/`sshd` telemetry from downstream detection logic by converting authentication activity into a consistent event schema.

### Supported Events

- Failed SSH authentication
- Successful SSH authentication
- Failed authentication attempts against invalid accounts

### Parameters

All parameters are required. No defaults are provided.

- `--input_file`
  Path to the input JSONL file exported from `journalctl`.

- `--output_file`
  Path for the normalized JSON output file.

### Requirements

- Python 3.8+
- Tested with Python 3.14.8
- Linux system using `journalctl` for source telemetry
- Permission to read the relevant journal logs

### Example Usage

```powershell
python .\ssh_normalizer.py --input_file E:\logs\example.jsonl --output_file C:\Users\Bob\Downloads\normalized.json
```

### Example Console Output

```text
Processed 43
Failed logins: 20
Successful logins: 1
Other events: 22
Normalization failures: 0
Normalized events: 21
Parse failures: 0
JSON parse failures: 0
Normalized events written to C:\Users\Bob\Downloads\normalized.json
```

### Normalized Output Example

```json
[
    {
        "Timestamp": "2026-10-01T22:56:12.857113+00:00",
        "Computer": "test",
        "Service": "sshd",
        "EventType": "FailedAuthentication",
        "TargetUser": "test4",
        "AccountValidity": "Valid",
        "SourceIp": "192.168.123.123",
        "SourcePort": 33330,
        "Protocol": "ssh2"
    },
    {
        "Timestamp": "2026-10-01T22:56:16.892269+00:00",
        "Computer": "test",
        "Service": "sshd",
        "EventType": "FailedAuthentication",
        "TargetUser": "test4",
        "AccountValidity": "Valid",
        "SourceIp": "192.168.123.123",
        "SourcePort": 33330,
        "Protocol": "ssh2"
    },
    {
        "Timestamp": "2026-10-01T22:56:21.879359+00:00",
        "Computer": "test",
        "Service": "sshd",
        "EventType": "FailedAuthentication",
        "TargetUser": "test4",
        "AccountValidity": "Valid",
        "SourceIp": "192.168.123.123",
        "SourcePort": 33330,
        "Protocol": "ssh2"
    },
    {
        "Timestamp": "2026-10-01T22:56:32.414175+00:00",
        "Computer": "test",
        "Service": "sshd",
        "EventType": "FailedAuthentication",
        "TargetUser": "test4",
        "AccountValidity": "Valid",
        "SourceIp": "192.168.123.123",
        "SourcePort": 33331,
        "Protocol": "ssh2"
    }
]
```

### Normalization

Relevant SSH authentication records are converted into a consistent output schema containing:

- Timestamp
- Computer
- Service
- EventType
- TargetUser
- AccountValidity
- SourceIp
- SourcePort
- Protocol

`EventType` converts source-specific SSH messages into source-independent values such as:

- `FailedAuthentication`
- `SuccessfulAuthentication`

This allows downstream detection logic to analyze authentication behavior without parsing raw `sshd` messages.

### Error Handling

The normalizer handles several malformed-input conditions without terminating processing of the remaining telemetry:

- Invalid JSONL records
- Valid JSON with an unexpected top-level structure
- Authentication-like messages that do not match the expected SSH format
- Missing or invalid timestamps
- Invalid source-port values

The script reports separate counters for JSON parsing failures, SSH message parsing failures, and normalization failures.

### SecurityEventAnalyzer Integration

Integration with SecurityEventAnalyzer is currently in development.

The intended workflow is:

```text
Linux journal / sshd
        ↓
ssh_normalizer.py
        ↓
normalized JSON
        ↓
SecurityEventAnalyzer
        ↓
detection findings
```

The goal is for source-specific collectors and normalizers to produce a common event representation that can be consumed by shared behavioral detection logic.

### Future Improvements

- Path validation
- Additional SSH authentication formats
- Additional Linux authentication event types
- SecurityEventAnalyzer integration
