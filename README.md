# SecurityAutomationLab

SecurityAutomationLab contains tools for collecting and normalizing security telemetry from Windows, Linux, and AWS environments for downstream behavioral detection.

The project currently supports:

- Windows Security Event collection and normalization through PowerShell
- Linux SSH authentication normalization through Python
- Linux UFW network-block normalization through Python
- AWS CloudTrail normalization through Python
- AWS VPC Flow Logs normalization through Python

Normalized events use common semantic fields where possible and are designed for downstream analysis by SecurityEventAnalyzer

## Architecture

SecurityAutomationLab separates source-specific collection and parsing from
downstream detection logic.

```text
Windows Security Log → Get-SecurityEvents.ps1   ┐
Linux SSH logs      → ssh_normalizer.py         |
Linux UFW logs      → ufw_normalizer.py         |
AWS CloudTrail logs → cloudtrail_normalizer.py  ├→ normalized SecurityEvent JSON
AWS VPC Flow logs   → vpc_flowlog_normalizer.py ┘
                                                          ↓
                                                 SecurityEventAnalyzer
                                                          ↓
                                                   SecurityFindings
```

## Get-SecurityEvents.ps1

### Purpose

This script queries Windows Security event logs, normalizes selected events into a consistent schema, and exports the results as JSON for downstream analysis with SecurityEventAnalyzer.

### Supported Event IDs

- 4624 — Successful Logon
- 4625 — Failed Logon
- 4672 — Special privileges assigned to new logon
- 4720 — A user account was created
- 4728 — A member was added to a security-enabled global group
- 4732 — A member was added to a security-enabled local group


### Parameters

All parameters are optional and have default values.

- `-Path`
  Path for the exported JSON file.
  Default: `$env:USERPROFILE\Downloads\powershell_security_events.json`

- `-MaxEvents`
  Number of events to process.
  Default: `100`

- `-EventIds`
  Specifies which Event IDs to query and normalize.
  Default: `4624, 4625, 4672, 4720, 4728, 4732`


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
- EventType
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

Authentication events are additionally mapped to source-independent semantic event types:

- Event ID `4624` → `SuccessfulAuthentication`
- Event ID `4625` → `FailedAuthentication`

This allows downstream detection logic to analyze authentication behavior without depending directly on Windows-specific Event IDs.

Fields that are not applicable to a particular event are exported as `null`.

### SecurityEventAnalyzer Integration

The exported JSON schema is designed to be compatible with the SecurityEventAnalyzer C# project.

Windows authentication events are normalized to source-independent `EventType` values so behavioral detections can operate on the same semantic fields used by other telemetry sources, such as Linux SSH logs.

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
- Expand semantic `EventType` mapping to additional Windows Security Events

---

## cloudtrail_normalizer.py

### Purpose

This script processes AWS CloudTrail telemetry in JSON format, extracts relevant API activity and identity information, and exports normalized JSON for downstream analysis with SecurityEventAnalyzer.

The normalizer locates identity programmatically using the following preference sessionIssuer.userName -> userIdentity.userName -> userIdentity.principalId -> userIdentity.arn finally assigning `None` if the preferred fields do not exist.

### Supported Input

Exported CloudTrail logs in JSON format as well as single event JSON files.

### Parameters

All parameters are required. No defaults are provided.

- `--input-file`
  Path to the input JSON file exported from CloudTrail.

- `--output-file`
  Path for the normalized JSON output file.

### Normalized Output

CloudTrail events are converted into a consistent output schema containing:

- Timestamp
- Service -> hardset to `CloudTrail`
- EventType -> hardset to `CloudApiCall`
- Action
- Username
- SourceIp
- ResourceType
- ResourceId

`Action` is set to the action reported by CloudTrail for downstream analysis.

`ResourceId` extracts the final resource identifier from the AWS ARN, removing the preceding ARN information to provide a concise identifier for downstream analysis.

Examples:

- `vpc-0123456789abcdef0`
- `i-0123456789abcdef0`

### Error Handling

The normalizer handles several malformed-input conditions without terminating processing of the remaining telemetry:

- Invalid input file type
- Valid JSON with an unexpected top-level structure
- Missing or invalid fields
- Incomplete records are skipped over without stopping execution

### SecurityEventAnalyzer Integration

Normalized CloudTrail telemetry has been validated with SecurityEventAnalyzer.

The shared `Action` values allow the detection logic to operate against normalized AWS CloudTrail events.

```text
CloudTrail exported logs JSON
        ↓
cloudtrail_normalizer.py
        ↓
normalized SecurityEvent JSON
        ↓
SecurityEventAnalyzer
        ↓
TerminateInstances / DeleteVpc detections
```

### Example Usage

```bash
python3 scripts/cloudtrail_normalizer.py \
    --input-file tests/aws_cloudtrail_destructive.json \
    --output-file /tmp/cloudtrail-destructive-normalized.json
```
The normalized output is then run through `SecurityEventAnalyzer` as outlined in its documentation with the following command:

```bash
dotnet run /tmp/vpc-flowlog-normalized.json
```

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

Normalized SSH telemetry has been validated with SecurityEventAnalyzer.

The shared `EventType` values allow the same behavioral authentication detection logic to operate against normalized Windows and Linux SSH events.

```text
Linux journal / sshd
        ↓
ssh_normalizer.py
        ↓
normalized SecurityEvent JSON
        ↓
SecurityEventAnalyzer
        ↓
shared behavioral detections
```

### Future Improvements

- Path validation
- Additional SSH authentication formats
- Additional Linux authentication event types

## ufw_normalizer.py

### Purpose

This script reads Linux UFW firewall telemetry exported from `journalctl` in JSONL format, parses blocked network connections, and exports normalized JSON for downstream analysis with SecurityEventAnalyzer.

The normalizer separates Linux/UFW-specific log formatting from downstream network detection logic.

### Supported Events

- UFW blocked network connections containing `[UFW BLOCK]`

### Parameters

All parameters are required.

- `--input_file` Path to the JSONL file exported from `journalctl`

- `--output_file` Path for the normalized JSON output file

### Example Source Collection

```bash
sudo journalctl -b -k -g "UFW BLOCK" -o json > ~/logs/ufw_block_raw.jsonl
```

### Example Usage

```powershell
python .\ufw_normalizer.py --input_file .\ufw_block_raw.jsonl --output_file .\ufw_normalized.json
```

### Normalized Schema

Relevant UFW records are normalized into the following fields:

- Timestamp
- Computer
- Service
- EventType
- SourceIp
- SourcePort
- DestinationIp
- DestinationPort
- Protocol

Blocked connections have the following fields strictly assigned

- `EventType = "NetworkConnectionBlocked"`
- `Service = "UFW"`

### SecurityEventAnalyzer Integration

Normalized UFW telemetry has been validated with the SecurityEventAnalyzer `PortScanDetector`.

The detector groups blocked connections by source IP, destination IP, and protocol and detects four or more unique destination ports within a sliding one-minute window.

```text
Linux kernel / UFW
        ↓
journalctl JSONL
        ↓
ufw_normalizer.py
        ↓
normalized SecurityEvent JSON
        ↓
SecurityEventAnalyzer
        ↓
PortScanDetector
```

### Validation

The complete pipeline has been validated using controlled Nmap traffic against an isolated Ubuntu server host

Boundary testing included:

- 3 unique blocked destination ports -> no finding
- 4 unique blocked destination ports -> finding
- 5 unique blocked destination ports -> finding
- Repeated ports without 4 unique destinations -> no finding
- Same source IP targeting different destination hosts -> no finding
- Events outside one-minute window -> no finding

### Future Improvements

- Path validation
- Support for additional firewall telemetry
- Add normalization support for Windows Firewall network-block telemetry

---

## vpc_flowlog_normalizer.py

### Purpose

This script processes AWS VPC Flow Logs in plain-text format, extracts relevant network connection metadata, and exports normalized JSON for downstream analysis with SecurityEventAnalyzer.

### Supported Input

The script accepts plain-text files containing AWS VPC Flow Log records in the default 14-field, space-delimited format.
Each line represents one flow log record. Records that do not contain exactly 14 fields are skipped without interrupting processing of the remaining records.

Only records with an action of `REJECT` are normalized. Records with an action of `ACCEPT` are ignored.

### Parameters

All parameters are required.

- `--input-file` Path to the plain-text AWS Flow Log file

- `--output-file` Path for the normalized JSON output file

### Normalized Output

Raw AWS VPC Flow Logs are converted into a consistent output schema containing:

- Timestamp
- Service -> hardset to `VPCFlowLogs`
- EventType -> hardset to `NetworkConnectionBlocked`
- SourceIp
- DestinationIp
- DestinationPort
- Protocol

`Timestamp` is ingested as Unix time and converted to ISO 8601 to match what is expected in SecurityEventAnalyzer

`Protocol` is converted from an integer using IANA standards. The normalizer supports TCP (6), UDP (17), and ICMP (1). Records containing unsupported protocol numbers or nonnumeric destination ports are skipped.

### Error Handling

The normalizer skips unsupported, irrelevant, or malformed records without interrupting the processing of remaining valid telemetry.

Records are skipped under the following conditions:

- Records containing fewer or more than 14 fields
- `ACCEPT` traffic (intentionally excluded)
- Unsupported protocol numbers
- Invalid or nonnumeric destination ports
- Invalid or nonnumeric Unix timestamps
- Nonnumeric protocol fields

### SecurityEventAnalyzer Integration

Normalized VPC Flow Logs have been validated with SecurityEventAnalyzer.

The shared `SecurityEvent` schema allows the existing `PortScanDetector` to analyze normalized network telemetry from both AWS VPC Flow Logs and Linux UFW. Both normalizers classify blocked network connections using `EventType = "NetworkConnectionBlocked"`, allowing the detector to operate independently of the original telemetry source.

`PortScanDetector` generates a Medium-severity finding under the flowing conditions

- 4 or more distinct blocked destination ports
- When SourceIp, DestinationIp and Protocol are all the same
- Within a 1 minute of each other

```text
Raw VPC Flow Log plaintext file
        ↓
vpc_flowlog_normalizer.py
        ↓
normalized SecurityEvent JSON
        ↓
SecurityEventAnalyzer
        ↓
Port Scan detections
```

### Example Usage

```bash
python3 scripts/vpc_flowlog_normalizer.py \
    --input-file tests/aws_vpc_flow_logs.txt \
    --output-file /tmp/vpc-flowlog-normalized.json
```

The normalized output is then run through `SecurityEventAnalyzer` as outlined in its documentation with the following command:

```bash
dotnet run /tmp/vpc-flowlog-normalized.json
```

### Example Output

```text
Analyzing /tmp/vpc-flowlog-normalized.json

Log event summary

===================

Processed 4 events


Port Scan Detection
4 distinct blocked destination ports detected within a 1 minute window.
===================
Severity: Medium
Timestamp: 10/15/2026 5:00:00 AM
Source IP: 192.0.2.10
Destination IP: 198.51.100.20
Count: 4
```
