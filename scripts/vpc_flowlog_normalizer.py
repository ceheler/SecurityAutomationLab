import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize VPC Flow Logs")

    parser.add_argument(
        "--input-file",
        type=Path,
        required=True,
        help="Path to text file"
    )

    parser.add_argument(
        "--output-file",
        type=Path,
        required=True,
        help="Path to output JSON file"
    )

    args = parser.parse_args()

    normalized_events = normalize_file(args.input_file)

    with open(args.output_file, "w", encoding="utf-8") as output_file:
        json.dump(normalized_events, output_file, indent=4)


def normalize_record(line: str):
    input_fields = line.split()

    if len(input_fields) != 14 or input_fields[12] != "REJECT":
        return None

    try:
        raw_timestamp = int(input_fields[10])
        protocol_int = int(input_fields[7])
        destination_port = int(input_fields[6])
    except ValueError:
        return None

    timestamp = datetime.fromtimestamp(raw_timestamp, tz=timezone.utc).isoformat()

    match protocol_int:
        case 6:
            protocol = "TCP"
        case 17:
            protocol = "UDP"
        case 1:
            protocol = "ICMP"
        case _:
            return None

    normalized_fields = {
        "Timestamp": timestamp,
        "Service": "VPCFlowLogs",
        "EventType": "NetworkConnectionBlocked",
        "SourceIp": input_fields[3],
        "DestinationIp": input_fields[4],
        "DestinationPort": destination_port,
        "Protocol": protocol
    }
    return normalized_fields

def normalize_file(input_path: Path):
    events = []
    with open(input_path, "r", encoding="utf-8") as file:
        for line in file:
            normalized = normalize_record(line)
            if normalized is not None:
                events.append(normalized)
    return events

if __name__ == "__main__":
    main()
