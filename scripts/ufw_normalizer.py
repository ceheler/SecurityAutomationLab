import json
import argparse
from datetime import datetime, timezone

def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize UFW logs")
    
    parser.add_argument(
        '--input_file',
        type=str,
        required=True,
        help="Path to the input JSONL file"
        )
    
    parser.add_argument(
        '--output_file',
        type=str,
        required=True,
        help="Path to the output JSON file"
        )

    args = parser.parse_args()

    try:
        total_event_count = 0
        other_event_count = 0
        normalization_failures = 0
        json_parse_failures = 0
        normalized_events = []

        with open(args.input_file, "r", encoding="utf-8") as imported_data:

            for line_number, line in enumerate(imported_data, start=1):
                if not line.strip():
                    continue
                
                try:
                    event = json.loads(line)
                    total_event_count += 1
                except json.JSONDecodeError:
                    json_parse_failures += 1
                    total_event_count += 1
                    print(f"JSON Parse failure on line: {line_number}")
                    continue
                if not isinstance(event, dict):
                    json_parse_failures += 1
                    print(f"Input is not a dictionary")
                    continue

                fields = {}
                message = event.get("MESSAGE")

                if not isinstance(message, str):
                    normalization_failures += 1
                    continue
                
                if message.startswith("[UFW BLOCK]"):
                    for token in message.split():
                        if "=" in token:
                            key, value = token.split("=", 1)
                            fields[key] = value
                else:
                    other_event_count += 1
                    continue

                try:
                    raw_timestamp = event.get("__REALTIME_TIMESTAMP")
                    if raw_timestamp is not None:
                        timestamp = (int(raw_timestamp) / 1_000_000)
                        utc_timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
                    else:
                        normalization_failures += 1
                        continue
                except (ValueError, TypeError, OSError):
                    normalization_failures += 1
                    continue

                try:
                    source_port = int(fields.get("SPT"))
                    destination_port = int(fields.get("DPT"))

                    if not 1 <= destination_port <= 65535:
                        normalization_failures += 1
                        continue

                    if not 1 <= source_port <= 65535:
                        normalization_failures += 1
                        continue
  
                except (ValueError, TypeError):
                    normalization_failures += 1
                    continue

                source_ip = fields.get("SRC")
                destination_ip = fields.get("DST")
                protocol = fields.get("PROTO")
                if protocol:
                    protocol = protocol.upper()

                if not source_ip or not destination_ip or not protocol:
                    normalization_failures += 1
                    continue

                normalized_events.append({
                    "Timestamp": utc_timestamp,
                    "Computer": event.get("_HOSTNAME", ""),
                    "Service": "UFW",
                    "EventType": "NetworkConnectionBlocked",
                    "SourceIp": source_ip,
                    "SourcePort": source_port,
                    "DestinationIp": destination_ip,
                    "DestinationPort": destination_port,
                    "Protocol": protocol
                })
        
        print(f"Total events: {total_event_count}")
        print(f"Normalized events: {len(normalized_events)}")
        print(f"Normalization failures: {normalization_failures}")
        print(f"JSON parse failures: {json_parse_failures}")

        with open(args.output_file, "w", encoding="utf-8") as output_file:
            json.dump(normalized_events, output_file, indent=4)
            
        print(f"Normalized events written to {args.output_file}")

    except FileNotFoundError:
        print("Error: The specified file does not exist")            
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()