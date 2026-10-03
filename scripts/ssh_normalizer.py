import json
import argparse
import re
from datetime import datetime, timezone

def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize SSH logs"
)
    
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
        failed_logins = 0
        successful_logins = 0
        normalization_failures = 0
        parse_failures = 0
        json_parse_failures = 0
        normalized_events = []

        with open(args.input_file, "r", encoding="utf-8") as imported_data:

            pattern = r"(?P<result>Failed|Accepted) password for (?:(?P<validity>invalid user) )?(?P<username>\S+) from (?P<source_ip>\S+) port (?P<port>\d+) (?P<protocol>\S+)"
            
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

                message = event.get("MESSAGE", "")

                is_auth_event = (
                    message.startswith("Failed password") 
                    or message.startswith("Accepted password")
                )
                
                match = re.match(pattern, message)

                if is_auth_event and not match:
                    parse_failures += 1
                    continue

                if not is_auth_event:
                    other_event_count += 1
                    continue


                result = match.group("result")
                username = match.group("username")
                source_ip = match.group("source_ip")
                port = int(match.group("port"))

                if not 1 <= port <= 65535:
                    normalization_failures += 1
                    continue
                
                protocol = match.group("protocol")

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

                if match.group("validity") is not None:
                    account_validity = "Invalid"
                else:
                    account_validity = "Valid"

                if result == "Failed":
                    event_type = "FailedAuthentication"
                    failed_logins += 1
                elif result == "Accepted":
                    event_type = "SuccessfulAuthentication"
                    successful_logins += 1
                
                
                normalized_events.append({
                    "Timestamp": utc_timestamp,
                    "Computer": event.get("_HOSTNAME", ""),
                    "Service": event.get("SYSLOG_IDENTIFIER", ""),
                    "EventType": event_type,
                    "TargetUser": username,
                    "AccountValidity": account_validity,
                    "SourceIp": source_ip,
                    "SourcePort": port,
                    "Protocol": protocol
                })                   

        print(f"Processed {total_event_count}")
        print(f"Failed logins: {failed_logins}")
        print(f"Successful logins: {successful_logins}")
        print(f"Other events: {other_event_count}")
        print(f"Normalization failures: {normalization_failures}")
        print(f"Normalized events: {len(normalized_events)}")
        print(f"Parse failures: {parse_failures}")
        print(f"JSON parse failures: {json_parse_failures}")

        with open(args.output_file, "w", encoding="utf-8") as output_file:
            json.dump(normalized_events, output_file, indent=4)
            
        print(f"Normalized events written to {args.output_file}")

    except FileNotFoundError:
        print("Error: The specified file does not exist")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()