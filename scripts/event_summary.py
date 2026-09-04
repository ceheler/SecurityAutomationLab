"""Summarize and filter normalized Windows Security Event JSON data."""
import json
import argparse

def main() -> None:
    parser = argparse.ArgumentParser(
    description="Analyze normalized Windows Security Events and optionally filter them by Event ID."
)
    
    parser.add_argument(
        '-e', '--events',
        type=argparse.FileType('r'),
        required=True,
        help="Optional Event ID to filter for"
    )
    
    parser.add_argument(
            '-ei', '--event-id',
            type=int,
            required=False,
            help="Event ID Filter"
        )
    
    args = parser.parse_args()
    
    try:
        with args.events as json_file:
            file_name = json_file.name
            events_list = json.load(json_file)
            
        if not isinstance(events_list, list):
            print("Error: Expected a JSON array of security events.")
            return
        if not events_list:
            print("Error: Input list is empty.")
            return 
        if args.event_id is not None:
            print(f"Successfully loaded {len(events_list)} events from {file_name}\nResults filtered by {args.event_id}\n")
        else:
            print(f"Successfully loaded {len(events_list)} events from {file_name}\n")
        
        if args.event_id is not None:
            events = filter_events_by_id(events_list, args.event_id)
            if not events:
                print(f"No events found matching Event ID {args.event_id}")
            else:
                for event in events:
                    print_event(event)
        else:    
            events, skipped_events = count_events(events_list)
            for key, value in sorted(events.items()):
                print(f"Event ID {key}: {value}")
            if skipped_events > 0:
                print(f"Skipped {skipped_events} events with missing EventId.")
        
    except json.JSONDecodeError:
        print("Error: The file is not a valid JSON document")
        
def count_events(events_list: list[dict]) -> tuple[dict[int, int], int]:
    """Count Windows Security Events by EventId.
    Args:
        events_list: List of Windows Security Event dictionaries.

    Returns:
        Dictionary mapping each EventId to the number of occurrences.
    """
    events = {}
    skipped_events = 0
    for event in events_list:
        event_id = event.get("EventId")
        if event_id is None:
            skipped_events += 1
            continue
        if event_id not in events:
            events[event_id] = 1
        else:
            events[event_id] += 1
    return events, skipped_events

def filter_events_by_id(events_list: list[dict], event_id: int) -> list[dict]:
    """Filter Windows Security Events by EventId.

    Args:
        events_list: List of Windows Security Event dictionaries.
        event_id: Targeted EventId.

    Returns:
        events: List of events with an EventId matching event_id.
    """
    events = []
    for event in events_list:
        target_id = event.get("EventId")
        if target_id != event_id:
            continue
        events.append(event)
    return events

def print_event(event: dict[str, object]) -> None:
    """Print a normalized Windows Security Event to the terminal.

    Args:
        event: Windows Security Event dictionary.
    """
    fields = {
        "Event ID": event.get("EventId"),
        "Timestamp": event.get("Timestamp"),
        "Computer": event.get("Computer"),
        "Username": event.get("Username"),
        "Source IP": event.get("SourceIp"),
        "Message": event.get("Message")
    }
    for label, value in fields.items():
        if value is not None:
            print(f"{label}: {value}")
    print("\n--------------------\n")     
        
if __name__ == "__main__":
    main()