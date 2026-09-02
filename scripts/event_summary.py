import json
import argparse

def main():
    parser = argparse.ArgumentParser(description="JSON file parser")
    
    parser.add_argument(
        '-e', '--events',
        type=argparse.FileType('r'),
        required=True,
        help="Path to input JSON file"
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
            events = count_events(events_list)
            for key, value in events.items():
                print(f"Event ID {key}: {value}")
        
    except json.JSONDecodeError:
        print("Error: The file is not a valid JSON document")
        
def count_events(events_list):
    events = dict()
    for event in events_list:
        event_id = event.get("EventId")
        if event_id is None:
            continue
        if event_id not in events:
            events[event_id] = 1
        else:
            events[event_id] += 1
    return events

def filter_events_by_id(events_list, event_id):
    events = []
    for event in events_list:
        target_id = event.get("EventId")
        if target_id != event_id:
            continue
        events.append(event)
    return events

def print_event(event):
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