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
        
        print(f"Successfully loaded {len(events_list)} events from {file_name}\n")
        
        events =  dict()
        
        for event in events_list:
            event_id = event["EventId"]
            if event_id not in events:
                events[event_id] = 1
            else:
                events[event_id] += 1
        for key, value in events.items():
            print(f"Event ID {key}: {value}")
    
    except json.JSONDecodeError:
        print("Error: The file is not a valid JSON document")
        
if __name__ == "__main__":
    main()