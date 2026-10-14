import json
import argparse

def main() -> None:
    parser = argparse.ArgumentParser(description= "Normalize CloudTrail logs")

    parser.add_argument(
        "--input-file",
        type = str,
        required = True,
        help = "Path to input JSON file"
    )

    parser.add_argument(
        "--output-file",
        type = str,
        required = True,
        help = "Path to ouput normalized JSON file"
    )

    args = parser.parse_args()

    data = load_validate_file(args.input_file)

    if data is None:
        return

    if "Records" in data:
        if not isinstance(data['Records'], list):
            print("The 'Records' key must contain a list of records.")
            return
        if not data['Records']:
            print("The 'Records' list in the CloudTrail log file is empty.")
            return
        event_list = data["Records"]

    else:
        event_list = [data]

    normalized_events = normalize_cloudtrail_events(event_list)

    with open(args.output_file, "w", encoding="utf-8") as output_file:
        json.dump(normalized_events, output_file, indent=4)
    

def load_validate_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            if not isinstance(data, dict):
                raise ValueError("CloudTrail log file must contain a JSON object.")
            return data

    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return None

    except ValueError as e:
        print(f"Value error: {e}")
        return None

def extract_username(event):
    """
    Extracts the username from a CloudTrail event.

    Args:
        event (dict): The CloudTrail event.

    Returns:
        str: The username from the event.
    """
    username = None

    user_identity = event.get("userIdentity")
    if isinstance(user_identity, dict):
        session_context = user_identity.get("sessionContext")
        if isinstance(session_context, dict):
            session_issuer = session_context.get("sessionIssuer")
            if isinstance(session_issuer, dict):
                username = session_issuer.get("userName")
        if not isinstance(username, str) or not username:
            username = user_identity.get("userName")
        if not isinstance(username, str) or not username:
            username = user_identity.get("principalId")
        if not isinstance(username, str) or not username:
            username = user_identity.get("arn")

    if not isinstance(username, str) or not username:
        username = None

    return username

def extract_resource(event):
    """
    Extracts the resource name from a CloudTrail event.

    Args:
        event (dict): The CloudTrail event.
    Returns:
        str: The resource type from the event.
        str: The resource id from the event.
    """
    resource_id = None
    resource_type = None

    resources = event.get("resources")
    if isinstance(resources, list) and resources:
        resource = resources[0]
        if isinstance(resource, dict):
            resource_type = resource.get('type')
            if not isinstance(resource_type, str) or not resource_type:
                resource_type = None

            arn = resource.get('ARN')
            if isinstance(arn, str) and arn:
                resource_id = arn.split("/")[-1]
            if not resource_id:
                resource_id = None

    return resource_type, resource_id

def normalize_cloudtrail_event(event):
    """
    Normalizes a CloudTrail event.

    Args:
        event (dict): The CloudTrail event.

    Returns:
        dict: The normalized event.
    """
    if not isinstance(event, dict):
        return None

    timestamp = event.get("eventTime")
    action = event.get("eventName")
    username = extract_username(event)
    resource_type, resource_id = extract_resource(event)
    source_ip = event.get("sourceIPAddress")

    if not isinstance(timestamp, str) or not timestamp:
        return None

    if not isinstance(action, str) or not action:
        return None

    if not isinstance(source_ip, str) or not source_ip:
        source_ip = None

    return {
        "Timestamp": timestamp,
        "Service": "CloudTrail",
        "EventType": "CloudApiCall",
        "Action": action,
        "Username": username,
        "SourceIp": source_ip,
        "ResourceType": resource_type,
        "ResourceId": resource_id
    }

def normalize_cloudtrail_events(events):
    normalized_events = []

    if not isinstance(events, list):
        return []

    for event in events:
        normalized_event = normalize_cloudtrail_event(event)
        if normalized_event is not None:
            normalized_events.append(normalized_event)

    return normalized_events

if __name__ == "__main__":
    main()