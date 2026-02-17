from datetime import datetime
def parse_timestamp(ts):
    try:
        if isinstance(ts, int):
            return ts / 1000

        if isinstance(ts, str):
            # Numeric string
            if ts.isdigit():
                return int(ts) / 1000

            # ISO format
            ts = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            return dt.timestamp()

    except Exception:
        return None

    return None


def calculate_engagement_duration(request_data):
    timestamps = []
    msg_ts = request_data.get("message", {}).get("timestamp")
    parsed = parse_timestamp(msg_ts)
    if parsed:
        timestamps.append(parsed)
    for msg in request_data.get("conversationHistory", []):
        ts = msg.get("timestamp")
        parsed = parse_timestamp(ts)
        if parsed:
            timestamps.append(parsed)
    if len(timestamps) < 2:
        return 0

    duration = int(max(timestamps) - min(timestamps))

    # Prevent negative or unrealistic values
    if duration < 0:
        return 0

    return duration
