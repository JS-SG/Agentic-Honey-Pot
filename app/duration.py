from datetime import datetime, timezone

def parse_timestamp(ts):
    if isinstance(ts, int) or (isinstance(ts, str) and ts.isdigit()):
        return int(ts) / 1000

    if isinstance(ts, str):
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.timestamp()

    return None


def calculate_engagement_duration(request_data):
    timestamps = []
    msg_ts = request_data.get("message", {}).get("timestamp")
    if msg_ts:
        parsed = parse_timestamp(msg_ts)
        if parsed is not None:
            timestamps.append(parsed)

    for msg in request_data.get("conversationHistory", []):
        ts = msg.get("timestamp")
        if ts:
            parsed = parse_timestamp(ts)
            if parsed is not None:
                timestamps.append(parsed)

    if not timestamps:
        return 0
    return int(max(timestamps) - min(timestamps))
