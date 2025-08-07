# Usage: uv run -w requests nuke_slack_thread.py <oauth_token> <thread_url>

import sys
import re
import requests


def parse_thread_url(url: str) -> tuple[str, str]:
    # Example: https://yourworkspace.slack.com/archives/C12345678/p1700000000000000
    match = re.search(r"/archives/([A-Z0-9]+)/p(\d{16})", url)
    assert match, "Invalid Slack thread URL"
    ts = match.group(2)
    return match.group(1), f"{ts[:10]}.{ts[10:]}"


def get_thread_messages(oauth_token: str, channel_id: str, ts: str) -> list:
    url = "https://slack.com/api/conversations.replies"
    params = {"channel": channel_id, "ts": ts, "limit": 1000}
    headers = {"Authorization": f"Bearer {oauth_token}"}
    res = requests.get(url, headers=headers, params=params).json()
    assert res.get("ok"), f"Failed to fetch messages: {res.get('error')}"
    return res.get("messages", [])


def delete_message(oauth_token: str, channel_id: str, ts: str) -> None:
    url = "https://slack.com/api/chat.delete"
    data = {"channel": channel_id, "ts": ts}
    headers = {"Authorization": f"Bearer {oauth_token}"}
    res = requests.post(url, headers=headers, data=data).json()
    if not res.get("ok"):
        print(f"Failed to delete message {ts}: {res.get('error')}")
    else:
        print(f"Deleted message {ts}")


def main() -> None:
    assert len(sys.argv) == 3, (
        "Usage: python nuke_slack_thread.py <oauth_token> <thread_url>"
    )
    oauth_token, thread_url = sys.argv[1], sys.argv[2]
    channel_id, ts = parse_thread_url(thread_url)
    messages = get_thread_messages(oauth_token, channel_id, ts)
    print(f"Deleting {len(messages)} messages")
    for message in messages:
        delete_message(oauth_token, channel_id, message["ts"])


if __name__ == "__main__":
    main()
