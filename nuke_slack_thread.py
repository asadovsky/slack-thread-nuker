import argparse
import logging
import os
import re
import threading
import time
import webbrowser
from urllib.parse import urljoin

import dotenv
import httpx
from flask import Flask, request
from slack_sdk import WebClient

OAUTH_AUTHORIZE_URL = "https://slack.com/oauth/v2/authorize"
OAUTH_ACCESS_URL = "https://slack.com/api/oauth.v2.access"
OAUTH_REDIRECT_PATH = "/slack/oauth-redirect"

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)
app = Flask(__name__)
auth_code = None


@app.route(OAUTH_REDIRECT_PATH)  # pyright: ignore [reportUntypedFunctionDecorator]
def oauth_redirect() -> tuple[str, int]:
    global auth_code
    auth_code = request.args.get("code")
    if auth_code:
        return "<html><body>OAuth success</body></html>", 200
    return "<html><body>OAuth failure</body></html>", 400


def get_user_token_via_oauth() -> str:
    # Start local server for OAuth redirect.
    server_thread = threading.Thread(
        target=lambda: app.run(host="localhost", port=8080, ssl_context="adhoc"),
        daemon=True,
    )
    server_thread.start()

    # Open OAuth URL.
    redirect_uri = urljoin("https://localhost:8080", OAUTH_REDIRECT_PATH)
    scope = ",".join(
        [
            "channels:history",
            "chat:write",
            "groups:history",
            "im:history",
            "mpim:history",
        ]
    )
    webbrowser.open(
        f"{OAUTH_AUTHORIZE_URL}"
        f"?client_id={os.getenv('SLACK_CLIENT_ID')}"
        f"&redirect_uri={redirect_uri}"
        f"&scope={scope}"
        f"&user_scope={scope}"
    )

    # Wait for auth code.
    start_time = time.time()
    while auth_code is None and (time.time() - start_time) < 60:
        time.sleep(1)
    assert auth_code, "OAuth timed out or failed"

    # Exchange auth code for token.
    res = httpx.post(
        OAUTH_ACCESS_URL,
        data={
            "client_id": os.getenv("SLACK_CLIENT_ID"),
            "client_secret": os.getenv("SLACK_CLIENT_SECRET"),
            "code": auth_code,
            "redirect_uri": redirect_uri,
        },
    ).json()
    assert res["ok"], f"OAuth exchange failed: {res['error']}"
    return res["authed_user"]["access_token"]


def parse_thread_url(url: str) -> tuple[str, str]:
    # Example: https://yourworkspace.slack.com/archives/C12345678/p1700000000000000
    match = re.search(r"/archives/([A-Z0-9]+)/p(\d{16})", url)
    assert match, f"Invalid Slack thread URL: {url}"
    ts = match.group(2)
    return match.group(1), f"{ts[:10]}.{ts[10:]}"


def main() -> None:
    dotenv.load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--thread", required=True)
    args = parser.parse_args()

    user_token_file = ".user_token"
    try:
        with open(user_token_file) as f:
            user_token = f.read().strip()
    except FileNotFoundError:
        user_token = get_user_token_via_oauth()
        with open(user_token_file, "w") as f:
            f.write(user_token)

    client = WebClient(token=user_token)
    channel, ts = parse_thread_url(args.thread)
    msgs = (
        client.conversations_replies(
            channel=channel,
            ts=ts,
            inclusive=True,
        )["messages"]
        or []
    )
    for msg in msgs:
        client.chat_delete(channel=channel, ts=msg["ts"])


if __name__ == "__main__":
    main()
