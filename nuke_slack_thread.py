import argparse
import logging
import os
import re
import threading
import time
import webbrowser

import dotenv
import requests
from flask import Flask, request
from slack_sdk import WebClient

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)
app = Flask(__name__)
auth_code = None


@app.route("/oauth/callback")
def oauth_callback():
    global auth_code
    auth_code = request.args.get("code")
    if auth_code:
        return "<html><body>OAuth success</body></html>", 200
    return "<html><body>OAuth failure</body></html>", 400


def do_oauth(client_id: str, client_secret: str) -> str:
    # Start local server for OAuth callback.
    server_thread = threading.Thread(
        target=lambda: app.run(host="localhost", port=8080, ssl_context="adhoc"),
        daemon=True,
    )
    server_thread.start()

    # Open OAuth URL.
    redirect_uri = "https://localhost:8080/oauth/callback"
    auth_url = (
        f"https://slack.com/oauth/v2/authorize?"
        f"client_id={client_id}&"
        f"redirect_uri={redirect_uri}&"
        f"user_scope=channels:history,chat:write,groups:history,im:history,mpim:history"
    )
    webbrowser.open(auth_url)

    # Wait for auth code.
    start_time = time.time()
    while auth_code is None and (time.time() - start_time) < 60:
        time.sleep(1)
    assert auth_code, "OAuth timed out or failed"

    # Exchange auth code for token.
    token_url = "https://slack.com/api/oauth.v2.access"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": auth_code,
        "redirect_uri": redirect_uri,
    }
    res = requests.post(token_url, data=data).json()
    assert res.get("ok"), f"OAuth failed: {res['error']}"

    user_token = res["authed_user"]["access_token"]
    WebClient(token=user_token).auth_test()
    return user_token


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
        user_token = do_oauth(os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"])
        with open(user_token_file, "w") as f:
            f.write(user_token)

    client = WebClient(token=user_token)
    channel, ts = parse_thread_url(args.thread)
    messages = client.conversations_replies(
        channel=channel,
        ts=ts,
        inclusive=True,
    )["messages"]
    for message in messages:
        client.chat_delete(channel=channel, ts=message["ts"])


if __name__ == "__main__":
    main()
