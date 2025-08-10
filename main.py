import argparse
import hashlib
import hmac
import json
import os
import time
from typing import Any

import dotenv
import httpx
import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from google.cloud import datastore

OAUTH_AUTHORIZE_URL = "https://slack.com/oauth/v2/authorize"
OAUTH_ACCESS_URL = "https://slack.com/api/oauth.v2.access"
DS_KIND_SLACK_USER_TOKEN = "SlackUserToken"

app = FastAPI()


def datastore_client() -> datastore.Client:
    return datastore.Client(project=os.getenv("GCP_PROJECT_ID"))


def save_user_token(team_id: str, user_id: str, user_token: str) -> None:
    client = datastore_client()
    key = client.key(DS_KIND_SLACK_USER_TOKEN, f"{team_id}:{user_id}")
    entity = datastore.Entity(key=key)
    entity.update(
        {
            "team_id": team_id,
            "user_id": user_id,
            "user_token": user_token,
            "updated_at": int(time.time()),
        }
    )
    client.put(entity)


def get_user_token(team_id: str, user_id: str) -> str:
    client = datastore_client()
    key = client.key(DS_KIND_SLACK_USER_TOKEN, f"{team_id}:{user_id}")
    entity = client.get(key)
    if not entity:
        return ""
    return entity["user_token"]


async def do_oauth_exchange(code: str, redirect_uri: str) -> tuple[str, str, str]:
    async with httpx.AsyncClient() as client:
        res = (
            await client.post(
                OAUTH_ACCESS_URL,
                data={
                    "client_id": os.getenv("SLACK_CLIENT_ID"),
                    "client_secret": os.getenv("SLACK_CLIENT_SECRET"),
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
            )
        ).json()
    if not res["ok"]:
        raise HTTPException(
            status_code=400, detail=f"OAuth exchange failed: {res['error']}"
        )
    authed_user = res["authed_user"]
    return res["team"]["id"], authed_user["id"], authed_user["access_token"]


def verify_slack_signature(req: Request, body: bytes) -> None:
    ts = req.headers.get("X-Slack-Request-Timestamp")
    if not ts:
        raise HTTPException(status_code=401, detail="Missing timestamp")
    if abs(time.time() - int(ts)) > 60 * 5:
        raise HTTPException(status_code=401, detail="Stale request")
    digest = hmac.new(
        os.getenv("SLACK_CLIENT_SECRET", "").encode(),
        f"v0:{ts}:{body.decode()}".encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(
        f"v0={digest}", req.headers.get("X-Slack-Signature", "")
    ):
        raise HTTPException(status_code=401, detail="Invalid signature")


async def slack_api_get(
    token: str, method: str, params: dict[str, Any]
) -> dict[str, Any]:
    url = f"https://slack.com/api/{method}"
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient() as client:
        return (await client.get(url, headers=headers, params=params)).json()


async def slack_api_post(
    token: str, method: str, payload: dict[str, Any]
) -> dict[str, Any]:
    url = f"https://slack.com/api/{method}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient() as client:
        return (await client.post(url, headers=headers, json=payload)).json()


async def is_admin(token: str, user_id: str) -> bool:
    data = await slack_api_get(token, "users.info", {"user": user_id})
    return bool(data["ok"] and data["user"]["is_admin"])


async def get_thread_messages(
    token: str, channel: str, ts: str
) -> list[dict[str, Any]]:
    """Returns all messages from the given thread."""
    msgs: list[dict[str, Any]] = []
    cursor = None
    params = {
        "channel": channel,
        "ts": ts,
        "include_all_metadata": True,
    }
    while True:
        if cursor:
            params["cursor"] = cursor
        data = await slack_api_get(token, "conversations.replies", params)
        if not data["ok"]:
            raise HTTPException(
                status_code=400, detail=f"conversations.replies failed: {data}"
            )
        msgs.extend(data.get("messages", []))
        cursor = data.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break
    return msgs


async def delete_message(token: str, channel: str, ts: str) -> dict[str, Any]:
    """Deletes the given message."""
    for i in range(3):
        res = await slack_api_post(token, "chat.delete", {"channel": channel, "ts": ts})
        if not res["ok"] and res["error"] in {"internal_error", "ratelimited"}:
            time.sleep(2**i)
            continue
        return res
    return res  # pyright: ignore [reportPossiblyUnboundVariable]


async def delete_thread(token: str, channel: str, ts: str) -> int:
    """Deletes all messages from the given thread in reverse chronological order."""
    num_deleted = 0
    msgs = await get_thread_messages(token, channel, ts)
    for msg in sorted(msgs, key=lambda x: float(x["ts"]), reverse=True):
        res = await delete_message(token, channel, msg["ts"])
        if res["ok"]:
            num_deleted += 1
    return num_deleted


@app.get("/")
def home() -> HTMLResponse:
    return HTMLResponse("<a href='/slack/install'>Install Thread Nuker</a>")


@app.get("/slack/install")
def slack_install(req: Request) -> RedirectResponse:
    redirect_uri = f"{req.base_url}slack/oauth_redirect"
    scope = ",".join(
        [
            "channels:history",
            "chat:write",
            "groups:history",
            "im:history",
            "mpim:history",
            "users:read",
        ]
    )
    return RedirectResponse(
        f"{OAUTH_AUTHORIZE_URL}"
        f"?client_id={os.getenv('SLACK_CLIENT_ID')}"
        f"&redirect_uri={redirect_uri}"
        f"&scope={scope}"
        f"&user_scope={scope}"
    )


@app.get("/slack/oauth_redirect")
async def oauth_redirect(req: Request) -> HTMLResponse:
    code = req.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")
    redirect_uri = f"{req.base_url}slack/oauth_redirect"
    team_id, user_id, user_token = await do_oauth_exchange(code, redirect_uri)
    save_user_token(team_id, user_id, user_token)
    return HTMLResponse("OK")


async def delete_thread_and_respond(
    token: str, channel: str, ts: str, response_url: str
) -> None:
    num_deleted = await delete_thread(token, channel, ts)
    async with httpx.AsyncClient() as client:
        await client.post(
            response_url,
            json={
                "response_type": "ephemeral",
                "text": f"Deleted {num_deleted} messages.",
            },
        )


@app.post("/slack/interactive")
async def interactive(req: Request, background: BackgroundTasks) -> JSONResponse:
    body = await req.body()
    verify_slack_signature(req, body)
    form = await req.form()
    payload_str = form["payload"]
    if not payload_str:
        raise HTTPException(status_code=400, detail="Missing payload")
    assert isinstance(payload_str, str)
    payload = json.loads(payload_str)
    if (
        payload["type"] != "message_action"
        or payload["callback_id"] != "nuke_thread_action"
    ):
        raise HTTPException(status_code=400, detail=f"Unexpected payload: {payload}")

    team_id = payload["team"]["id"]
    user_id = payload["user"]["id"]
    channel = payload["channel"]["id"]
    ts = payload["message"]["thread_ts"] or payload["message"]["ts"]
    response_url = payload["response_url"]

    token = get_user_token(team_id, user_id)
    if not token:
        return JSONResponse(
            {"response_type": "ephemeral", "text": "Missing user token."}
        )
    if not await is_admin(token, user_id):
        return JSONResponse({"response_type": "ephemeral", "text": "Not an admin."})

    background.add_task(delete_thread_and_respond, token, channel, ts, response_url)
    return JSONResponse({"response_type": "ephemeral", "text": "Deleting thread..."})


def main() -> None:
    dotenv.load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
