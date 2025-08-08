# slack-thread-nuker

## Usage

```
uv run -w cryptography,dotenv,flask,requests,slack_sdk nuke_slack_thread.py --thread=https://microsoft-ai.slack.com/archives/C09A85QAW0G/p1754623024351449
```

## Development

```
uvx ruff format .
uvx ruff check --select E,F,I,PLC,PLE,UP --fix-only --target-version py313 .
uvx pyright nuke_slack_thread.py
```
