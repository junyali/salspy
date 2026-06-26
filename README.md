# salSPY

**Slack Audit Log SPY**

A tool for reading and parsing Slack Enterprise Grid audit log exports.

## Features

- Import Slack audit log exports (NDJSONs)
- Deduplicate and aggregate events on import
- Search by IPv4 address to list observed records
- Filter results by audit action type

## Using salSPY

salSPY can be launched via the GUI or the CLI. Download the latest binaries from [releases](https://github.com/junyali/salspy/releases/latest).

### Using the CLI

| Command              | Description                                |
|----------------------|--------------------------------------------|
| `salspy-cli import`  | Import audit log files                     |
| `salspy-cli search`  | Search for an IPv4 address                 |
| `salspy-cli count`   | Output total number of observations        |
| `salspy-cli actions` | List distinct action types in the database |
| `salspy-cli clear`   | Clear all database records                 |

Run `salspy-cli help` to see all available commands, or `salspy-cli help <command>` for detailed help on a specific command.

## Input format

The tool expects Slack Enterprise Grid audit log exports in the NDJSON format. Files should contain one JSON object per line.

Example format (see the [Slack docs](https://docs.slack.dev/admins/audit-logs-api/) for reference)

```json
{
  "id": "0123a45b-6c7d-8900-e12f-3456789gh0i1",
  "date_create": 1521214343,
  "action": "user_login",
  "actor": {
    "type": "user",
    "user": {
      "id": "W123AB456",
      "name": "Charlie Parker",
      "email": "bird@slack.com"
    }
  },
  "entity": {
    "type": "user",
    "user": {
      "id": "W123AB456",
      "name": "Charlie Parker",
      "email": "bird@slack.com"
    }
  },
  "context":{
    "location": {
      "type": "enterprise",
      "id": "E1701NCCA",
      "name": "Birdland",
      "domain": "birdland"
    },
    "ua": "Mozilla\/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/64.0.3282.186 Safari\/537.36",
    "session_id": "847288190092",
    "ip_address": "1.23.45.678"
  }
}
```

Accepted file extensions: `.ndjson`, `.json`, `.jsonl`, `.txt`

## Configuration

Settings are stored in `~/.config/salspy/settings.toml`. You can edit this file directly or use the GUI settings panel.

```toml
backend = "sqlite"
db_folder = ""
db_name = "audit.db"
safe_writes = true
batch_size = 10000
postgres_host = "localhost"
postgres_port = "5432"
postgres_user = "postgres"
postgres_dbname = "audit"
```

## Building from source

**Requirements:**
- Rust (2024 edition or later)
- (Linux) Development headers for keyring support (`libdbus-1-dev` or `libsecret-1-dev`)

**Build:**

```console
# Build all
$ cargo build --release

# Build only the CLI
cargo build --release -p salspy-cli

# Build only the GUI
cargo build --release -p salspy-gui
```

Binaries are written to `target/release/`.
