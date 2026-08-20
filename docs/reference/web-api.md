# Local Web API Reference

The MTScan web API is a same-origin API used by the local dashboard. It is an **alpha interface**, not a stable public remote API.

Default base URL:

```text
http://127.0.0.1:8765
```

## Authentication model

- Session-cookie authentication.
- Default username: `admin`.
- First-run password: cryptographically random and printed to the local server console when auth state is initialized.
- Password change is mandatory before normal protected API use.
- Sessions are held in server memory and expire after approximately 12 hours.
- Non-loopback serving requires `--allow-remote` and changes the threat model.

## Request constraints

- JSON request bodies should use `Content-Type: application/json`.
- Maximum request body: 64 KiB.
- Host headers are checked against the server's allowed host set.
- Protected responses are no-store and include defensive browser headers.

## Endpoints

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| `GET` | `/api/session` | no | Current authentication state |
| `POST` | `/api/login` | no | Authenticate and set session cookie |
| `POST` | `/api/logout` | session if present | End session |
| `POST` | `/api/change-password` | yes | Change current password |
| `GET` | `/api/overview` | yes | Dashboard aggregate data |
| `GET` | `/api/health` | yes | Platform, scanner, and storage health |
| `GET` | `/api/scans` | yes | Scan history |
| `POST` | `/api/scans` | yes | Create scan job |
| `GET` | `/api/scans/{scan_id}` | yes | Scan status/result |
| `GET` | `/api/schedules` | yes | List schedules |
| `POST` | `/api/schedules` | yes | Create schedule |
| `GET` | `/api/schedules/{schedule_id}` | yes | Read schedule |
| `PATCH` | `/api/schedules/{schedule_id}` | yes | Update schedule |
| `DELETE` | `/api/schedules/{schedule_id}` | yes | Delete schedule |
| `POST` | `/api/schedules/{schedule_id}/run` | yes | Run schedule immediately |

Other PUT/OPTIONS operations are not supported by the current API.

## Create a scan

Example JSON body:

```json
{
  "target": "https://target.example",
  "mode": "chain",
  "profile": "default",
  "dry_run": false,
  "json_output": true,
  "options": {
    "severity": "critical,high,medium"
  }
}
```

Supported modes are `chain`, `naabu`, `httpx`, and `nuclei`. Built-in profiles are `default`, `fast`, `stealth`, and `deep`.

The response returns a 12-character scan ID and the current job state. Poll `GET /api/scans/{scan_id}` for completion.

## Create a schedule

Schedules contain a name, target, mode, profile, options, interval in hours, enabled state, dry-run state, and structured-output state. Schedule IDs are 12-character lowercase hexadecimal strings.

## Status behavior

Typical HTTP status codes include:

- `200` successful read/update/login.
- `201` scan or schedule created.
- `400` invalid JSON, target, option, or password-change request.
- `401` authentication required or invalid login.
- `403` host rejected or password change required for protected API use.
- `404` scan/schedule/endpoint not found.
- `409` schedule conflict, such as a schedule already running.

## Stability

No compatibility guarantee is made for this API until a stable API version is documented. Automation should pin an MTScan release and validate response fields after upgrades.
