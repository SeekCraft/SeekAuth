# SeekAuth Feature Inventory

> This document collects every feature the project **currently implements**, matching the real state of the code.
> Last verified: 2026-10-16 (commit `1e9fb34`).

## 1. What the Project Is

A **third-party verification server** for NetEase's *Minecraft*. It gives the FateArk client:

1. **Protocol-layer verification** — replaces NetEase's official verification; the client performs login and server-transfer checks using local key pairs
2. **Account system** — email registration/login plus NetEase account binding (sauth cookie / MPay guest account)
3. **Operations API** — `/api/admin/*`: overview / sessions / cache / audit / announcements / logs / settings
4. **User-center API** — `/api/uc/*`: self-service queries for join history, skins, and bot status

Stack: Python 3.11+ · FastAPI · aiosqlite · orjson · PyJWT · managed with uv

**Backend only**: this repository ships no frontend artifacts. `/panel`, `/uc`, `/uc/login` and `/uc/register`
uniformly return 501 plus a JSON explanation; the frontend (Vue 3 + mcui-oreui) lives in a separate project,
and any HTTP client or home-grown frontend can call these endpoints directly.

---

## 2. Core Feature Modules

### 2.1 Protocol verification layer (`routes.py`, `crypto.py`, `rotor.py`, `checknum.py`, `pymarshal.py`)

The key pieces that replace NetEase's g79 protocol verification:

| Endpoint | Purpose |
|---|---|
| `POST /init` | Client initialization: pushes server config, line selection and salt |
| `POST /rental-game/get-login-info` | **Rental-server login info** (the core): issues the multiplayer address and auth state to the client |
| `POST /domain-game/get-login-info` | **Domain-server login info** (the same thing on the other product line) |
| `GET /common/transfer-start-type` | Query the server-transfer start type |
| `POST /common/transfer-check-num` | Generate and validate the server-transfer check code |

Underlying capabilities:

- **RSA signing/verification** — `keys/server_private.pem` (server) + `keys/client_private.pem` (client), with compact-token ↔ full-cookie mapping (`keys/fbtokens.json`)
- **Rotor obfuscation** — `rotor.py`: reversible scrambling of protocol fields, combined with linepick line selection to evade risk-control fingerprinting
- **Compact check code** — `checknum.py`: compresses long numbers into short strings (sent as `check_num` in the protocol)
- **pymarshal** — in-house binary serialization (1877 lines) modelled on Go's `encoding/gob`, used for compact token encoding and decoding
- **Login-state cache** — two tables, `sessions` + `login_cache`; a cache hit is served directly without going to NetEase

### 2.2 Account system (`usercenter.py`, `db.py`)

| Endpoint | Function |
|---|---|
| `POST /api/uc/config` | Frontend bootstrap config (whether token login is enabled, etc.) |
| `POST /api/uc/register` | Email registration |
| `POST /api/uc/send-code` | Send the email verification code (60-second cooldown) |
| `POST /api/uc/login` | Login: password **or** token (token can be disabled by config) |
| `POST /api/uc/logout` | Logout |
| `GET /api/uc/profile` | Profile (nickname/level/uid/binding state) |
| `GET /api/uc/account` | Account details (email/bound uid/bot info) |
| `POST /api/uc/password` | Change password (current password required) |
| `GET /api/uc/announcements` | Announcement list |
| `GET /api/uc/recent-logins` | Recent login records |
| `POST /api/uc/heartbeat` | Keep-alive heartbeat (refreshes the NetEase login state) |

Security design:

- Passwords stored with **PBKDF2-SHA256** (200,000 iterations, 16-byte salt)
- **JWT sessions** (`_SESSION_TTL=1800`, random 32-byte key by default, pinnable with `SEEK_UC_SESSION_KEY`)
- **HMAC constant-time comparison** (`hmac.compare_digest`) for admin tokens and sessions
- **Login/session audit** written to the `audit_log` table

### 2.3 NetEase account binding (`usercenter.py`, `g79.py`, `mpay.py`)

**Two binding paths**:

| Path | Endpoint | Notes |
|---|---|---|
| Paste a Cookie | `POST /api/uc/bind-uid` | Feed in a sauth cookie or a bare token directly (fastest, risk-control friendly) |
| Auto-generate | `POST /api/uc/bind/generate` | Create a NetEase guest account through the MPay guest channel |

Key engineering details (all of them hardening after hitting real problems):

- **MPay guest channel**: `register_device` → `create_guest` → `build_sauth_cookie`; the resulting sauth is handed straight to G79 for the login-token exchange
- **MPay device-fingerprint carry-over**: `_mpay_pending` with a 1800-second TTL; risk-control retries reuse the same device (otherwise they loop forever)
- **Pending binding state**: once the guest account has been generated it is parked as `pending`, and the account is only really created after the user supplies email/password — no half-built accounts
- **Credential shape tolerance**: sauth accepts both the wrapped string `{"sauth_json": ...}` and bare JSON

**NetEase credential management after binding**:

- `uc_users.bound_session` stores the long-lived credential (`entity_id|token`, `G79Client.dump_session/load_session`)
- `_client_for_account` precedence: g79 cache → `bound_session` → `bound_token` → `bound_cookie`
- **Single sign-on guard**: only one active client per credential for the whole process (otherwise code 22, "account logged in elsewhere")

### 2.4 Bot status and skins (`usercenter.py`, `g79.py`)

| Endpoint | Function |
|---|---|
| `GET /api/uc/bot-status` | Bot status: nickname/level/skin count/real-name state/online state (DB-cached; `refresh=1` forces a refresh) |
| `POST /api/uc/bot-name` | Change the bot nickname (leave it blank to auto-generate `Seek` + 5 random characters) |
| `GET /api/uc/skin` | **Skin lookup**: `pe-get-user-setting-list` → `skin_data.item_id` → `search-by-id-list` to resolve the image URL |
| `GET /api/uc/cookie` | Fetch the sauth cookie of the currently bound account |
| `POST /api/uc/transfer-out` | Transfer out of a server |
| `POST /api/uc/start` | Start/enter the game |

The skin implementation has been aligned against **traffic captured from the real official client** (`skin_data.item_id` negative = built-in system skin, positive = item skin).

### 2.5 User-center endpoint groups (`/api/uc/*`)

Grouped by capability into four sets; the frontend pages are the consumers of these endpoints:

| Group | Endpoints | Notes |
|---|---|---|
| Account | `/register`, `/login`, `/logout`, `/send-code`, `/password` | Email + password (PBKDF2); token login can be turned off with `SEEK_UC_ALLOW_TOKEN_LOGIN` |
| Profile | `/profile`, `/account`, `/bot-name`, `/bot-status`, `/skin`, `/cookie`, `/fbtoken` | Nickname/level/uid/avatar, bot status and skins |
| Rental server | `/rental-servers`, `/recent-logins`, `/start`, `/transfer-out`, `/heartbeat` | List, recent visits, start and heartbeat keep-alive |
| Binding | `/bind-uid`, `/bind/generate` | Paste a sauth cookie; or auto-create an account via the MPay guest channel |

Binding state machine: "unbind" is rejected while unbound; while bound, "bind" is rejected with the hint "unbind first if you want to switch";
when `need_realname` is true the endpoint returns guidance for completing real-name verification (this service never collects ID numbers).

### 2.6 Operations API (`/api/admin/*`)

Bearer-token auth (`hmac.compare_digest`, `SEEK_ADMIN_TOKEN`; everything returns 401 when it is unset).
A missing frontend does not affect the API itself; 14 handlers cover:

| Capability | Endpoints | Notes |
|---|---|---|
| Overview | `/overview` | Session count/online count/cache hits/recent audit |
| Sessions & cache | `/sessions`, `/login-cache`, `/purge-cache` | Current login sessions, cache details, cache purge |
| Audit | `/audit` | Operation audit log |
| Announcements | `/announcements` (GET/POST), `/announcements/{aid}` (PUT/DELETE) | Atomic writes: tempfile + `os.replace` |
| Logs | `/logs/files`, `/logs/content` | File switching + tail from the end (1..5000 lines, 2MB chunk seek reads, directory-traversal safe) |
| Settings | `/settings` (GET/PUT), `/email-test` | 17 fields edited online and reloaded (type guards + `log_level` allow-list), send a test email |

Two settings-rewrite pitfalls are already fixed: the `config.get_settings()` singleton and the
`app.state.seek.settings` snapshot **both** have to be written, otherwise the echo does not change;
pydantic `validate_assignment` is off by default, so type guards have to be done by hand.

### 2.7 Operational foundations

| Capability | Implementation |
|---|---|
| **Logging** | `logging_setup.py`: three-layer logger + async queue (`_QueueListener`) + rotating files (10MB × 5) + a separate error.log |
| **Error handling** | Global exception handler → readable JSON message; `G79Error`/`UpstreamError`/`MpayError` custom exception family; `contextlib.suppress` for exactly the ignorable OS errors |
| **Performance** | orjson emits bytes directly (`json_response`); gzip responses; aiosqlite async DB; in-memory login-state cache |
| **Low footprint** | single-process asyncio; no external services (SQLite is embedded); log tails are seek-read so whole files never enter memory |
| **Configuration** | `.env` + pydantic `BaseSettings`, 17 fields hot-editable at runtime |

---

## 3. API Endpoint Inventory (43 paths)

```
Protocol layer (public, called by the client)     5
  POST /init
  POST /rental-game/get-login-info
  POST /domain-game/get-login-info
  GET  /common/transfer-start-type
  POST /common/transfer-check-num

User center /api/uc/*                             21 (unique paths, 22 handlers)
  GET  /config                     POST /register
  POST /login                      POST /send-code
  POST /logout                     GET  /profile
  GET  /rental-servers             GET  /recent-logins
  POST /transfer-out               POST /start
  GET  /announcements              GET  /account
  POST /password                   POST /bind-uid
  POST /bind/generate              POST /bot-name
  GET  /skin                       POST /heartbeat
  GET  /cookie                     GET  /bot-status
  GET  /fbtoken

FateArk integration points (plaintext REST)       4
  GET  /api/new                    POST /api/phoenix/login
  GET  /api/phoenix/transfer_start_type
  POST /api/phoenix/transfer_check_num

Noah's Ark (AES-encrypted protocol)               6
  POST /api/noahs-ark/init         POST /api/noahs-ark/rental-game/get-login-info
  POST /api/noahs-ark/domain-game/get-login-info
  POST /api/noahs-ark/lobby-game/get-login-info
  GET  /api/noahs-ark/common/transfer-start-type
  POST /api/noahs-ark/common/transfer-check-num
  (+ /health)

Operations API /api/admin/*                        11 (unique paths, 14 handlers)
  GET  /overview                   GET  /sessions
  GET  /login-cache                GET  /audit
  POST /purge-cache                POST /email-test
  GET  /settings                   PUT  /settings
  GET  /announcements              POST /announcements
  PUT  /announcements/{aid}        DELETE /announcements/{aid}
  GET  /logs/files                 GET  /logs/content
```

6 data tables: `sessions`, `login_cache`, `audit_log`, `uc_users`, `uc_email_codes`, `uc_mpay_devices`

> Endpoint counting basis: **number of unique paths** (`grep '^@router\.' | awk -F'"' '{print $2}' | sort -u`).
> In the operations API, `/announcements`, `/announcements/{aid}` and `/settings` each carry
> several methods (GET/POST/PUT/DELETE), hence 14 handlers over 11 paths;
> the user center's `/bot-name` used to be defined twice and has been cleaned up (handlers 23 → 22).

---

## 4. Quality Gates (currently all green)

```bash
uv run ruff check .        # All checks passed
uv run mypy src            # 0 errors (24 source files)
uv run pytest -q           # 85 passed, 7 skipped
uv run python tests/verify_g79_against_go.py   # 188/188 matches the Go reference implementation
                           # (SEEK_GO_REF_DIR must point at the Go repo containing diag/g79vectors.go)
```

Test coverage: `test_protocol` (protocol), `test_admin` (operations API), `test_usercenter` (UC, including auth isolation),
`test_bind_flow` (binding and MPay flows, both using stand-ins), `test_crypto_vectors` / `test_rotor_vectors` /
`test_linepick` / `test_checknum` (algorithm vectors).

---

## 5. Reverse-Engineering Results (`docs/mc-official-api-notes.md`)

Captured and reverse-engineered on 2026-10-16 against the official Android MC build (PE) with mitmproxy + the MuMu emulator. Results:

- **§6.1~6.23**: g79 gateway authentication, the full 34-endpoint rental-server family, three-line BGP routing on server join, user details,
  pets, heartbeat/anti-addiction, avatar and skin write endpoints, the personal-homepage family
- **§6.24**: the complete re-login handshake + **the truth about user-token** (derived deterministically, not random)
- **§6.25**: localizing `libminecraftpe.so` by disassembly (`nativeEncryptToken @ 0x5F12178`)
- **§6.26**: correction — **the user-token algorithm had been implemented all along** (`calculate_dynamic_token`, cross-verified 10/10 against Go)
- **§8**: item-by-item comparison of our implementation against the official endpoints (aligned/fixed/added/unsolvable)
- `src/seek_auth/mc_api.py`: routing table for the 88 official endpoints (including `hostName` domain hints)

---

## 6. Known Limitations

1. **No self-service password login** — only "paste a sauth cookie" and "MPay guest account" are offered.
   With the new `env` encryption chain and device fingerprinting there is no stable implementation of the password flow.
2. **The three uid systems are not fully bridged** — no mapping endpoint has been captured between `3100073113` (MC gateway) /
   `952589465` (NetEase account) and the internal channel uid.
3. **`pe-user-detail/get` is still the old version** — `query_user_detail_other` (the endpoint the official client actually uses) has been added,
   but old paths such as `refresh_user_detail` have not been switched over.
4. **`User-Agent` is still `WPFLauncher/0.0.0.0`** — the real client sends `libhttpclient/1.0.0.0`;
   it was left as is because it keeps working.

---

## 7. Directory Layout

```
seek-auth/
├── src/seek_auth/
│   ├── routes.py          protocol endpoints (init/rental/domain/transfer)
│   ├── usercenter.py      user center, 21 endpoints + binding state machine
│   ├── admin.py           admin API, 14 endpoints
│   ├── g79.py             NetEase g79 client + user-token algorithm (2304 lines)
│   ├── mpay.py            MPay guest channel
│   ├── db.py              6 tables + lightweight migrations
│   ├── models.py          Pydantic models
│   ├── mc_api.py          routing table for 88 official endpoints ★new
│   ├── mc_token.py        user-token RE conclusions, frozen ★new
│   ├── crypto/rotor/checknum/pymarshal/linepick   protocol algorithms
│   ├── logging_setup.py   logging system
│   └── static/            swagger-ui assets + logo (backend only, no SPA)
├── tests/                 90+ cases + Go cross-verification script
├── docs/
│   ├── mc-official-api-notes.md   MC official API RE notes (1189 lines)
│   ├── FEATURES.md                this document ★new
├── keys/                  RSA private keys + token mapping (not committed)
├── data/                  announcements.json (committed) + *.db (runtime)
└── logs/                  rotating logs (not committed)
```
