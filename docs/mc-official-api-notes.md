# NetEase MC (x19/g79) Official API Gateway — Capture Intelligence

> Source: MuMu emulator (Android 15) + mitmproxy, capturing the official NetEase Minecraft Android client (PE)
> Login account: a real-name-verified NetEase account (character nickname `Seek4W9FP`)
> Capture date: 2026-10-16
> Goal: obtain the endpoints the seek-auth user center needs for "user info / skins / avatars / rental servers"

---

## 0. Conclusions at a Glance

| Need | Official endpoint | Status |
|---|---|---|
| Basic user info | `pe-get-user-achievement-basic-info` | ✅ captured |
| **Skin data** | **`pe-get-user-setting-list`** (`skin_data`/`skin_type`/`persona_data`) | ✅ captured |
| **Avatar library** | **`user-head-url-v2`** | ✅ captured |
| Backpack items | `user_bag/query_user_bag` | ✅ captured |
| **Rental servers** | **`my-rental-server/query/search-by-user`** | ✅ captured |
| Currency | `user-currency-new/query`, `get-currency-online/` | ✅ captured |
| Phone binding state | `mobile-bind-status` | ✅ captured |
| Friends | `user-addme-friends/`, `friend-ship/intimacy-apply-list` | ✅ captured |
| Mail | `get-general-mail-list/` | ✅ captured |
| Achievements | `pe-get-user-achievement-basic-info` | ✅ captured |

**All of these endpoints share one set of auth headers and one response format**; see below.

---

## 1. Authentication (the key part)

Three request headers, **no cookies, no signatures**:

| Header | Meaning | Observed value |
|---|---|---|
| `user-id` | NetEase uid of the current login | `3100073113` |
| `user-token` | **17 characters, different on every request** (derived from the long-lived login token, see §6.25) | `mTSrKHj7qyh4OHx41` |
| `x_trace_id` | **32 random characters, different on every request** | `Jt0MXeKRfe3VhWoTocwpScpHQTl5LczH` |

Other fixed headers:
```
User-Agent: libhttpclient/1.0.0.0
Content-Type: application/json
Host: g79apigatewayobt.minecraft.cn
Connection: Keep-Alive
accept-encoding: gzip
```

**`user-token` is different on every request**, but it is **not** a random or one-shot token — it is
the deterministic output of `calculate_dynamic_token(long-lived login token, url, body)` (same input, same output).
The algorithm **was implemented in the project long ago** (`g79.py`, a character-for-character port of the g79client Go code); see §6.25.
- The captured `user-id=3100073113` is **different** from the uid `952589465` of the bound account — `user-id` is the uid MC rebuilds on its side (an account system created on the channel side), not the NetEase Passport uid.
- The long-lived login `token` comes from `entity.token` in the g79 auth response (`self.user_token` at `g79.py:1076/1698`).

### Response format

```json
{"code":0,"message":"OK","details":"","entity":{...}}
```

List endpoints use `entities` + `total`:
```json
{"code":0,"message":"OK","details":"","entities":[],"total":0}
```

Response headers carry debugging information (usable for latency monitoring):
```
Server-Time / Server-Activity-Time
Start-Exec-Time / End-Exec-Time      ← server-side processing time (ms, measured 12~35ms)
ntes-trace-id: <32hex>:<32hex>:0:1
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 1800
```

---

## 2. Endpoint by Endpoint

### 2.1 Basic user achievement info

```http
POST https://g79apigatewayobt.minecraft.cn/pe-get-user-achievement-basic-info
Content-Type: application/json

{"query_other_uid": 0}
```

- `query_other_uid = 0` queries yourself; **non-zero queries another user** (this is what `/user/info?UID=xxx` in `nv1-openapi.txt` relies on).

Response:
```json
{"code":0,"message":"OK","details":"","entity":{
  "achievement_score":"10",
  "current_medal_id_list":[],
  "score_reward_got_times":[]
}}
```

### 2.2 Skin / persona / settings (core)

```http
POST https://g79apigatewayobt.minecraft.cn/pe-get-user-setting-list
Content-Type: application/json

{"settings": ["skin_type", "skin_data", "persona_data", "screen_config",
              "outfit_type", "personal_open", "personal_ad_open",
              "personal_tags", "bag_item"]}
```

`settings` is an **array of fields queried on demand**; the server returns only the requested keys.

Response (recorded from this account, no skin equipped):
```json
{"code":0,"message":"OK","details":"","entity":{
  "skin_type":{},
  "skin_data":{"item_id":"-1"},
  "persona_data":{},
  "screen_config":{},
  "outfit_type":{},
  "personal_open":{"resRecommend":1},
  "personal_ad_open":{"adRecommend":1},
  "personal_tags":{"tags":["all"]},
  "bag_item":{}
}}
```

**Field interpretation**:
| Key | Meaning | Meaning of `-1` / `{}` |
|---|---|---|
| `skin_data.item_id` | Item id of the current skin | `-1` = default skin (Steve) |
| `skin_type` | Skin type | empty = nothing customised |
| `persona_data` | persona (appearance/actions) | empty = default |
| `outfit_type` | Outfit type | empty = no outfit |
| `screen_config` | Personal-homepage display config | empty |
| `personal_tags` | Personal tags | `["all"]` = everything |

**This is the official source behind `/user/skin` in `nv1-openapi.txt`.** If seek-auth is to display a user's skin, it should switch to calling this endpoint for `skin_data.item_id`, then use the item library `pe-item/query/search-by-id-list` to resolve it into an image URL.

### 2.3 Avatar library

```http
POST https://g79apigatewayobt.minecraft.cn/user-head-url-v2
Content-Type: application/json

{}
```

Response: an `entities` array, **107 entries** measured (7280 bytes). Each entry looks like:

```json
{
  "id": 1,
  "type": 0,                  // 0 = static avatar, 1 = animated avatar (gif)
  "url":   "https://x19.fp.ps.netease.com/file/65b8bb7ed52cfea63bc3a9e4MH5cJO2q05",
  "pc_url":"https://x19.fp.ps.netease.com/file/65b8bb7ed52cfea63bc3a9e4MH5cJO2q05",
  "static_url": "",
  "tips": "Xuanyuan Dragon Spirit animated avatar",
  "name": "Xuanyuan Dragon Spirit",
  "status": 0,                // 0 = not owned, 1 = owned
  "first_type": 200,
  "item_id": 2000001,
  "item_name": "Static Avatar",
  "jump_type": "Skins.Illustration",
  "jump_target": "1_3",
  "is_gif": 0
}
```

**Image CDN domain: `https://x19.fp.ps.netease.com/file/<fileid>`**
(`fileid` looks like `65b8bb7ed52cfea63bc3a9e4MH5cJO2q05`, a 24+ character mixed string)

Note: the `status` field distinguishes **owned / not owned** (for this account every animated avatar is `0` = not owned and every static avatar is `1` = owned).

### 2.4 Backpack items

```http
POST https://g79apigatewayobt.minecraft.cn/user_bag/query_user_bag
Content-Type: application/json

{"length": 100, "first_type": 214, "offset": 0}
```

- `first_type`: first-level item category (`214` is the category this account was queried with; avatars and skins presumably each have their own id)
- `length` + `offset`: pagination

Response:
```json
{"code":0,"message":"OK","details":"","entity":{"items":[],"total":0}}
```

### 2.5 Rental servers (directly relevant to seek-auth)

```http
POST https://g79apigatewayobt.minecraft.cn/my-rental-server/query/search-by-user
Content-Type: application/json

{"length": 10, "offset": 0}
```

Response (this account owns no rental server):
```json
{"code":0,"message":"OK","details":"","entities":[],"total":0}
```

- **`entities[]` is expected to be an array of rental-server objects** (empty for this account, so no entity sample could be obtained; needs re-capturing with an account that owns a rental server).

### 2.5.1 The full rental-server endpoint family (completed, see section 6)

> ⚠ The previous note "no entity sample obtained" was resolved by later captures: the entity structure is in **§6.1**, the join endpoint in **§6.2**.

### 2.6 Currency

```http
POST https://g79apigatewayobt.minecraft.cn/user-currency-new/query
{}
```

```http
POST https://g79apigatewayobt.minecraft.cn/get-currency-online/
{}
```

`get-currency-online` response as recorded:
```json
{"code":0,"message":"OK","details":"","entity":{
  "rest_currency_time":3343,
  "date":"2026-10-16 13:27:08"
}}
```
→ `rest_currency_time` is presumably "remaining game time (seconds)", and `date` is **server local time** (consistent with the `server-time` response header).

### 2.7 Phone binding state

```http
POST https://g79apigatewayobt.minecraft.cn/mobile-bind-status
{}
```
Response:
```json
{"code":0,"message":"OK","details":"","entity":{"is_bind":false,"has_mobile_num":false}}
```

### 2.8 Friends

```http
POST https://g79apigatewayobt.minecraft.cn/user-addme-friends/      // friend requests addressed to me
POST https://g79apigatewayobt.minecraft.cn/friend-ship/intimacy-apply-list  // intimacy request list
```

### 2.9 Other endpoints seen (not examined closely)

| Endpoint | Presumed purpose |
|---|---|
| `home-shop-all` | Homepage shop |
| `home-get-user-pet-detail` | Pet details |
| `get-general-mail-list/` | Mail list |
| `user-chat-bubble-get` | Chat bubbles |
| `activity_task/get_task_info` | Event quests |
| `new_activity_center/get_info`, `get_bubble` | Activity centre |
| `user-guide-new/get`, `user-guide-new/skip-group` | New-player guidance |
| `pe-season-mod/search-season-mods` | Season mods |
| `pe-item/query/lib-item-tags` | Item tag library (GET) |
| `pe-item/query/search-by-id-list` | Batch item lookup by id |
| `pe-item/water_fall` | Item waterfall feed |
| `pe/web/popup-window/query_horizontal_v2` | Popup promotion slots |
| `online-lobby/query/feeds` | Multiplayer lobby feeds (paginated recommendation stream) |
| `lottery/new/portrait/activity/user-lottery-info(-list)` | Lottery-event avatars |
| `pe-get-user-setting-list` | see 2.2 |
| `salog`, `salog-new`, `salog/login-ui` | Analytics reporting |
| `server-time` | Server time (GET) |

---

## 3. Multiplayer Lobby / Server List

```http
POST https://g79apigatewayobt.minecraft.cn/online-lobby/query/feeds
{"current_index": 16, "scene": "hot", "last_exposed": "[\"4684007218039332223\", ...]"}
```

- `scene`: `hot` (popular)
- `last_exposed`: **the list of server ids already exposed (as a JSON string)**; the server de-duplicates against it and returns a fresh batch → this is the **infinite-scroll pagination** mechanism
- response `entity.res`: the next batch of 16 server ids (numeric strings)

Server entity details have a separate endpoint (not captured; requires tapping into a specific server).

---

## 4. Correspondence with nv1-openapi.txt

`nv1.aetheredge.top` is a **third-party relay** that wraps the official NetEase endpoints in one more layer:
- Its own paths (`/user/info`, `/user/skin`, `/rapid/login`, `/masterserver`, `/query_mc_version`, `/netgame/g79/get_server_list`) are its own custom shell
- **What it actually forwards is exactly the `g79apigatewayobt.minecraft.cn/*` and g79 protocol endpoints documented in this file**
- It also swaps authentication for `authorization: <uuid>` + `X-Caller: gameaccount|helperbot`

**What this means for our project**: every capability in `nv1-openapi.txt` (account info, skins, rental servers/online play, server hosting) has a corresponding official endpoint on the NetEase side; but the custom UDP/TCP protocol it uses (`1001/1002/1003/1005/9/51/404/1004/1011/1012`) is a **self-built forwarding channel**, not the same thing as the official HTTP endpoints.

---

## 6. Rental Server — the Complete Endpoint Family

> Captured live on 2026-10-16 while the user entered a rental server from "recent visits"
> (`entity_id=4658680138770108095`, `owner_id=2492760332`, display name "Happy♂Light's server", internal name `48285363`).

Every endpoint is `POST https://g79apigatewayobt.minecraft.cn/...` (unless noted), with the same three
auth headers (`user-id` / `user-token` / `x_trace_id`) and the uniform response `{"code":0,"message":"OK","details":"", ...}`.

### 6.1 Rental server listing and queries

| Endpoint | Request body | Notes |
|---|---|---|
| `/rental-server/query/available-by-sort-type` | `{"sort_type":0,"order_type":0,"offset":0}` | Random recommendation list, measured `total:"12246"` (a string), 30 records per call |
| `/rental-server/query/recent-visit-server` | `{"offset":0}` | Recently visited servers |
| `/my-rental-server/query/search-by-user` | `{"length":10,"offset":0}` | **Your own** rental servers (empty for this account) |
| `/rental-server/query/search-by-name` | `{"server_name":"48285363","offset":0}` | Search by internal server name |
| `/rental-server-details/get` | `{"server_id":"..."}` | Server details; **the domain is `g79mclobt.minecraft.cn`, the Content-Type is `text/plain`, and there is no `x_trace_id` header** |

**Complete rental-server entity fields** (30 real samples, from `available-by-sort-type`):

| Field | Type | Observed value | Notes |
|---|---|---|---|
| `entity_id` | string (19 digits) | `"4691213040660085432"` | Unique server id |
| `name` | string (digits) | `"56030476"` | Internal server name (generated at creation) |
| `owner_id` | int | `3100098107` | Owner uid (**returned as the string `"2492760332"` by `rental-server-details/get` — type mismatch**) |
| `visibility` | int | `0` | Visibility |
| `status` | int | `1` | 1 = running |
| `icon_index` | int | `1`~`5` | Server icon (5 variants on the client) |
| `capacity` | int | `4`/`10`/`20`/`40` | Player cap |
| `mc_version` | string | `"1.21.120-release"` | MC version |
| `player_count` | int | `0`~`34` | Players currently online |
| `like_num` | int | `0`~`54` | Like count |
| `server_type` | string | `"docker_new_guian"` | Server type (fixed value) |
| `offset` | int\|null | `0`/`null` | Pagination offset (null from some endpoints) |
| `has_pwd` | **string** | `"0"`/`"1"` | **Whether the server has a password — a string, not a boolean** |
| `image_url` | string | `https://g79-3.fp.ps.netease.com/file/<id>` | Cover image (**a different CDN from the avatar one, `x19.fp.ps.netease.com`**) |
| `world_id` | string (21 chars) | `"mrzpscdcqpsq3dj9fr9jfa"` | World id |
| `min_level` | int\|string | `0`/`25`/`"0"` | Level requirement (**inconsistent between endpoint types**) |
| `pvp` | bool | `true`/`false` | Whether PVP is enabled |
| `server_name` | string | `"Permanent Casual Survival's server"` | Display name (**empty string `""` from `recent-visit-server`**) |
| `brief_summary` | string | `""` | Description |

> ⚠ **Field types are inconsistent between endpoints** (`owner_id` and `min_level` are sometimes numbers and sometimes strings; `has_pwd` is always a string), so parsing must be tolerant.

**Samples** (a few of the 30):
```
entity_id=4691213040660085432 name=56030476 owner=3100098107 capacity=40
  player_count=2  like=0  has_pwd="1" min_level=25 pvp=true  server_name="Permanent Casual Survival's server"
entity_id=4691212895094155362 name=43865260 owner=3100097630 capacity=20
  player_count=16 like=0  has_pwd="0" min_level=0  pvp=true  server_name="XingzuoQing's server"
entity_id=4691192120752337186 name=12922260 owner=3100049896 capacity=40
  player_count=27 like=54 has_pwd="0" min_level=15 pvp=true  server_name="Latitude Quaternary's server"
```

### 6.2 Join endpoint ★core

```http
POST /rental-server-world-enter/get
{"server_id": "4658680138770108095", "pwd": ""}
```

`pwd` corresponds to `has_pwd` on the list entity (required for password-protected servers, an empty string otherwise).

**The response hands back the MC multiplayer address directly, including three-carrier routing**:

```json
{"code":0,"message":"OK","details":"","entity":{
  "entity_id":          "4658680138770108095",
  "mcserver_host":      "1.95.233.220",
  "mcserver_port":      13631,
  "isp_enable":         true,
  "cmcc_mcserver_host": "117.187.184.37",   // China Mobile
  "cmcc_mcserver_port": 13631,
  "ctcc_mcserver_host": "111.124.198.37",   // China Telecom
  "ctcc_mcserver_port": 13631,
  "cucc_mcserver_host": "220.197.38.43",    // China Unicom
  "cucc_mcserver_port": 13631,
  "state":              1,
  "async_progress":     4,
  "total_progress":     4
}}
```

**Key conclusions**:

1. **Rental servers are cold-start services, spun up on demand**: `async_progress`/`total_progress` are the asynchronous startup progress, and the server is enterable only at `4/4` (poll and wait while progress is incomplete).
2. **Three-line BGP access**: the three carrier IPs sit in completely different subnets (`117.187`/`111.124`/`220.197`); when `isp_enable=true` the client picks the IP matching its own ISP, and `mcserver_host` is the generic fallback address.
3. **The port is always 13631** (identical on all three lines).
4. **After obtaining the IP you still need the MC protocol auth handshake** (this endpoint returns no MC-side token) — join authentication lives at the MC game protocol layer, not in an HTTP endpoint.

### 6.3 Joining-player record (a write)

```http
POST /rental-server-player
{"server_id": "4658680138770108095"}
```

**The response is the current user's complete information** (cross-checked against `pe-get-user-setting-list`/`user-head-url-v2`):

```json
{"code":0,"message":"OK","details":"","entity":{
  "entity_id":  "785502692",
  "server_id":  "4658680138770108095",
  "user_id":    "3100073113",     // matches the user-id request header
  "name":       "Seek4W9FP",   // character nickname
  "status":     0,
  "create_ts":  1792125257,
  "delete_ts":  0,
  "headImage":  "https://x19.fp.ps.netease.com/file/5a34e0777f9d2a8a4ea3d36eza31LhW3",
  "frame_id":   null,
  "pe_growth":  [],
  "is_online":  false
}}
```

> The `headImage` fileid `5a34e0777f9d2a8a4ea3d36eza31LhW3` is precisely the 6th static avatar (`item_id=2000005`) in the list returned by `user-head-url-v2` — **the two paths cross-validate successfully**.

### 6.4 Player queries

```http
POST /rental-server-player/query/search-by-server
{"status":0,"server_id":"4658680138770108095","order_type":1,"is_online":true,"length":50,"offset":0}
```
Queries a server's player list. Measured `{"entities":[],"total":100}` (`entities` empty but total=100; the response body looks truncated or additional permission is required).

```http
POST /rental-server-player/query/search-by-user-server
{"server_id": "4658680138770108095"}
```
Queries **your own** record on a given server. Measured `{"entities":[],"total":0}`.

### 6.5 Favorites

```http
POST /rental-server-favorite/get-all      {"offset":0}   → entities[] + total
POST /rental-server-favorite/query-status {"server_id":"4658680138770108095"}
POST /rental-server-favorite/update       {"server_id":"...","is_favorite":1}  (1 = favorite, 0 = unfavorite, presumed)
```

`query-status` response:
```json
{"code":0,"message":"OK","details":"","entity":{"sid":4658680138770108095,"is_favorite":true}}
```
> Note that `sid` comes back as a **number** (unquoted), while the request sends a string.

### 6.6 Likes

```http
POST /rental-server-like/update  {"server_id":"4658680138770108095","is_like":1}
POST /rental-server-like/get     {"server_id":"4658680138770108095"}
```

`update` response: `{"code":0,"message":"OK","details":"","entity":{"entity_id":"4658680138770108095","is_like":1}}`

### 6.7 Multiplayer lobby infinite-scroll mechanism

```http
POST /online-lobby/query/feeds
{"current_index":16,"scene":"hot","last_exposed":"[\"4684007218039332223\", ...]"}
```

- `scene`: `hot` (popular)
- `last_exposed`: **the list of server ids already exposed (as a JSON string)**; after de-duplicating, the server returns the next batch of 16 → this is the **infinite-scroll pagination** mechanism
- response `entity.res`: an array of 16 server ids (numeric strings)

### 6.8 Server details

```http
POST https://g79mclobt.minecraft.cn/rental-server-details/get
{"server_id": "4658680138770108095"}
```

> ⚠ **Different domain** (`g79mclobt` vs `g79apigatewayobt`), `Content-Type: text/plain`, **no `x_trace_id` header**.

The response carries more fields than the list entity:
```json
{"code":0,"message":"OK","details":"","entity":{
  "entity_id":"4658680138770108095",
  "world_id":"l7patkmjtdeib3uyg6rlaa",
  "owner_id":"2492760332",              // string
  "name":"48285363",
  "brief_summary":"",
  "icon_index":5,
  "begin_time":1792058866,              // server creation time
  "mc_version":"1.21.120-release",
  "capacity":10,
  "active_components":[],               // list of active components
  "update_active_components":[],        // components pending update
  "status":1,
  "visibility":0,
  "player_count":0,
  "like_num":8076,
  "server_type":"docker_new_guian",
  "has_pwd":"0",
  "image_url":"",
  "min_level":0,
  "server_name":"Happy♂Light's server",   // the details endpoint can read the display name
  "bound_domain_sid":0,
  "pvp":false                            // note: false here in details, true in the list endpoint (data inconsistency)
}}
```

### 6.9 New endpoints after joining (measured)

**The rental-server player list finally returns real data** (after joining `is_online:true`, and `frame_id` plus a full `pe_growth` now appear):

```http
POST /rental-server-player/query/search-by-server
{"status":0,"server_id":"4658680138770108095","order_type":1,"is_online":true,"length":50,"offset":0}
```
```json
{"code":0,"message":"OK","details":"","entities":[{
  "entity_id":"785502692","server_id":"4658680138770108095",
  "user_id":"3100073113","name":"Seek4W9FP","status":0,
  "create_ts":1792125257,"delete_ts":0,
  "headImage":"https://x19.fp.ps.netease.com/file/5a34e0777f9d2a8a4ea3d36eza31LhW3",
  "frame_id":"https://x19.fp.ps.netease.com/file/5b0621055e602717a0751356PB1UpiEr",
  "pe_growth":{"exp":0,"lv":1,"decorate":[],"msg_background_id":0,"chat_bubble_id":0,"is_vip":false,"need_exp":100},
  "is_online":true
}],"total":100}
```
> Before joining it was `entities:[]`, and **`is_online` flips from false to true**; `frame_id` is the avatar-frame URL (same CDN).

### 6.10 User details (the most complete profile endpoint) ★

```http
POST https://g79mclobt.minecraft.cn/user-detail/query/other
{"entity_id": "3100073113", "with_statis_data": 0, "with_dynamic_head_img": 1}
```
> Domain `g79mclobt.minecraft.cn`, `Content-Type: text/plain`, no `x_trace_id` header.

**Response fields (more complete than `pe-get-user-setting-list`)**:
```json
{"code":0,"message":"OK","details":"","summary_md5":"e4319aa0e4b58f1f708e2487b01c0a72","entity":{
  "id":3100073113,
  "nickname":"Seek4W9FP",
  "signature":"",
  "headImage":"https://x19.fp.ps.netease.com/file/5a34e0777f9d2a8a4ea3d36eza31LhW3",
  "frame_id":"https://x19.fp.ps.netease.com/file/5b0621055e602717a0751356PB1UpiEr",
  "moment_id":"6ad0cce1ecb3a8126fe59560",
  "public_flag":false,
  "pe_growth":{"lv":1,"exp":0,"need_exp":100,"decorate":[],"is_vip":0},
  "tag":[],
  "is_developer":false,
  "mark":"",
  "headImageType":0,
  "is_friend":false,
  "homepage_bg":0,
  "visit_card_bg":0,
  "recharge_vip_level":0
}}
```
- The `entity_id` you pass is the `user-id` itself → **any user can be queried** (this is how "view someone else's profile" works)
- `with_statis_data` / `with_dynamic_head_img` are two optional switches
- `summary_md5` can be used for cache comparison

### 6.11 Pet (homestead) endpoints ★ adds a `server: home` request header

Besides the three auth headers, the following endpoints **carry an extra `server: home` header** (marking the "homestead" service):

```http
POST /home-get-all-pets       {} → pet list
POST /home-get-user-pet-detail {"pet_num": 1} → details for the given pet
POST /home-shop-all           {} → homestead shop (three measured responses of 5870 / 93473 / 136016 bytes, sharded loading)
```

`home-get-all-pets` response:
```json
{"code":0,"message":"OK","details":"","entities":[
  {"id":1,"name":"Fox","possessed":true,"using":true,"is_using":true},
  {"id":2,"name":"Panda","possessed":false,"using":false,"is_using":false},
  {"id":3,"name":"Dr. Woof","possessed":false,"using":false,"is_using":false}
]}
```

`home-get-user-pet-detail` response (contains **the complete item/skin entity structure**, directly reusable as a skin-parsing template):
```json
{"code":0,"message":"OK","details":"","summary_md5":"eb3bbc5cb4eab5de2028f790bb53c005","entity":{
  "pet_num":1,"pet_name":"Fox",
  "skin_info":{
    "is_activity":0,"name":"Fox","size_x":1,"size_y":1,
    "shadow_x":0,"shadow_y":0,"rarity":0,
    "material":"ty_yuanshenghuli_0_0",
    "icon":"https://x19.fp.ps.netease.com/file/5ef208058b7427b3fdfcbdb2kUys0EIT02",
    "preview_icon":"https://x19.fp.ps.netease.com/file/5ef208058b7427b3fdfcbdb2kUys0EIT02",
    "score":600,"type":5,"desc":"Fox","buy_num":10001,"category_id":1,
    "update_time":"2020-07-1 00:00:00",
    "offset_x":0,"offset_y":30,"scale":1.4,"skin_id":10001,"effect":"{}"
  },
  "action_ids":[]
}}
```

### 6.13 Other post-join endpoints (supplementary)

| Endpoint | Notes |
|---|---|
| `POST /salog`, `POST /salog/login-ui` | Analytics reporting (200, empty body) |
| `POST https://drpf-g79.proxima.nie.netease.com/` | **High-frequency telemetry** (once every 1~2 seconds after joining, 2-byte response) |
| `POST https://x19apigatewayobt.nie.netease.com/diagnostic-log` | Diagnostic logs (62 bytes, extremely frequent) |
| `POST https://x19apigatewayobt.nie.netease.com/diagnostic-value` | Diagnostic metrics |
| `GET /server-time` | Server time (80 bytes) |
| `GET https://g79.update.netease.com/clienttips/release/setting.json` | Client tip configuration |

### 6.14 Querying another user's profile (verified) ★

The `entity_id` of `user-detail/query/other` **accepts any user** — measured against the rental-server owner `2492760332`:

```http
POST /user-detail/query/other
{"is_need_recharge_benefit": 0, "entity_id": "2492760332", "with_statis_data": 0}
```
```json
{"code":0,"message":"OK","details":"","summary_md5":"cf80868e2e2657c424660d283f6360d5","entity":{
  "id":2492760332,
  "nickname":"Happy♂Light",
  "signature":"",
  "headImage":"https://x19.fp.ps.netease.com/file/5a34dfb67f9d2a91b885b936dNQqXzu8",
  "frame_id":"https://x19.fp.ps.netease.com/file/5b0621055e602717a0751356PB1UpiEr",
  "moment_id":"5eaacc8888ad1f5a81d1987d",
  "public_flag":false,
  "pe_growth":{"lv":50,"exp":0,"need_exp":6230,"decorate":[],"is_vip":0},
  "tag":[],
  "is_developer":{"developer_id":"7633752159","uid":"2492760332","username":"eternity_hope@163.com"},
  "mark":"",
  "is_friend":false,
  "homepage_bg":0,
  "visit_card_bg":0,
  "recharge_vip_level":7
}}
```

**New optional parameter**: `is_need_recharge_benefit` (0/1).

**The `is_developer` field gives away identity**: for a developer it returns an object (`developer_id`/`uid`/`username`, where `username` contains the **registration email**); for everyone else it is `false`. This completes the **other user's uid → profile** chain.

### 6.15 Item id lookup (the key step in skin resolution)

```http
POST /pe-item/query/search-by-id-list
{"channel_id": 5, "item_id_list": []}
```
- `channel_id: 5` — channel identifier (different channels have different item pools)
- `item_id_list: []` — pass item_ids in bulk and **the server returns the matching entities**
- An empty array measured `{"entities":[0],"total":0}`
- **Note the extra `hpack: 1` request header** (specific to this endpoint)

> This is the "`skin_data.item_id` → image URL" resolution step: first get the `item_id` from `pe-get-user-setting-list`, then exchange it for an entity through this endpoint (which carries `icon`/`preview_icon` URLs).

### 6.16 Domain Server endpoints ★

```http
POST /domain-server/get-my-server-details      {} → details of my domain server
POST /domain-server/req-leave-domain-server    {} → request to leave the domain server (called on exit)
```

`get-my-server-details` measured `{"entities":[]}` (this account has no domain server).

> **Domain servers and rental servers are two separate systems**: rental servers go through `rental-server/*`, domain servers through `domain-server/*`. When leaving a rental server, call `req-leave-domain-server` first.

### 6.17 Flash sale / other supplements

```http
POST /flash-sale/info
{"need_order": true, "sale_list": [20261016, 20261017, 20261018]}
```
```json
{"code":0,"message":"OK","details":"","entities":[
  {"begin_at":"1792152000","end_at":"1792166399","fixed_price":"100","max_cnt":"5000","item_id":"4690817423942739131","is_order":0},
  {"begin_at":"1792238400","end_at":"1792252799","fixed_price":"100","max_cnt":"10000","item_id":"4689513830288492893","is_order":0},
  {"begin_at":"1792324800","end_at":"1792339199","fixed_price":"100","max_cnt":"10000","item_id":"4685316796468183305","is_order":0}
]}
```
- `sale_list` is a **date array** (YYYYMMDD form); flash sales are queried per date
- `item_id` is a 19-digit numeric string (the same shape as the rental-server `entity_id`)
- amounts are all strings

**Other newly seen endpoints** (triggered in a batch when exiting the game):
| Endpoint | Notes |
|---|---|
| `POST /pe-team/get-my-team` | My team |
| `POST /hill-battle/get_activity_status` | Hill-climb event status |
| `POST /activity_task/get_task_info` | Event quests (two measurements: 90 bytes and 3408 bytes, the latter with quest details) |
| `POST /user-currency-new/query` | Currency query |
| `POST /rental-server/query/recent-visit-server` | Refresh recent visits after exiting |

### 6.18 Set-avatar write endpoint ★★★ (the last missing piece, measured)

```http
POST https://g79apigatewayobt.minecraft.cn/set-user-head/
```
> Note the **trailing slash in the path** (`set-user-head/`), unlike the other endpoints.

**Request**:
```json
{"rollback_last": 0, "head_image": "https://x19.fp.ps.netease.com/file/5a34e09ca7f252df68c974d3i3rv7YsD"}
```

| Field | Value | Notes |
|---|---|---|
| `rollback_last` | `0` / `1` | `0` = switch to the given avatar; `1` = roll back to the previous avatar (`head_image` may then be omitted) |
| `head_image` | full URL | **Pass the `url` field straight from the `user-head-url-v2` list**; no id exchange needed first |

**Response**:
```json
{"code":0,"message":"OK","details":"","entity":{
  "entity_id":"3100073113",
  "head_image":"https://x19.fp.ps.netease.com/file/5a34e09ca7f252df68c974d3i3rv7YsD",
  "head_image_cd":0
}}
```
- `head_image_cd`: `0` = no cooldown. **Changing avatars very likely has a cooldown or usage limit**; a non-zero value should be read as the remaining cooldown in seconds (unverified).

**The complete avatar-change chain (verified end to end in three steps)**:
```
1. POST /user-head-url-v2           {} → fetch the selectable avatar list (107 entries, with status saying whether each is owned)
2. POST /set-user-head/             {"rollback_last":0,"head_image":"<url>"} → set it
3. POST /user-detail/query/other    {"entity_id":"<uid>"} → read back to verify
```

### 6.19 Skin shop query

```http
POST /pe-item/query/get-skin-by-type
{"vip_only":"no","channel_id":5,"sort_type":6,"offset":0,"length":50,"is_purchased":1,"asc_flag":0}
```
```json
{"code":0,"message":"OK","details":"","entity":{"res":[],"tag":-1,"campaign_id":-1}}
```
- `vip_only` is a **string**, `"no"`; `is_purchased: 1` means owned-only (empty for this account)
- `sort_type`/`asc_flag` control ordering; `channel_id: 5` as in `search-by-id-list`

### 6.20 Personal-homepage endpoint family ★ (a third uid appears)

```http
POST /user-personal-page-view      {"personal_page_user_id": "3100073113"}
POST /user-home-page/get-config/   {"uid": "3100073113"}     ← trailing slash in the path
POST /user-home-page/get-favorite-mods  {}                   
POST /user-stat/get-user-state     {"search_id": "3100073113"}
```

**The `user-personal-page-view` response reveals the uid systems**:
```json
{"code":0,"message":"OK","details":"","entity":{
  "entity_id":"0",
  "visitor_user_id":"3100073113",
  "personal_page_owner_user_id":"952589465"
}}
```

| uid | Meaning |
|---|---|
| `3100073113` | **MC gateway user-id** (used by every `g79apigatewayobt.minecraft.cn` endpoint) |
| `952589465` | **NetEase account uid** (`personal_page_owner_user_id`, i.e. the one our seek-auth project binds) |

→ The two are **the same account's id in two different systems**: the MC-gateway user-id and the NetEase account uid proper.

**`user-home-page/get-config/` response** (personal-homepage configuration):
```json
{"code":0,"message":"OK","details":"","entity":{
  "favorite_iid":"","achievement_iid":"","favorite_reason":"",
  "tag":[],"comment_permission":0,"appearance_id":0,"novice_tag":0,
  "favorite_mods":[],"favorite_iid_name":"","achievement_iid_name":"","appearance_detail":[]
}}
```

**`user-stat/get-user-state` response** (personal-homepage statistics):
```json
{"code":0,"message":"OK","details":"","entity":{
  "entity_id":"3100073113",
  "personal_page_view_count":1,
  "personal_page_like_count":0,
  "video_view_count":0,
  "game_purchase_count":0,
  "component_purchase_count":0,
  "friend_cnt":0,
  "public_user_fans_cnt":0,
  "my_public_follow_cnt":4,
  "has_like":false
}}
```

### 6.21 Avatar library (loaded when changing avatars, 47666 bytes)

```http
POST /user-head-url-v2
{}
```
- Returns 107 selectable avatars, each with fields: `id`/`type`(0 = static, 1 = animated gif)/`url`/`pc_url`/`static_url`/`tips`/`name`/`status`(0 = not owned, 1 = owned)/`first_type`/`item_id`(static ones start at 2000001)/`item_name`/`jump_type`/`jump_target`/`is_gif`
- Image CDN: `https://x19.fp.ps.netease.com/file/<fileid>`
- This account's current avatar fileid `5a34e0777f9d2a8a4ea3d36eza31LhW3` = the 6th static avatar in the list (`item_id=2000005`)
- **The `head_image` of `set-user-head/` simply uses the `url` from here**

### 6.22 Set-skin write endpoint ★★★ (measured, the counterpart of `set-user-head/`)

```http
POST https://g79apigatewayobt.minecraft.cn/pe-set-user-setting-list
```

**Request** (note this is a **partial update** wrapped in `data`):
```json
{"data": {
  "persona_data": {},
  "skin_data":     {"item_id": "-2"},
  "screen_config": [],
  "skin_type":     {"type": "skin"}
}}
```

**Response**:
```json
{"code":0,"message":"OK","details":"","entity":null}
```

#### Exactly mirrors the read endpoint `pe-get-user-setting-list`

```http
Read:  POST /pe-get-user-setting-list
    {"settings": ["skin_type","skin_data","persona_data","screen_config","outfit_type","personal_open","personal_ad_open","personal_tags","bag_item"]}
```

| Key | Type | Observed value | Meaning |
|---|---|---|---|
| `skin_type` | object | `{"type":"skin"}` | Skin type |
| `skin_data` | object | `{"item_id":"-1"}` | **item_id of the current skin** |
| `persona_data` | object | `{}` | Character persona |
| `screen_config` | **object (read) / array (write)** | `{}` / `[]` | Screen configuration — **type differs between read and write** |
| `outfit_type` | object | `{}` | Outfit type |
| `personal_open` | object | `{"resRecommend":1}` | Recommendation openness |
| `personal_ad_open` | object | `{"adRecommend":1}` | Ad recommendations |
| `personal_tags` | object | `{"tags":["all"]}` | Personal tags |
| `bag_item` | object | `{}` | Backpack items |

> `settings` is an **on-demand** array — you get back exactly the keys you send.

#### Special values of `skin_data.item_id` (measured)

| Value | Meaning |
|---|---|
| `"-1"` | Default skin (Steve) — the initial state |
| `"-2"` | Another built-in system skin (the value after this capture's switch) |
| `"-3"` | Presumed to be another built-in slot (not measured) |
| positive integers such as `"2000001"` | ids of owned **item skins** (matching the item_ids of `user-head-url-v2`/`pe-item`) |

> **Negative numbers are free system skins; positive numbers are item skins.** Item skins must be owned first (`is_purchased` from `user_bag`/`pe-item/query/get-skin-by-type`), then resolved into an entity and image URL with `pe-item/query/search-by-id-list` (`channel_id:5`).

#### The complete skin chain

```
1. Read the current skin: POST /pe-get-user-setting-list  {"settings":["skin_type","skin_data"]}
2. See available skins:   POST /pe-item/query/get-skin-by-type  {"channel_id":5,"is_purchased":1,...}
3. Resolve the item:      POST /pe-item/query/search-by-id-list {"channel_id":5,"item_id_list":[...]}
4. Write the new skin:    POST /pe-set-user-setting-list  {"data":{"skin_data":{"item_id":"X"},"skin_type":{"type":"skin"}}}
5. Read back to verify:   POST /pe-get-user-setting-list  {"settings":["skin_data"]}
```

### 6.23 Avatar vs skin — the two write endpoints compared

| | `set-user-head/` | `pe-set-user-setting-list` |
|---|---|---|
| What it changes | Avatar (headImage) | Skin, persona, tags, screen configuration, etc. |
| Parameter | `head_image` is a **full CDN URL** | `data.skin_data.item_id` is an **item_id** |
| Data source | the `url` from the `user-head-url-v2` list | the `item_id` from the `pe-item` family |
| Trailing slash | **yes** (`set-user-head/`) | no |
| Response entity | an object (new value + `head_image_cd`) | `null` |

### 6.24 Handshake/initialization endpoints captured on re-login (second capture, 2026-10-16)

**The complete flow after killing the process and restarting MC** (NetEase official Android client):

1. **NetEase SDK protocol template**
   - `GET https://protocol.unisdk.netease.com/api/template/v94/latest.json?data=<base64>`
   - **the decoded `data` is `{"gameid":"x19","app_channel":"<channel id>","platform":"a"}`**
   - the second request returns `304` (served from cache)

2. **Resource/patch chain**
   - `GET /pack_list/production/g79_cps_packlist`
   - `GET /pack_list/production/g79_packlist_2`
   - `GET /patch_list/production/g79_rn_patchlist`
   - `GET /serverlist/adr_release.0.17.json` (a version query may be appended, e.g. `?9494`)
   - `GET /linkserver_obt.list`
   - `GET /anti`
   - `GET /game_notice/g79_notice_non_netease`

3. **Login-UI analytics** (exposes the full device fingerprint)
   - `POST /salog/login-ui`, `Content-Type: text/plain`
   ```json
   {"op_data": {
     "rom":"135192317952", "ram":"6231212032",
     "app_ver":"3.9.15.297900", "sdk_ver":"3.18.0",
     "disk":"", "network":"CHANNEL_UNKNOW", "core_num":"4",
     "app_channel":"netease",
     "device_height":"720", "mac_addr":"02:00:00:00:00:00",
     "cpu_digit":"64", "os_name":"android", "cpu_name":"placeholder",
     "reach_login_time":1792126281,
     "device_width":"1280", "udid":"62ff4a2a2e501f6b",
     "cpu_hz":"3200000", "launcher_type":"PE_C++",
     "device_model":"REDMI 23117RK66C",
     "emulator":false, "root":0, "os_ver":"15"
   }}
   ```
   > Note **`emulator:false`** — even when running inside MuMu, the client still reports false.

5. **One-off initialization after login** (40+ endpoints in a batch within 293~294 seconds)
   `pe-season-mod/get-user-purchase-info` (fired 9 times in a row), `get-chat-msgs`, `get-chat-ver-id`, `get-all-groups/`, `query-total-recharge-reward-data`, `query-total-recharge-data`, `query-montly-card-info`, `query-subscribe-card-benefit-info`, `query-user-recharge-benefit-info`, `user-negative-balance/query`, `has-shop-red-dots-v2`, `pe-web/advertisement/reward-total`, `user-currency-new/query`, `pe-get-user-setting` (note this is **a different endpoint** from `pe-get-user-setting-list`), `mobile-bind-query`, `user-allfriends-with-detail`, `domain-server/get-my-server-details`, `domain-server/get-invite-list`, `interconn/web/client-config-switch` (GET), `pe-team/get-my-team`, `activity_task/get_task_info`, `hill-battle/get_activity_status`, `server-time`, `get-currency-online/`

#### ★ The secret of `user-token`: a fresh one for every request

**Key observation**: two requests within the same second carry different tokens —
- `user-allfriends-with-detail` (t=293) → `vj0tPCmm6jwom2ho1`
- the other endpoints in the same batch → their own 16-character random-looking strings

30+ samples have been observed so far (`mTSrKHj7qyh4OHx41`, `bCthrzymaClooq9p1`, `dGzofeo86mm4d3Xm1`, `Lf6tdHk9rmqmPD411`, `LT0sr2imaOt5o33m1`, `vj0tPCmm6jwom2ho1`, `oi1oKLt4un3rrnh41`, `aD3uqiw4aCi6PnVo1`…), **all distinct, length always 17** (always ending in `1`).

**Conclusion (corrected)**: `user-token` is **not** a random or one-shot token but a **deterministic** value the client **derives locally on every request** — `f(long-lived login token, url, body)`, the same input always producing the same output. It is not issued by any HTTP response (what is issued is the **long-lived** `entity.token`, see §6.25), so it is entirely normal that no "fetch token" endpoint shows up in the capture. **The algorithm has been implemented in the project from the start** (`g79.py:calculate_dynamic_token`), see §6.25 — this section's earlier judgement of "cannot be reused, needs reverse engineering" was a misjudgement.

**Impact on us**: no external obstacle. As long as we hold the long-lived `entity.token` obtained from g79 authentication, we can compute the user-token locally for any (url, body) and call every g79 endpoint independently.

### 6.25 ★★★ `user-token` algorithm reverse engineering (vanilla_decompiled sources + .so localization)

**The user-supplied `E:\fateark\mcp\vanilla_decompiled\` (decompiled sources of NetEase MC's vanilla.mcp, 3903 Python files)** delivered the decisive conclusion.

#### 1. Where the token is generated (Python layer, 40+ call sites across the project)

Every g79 gateway request follows the same pattern (`framework/network_proxy.py` is typical):

```python
def _inner_http_request_apigateway_with_gzip(url, callback, method=POST, content=None, ...):
    if not application.instance.GetApiGatewayUrl():
        return
    if content is None:
        content = ''
    url = '/' + url
    user_token = utility.encrypt_token(url, content)          # ★ the token
    user_uid = setting.get_login_uid()
    http_instance = http.GetClientIns().HttpConnection(
        application.instance.GetApiGatewayUrl() + url)
    http_instance.setHeaders({'user-id': str(user_uid),
                              'user-token': user_token,
                              'Accept-Encoding': 'gzip'})
    http_instance.setContentType('application/json')
    http_instance.setContent(content)
    ...
```

**Call-site signature: `utility.encrypt_token(url, content)`** — only two arguments:
- `url`: **the path with a leading slash**, e.g. `'/user-detail/query/other'`, `'/salog-new'`, `'/authentication/update'`
- `content`: **the original plaintext body** (the JSON string before encryption; `''` when there is no body)

**This explains "a fresh one per request"**: the token is a function of `f(url, plaintext body)`, and both url and body differ every time → the token naturally differs every time. **It contains no timestamp or nonce** (the call site has no extra input).

#### 2. The algorithm itself lives in native code (not cracked, but localized)

`framework/utility.py:941`:
```python
def encrypt_token(url, data):
    import application
    if not isinstance(url, str) or not isinstance(data, str):
        raise Exception, 'Invalid params in encrypt_token'
    return _utility.encrypt_token(url, data)      # ← native extension
```

`_utility` / `_setting` are both **C++ extension modules inside `libminecraftpe.so`**; Python merely forwards.

**The relevant native interfaces (passed through by `minecraft/setting.py`)**:
| Native interface | Purpose |
|---|---|
| `_utility.encrypt_token(url, data)` | **Generate the user-token** |
| `_utility.encrypt_http_content(data, useHex)` | Body encryption |
| `_utility.decrypt_http_response(data, useHex)` | Response decryption |
| `_setting.get_login_uid()` | Read the uid |
| `_setting.get_login_sead()` | **Read the seed (derivation key)** |
| `_setting.refresh_login_info(token, sead)` | Refresh the login credential |
| `_utility.get_prop_string('SAUTH_JSON')` | Read the sauth JSON (contains `sdkuid`/`ip`/`aim_info`) |

#### 3. Key source: `token` + `sead` as a pair (**this section's inference has been disproven, see §6.26**)

`minecraft/setting.py:44`:
```python
def refreshLoginInfo(token, sead):
    _setting.refresh_login_info(token, sead)
    import tan_lobby_ctrl
    tan_lobby_ctrl.instance.UpdateToken()
```

`gui_2d/manager/NetWorkManager.py:96` (refresh on reconnect):
```python
setting.refreshLoginInfo(res.entity.token, res.entity.sead)
```

**Inference at the time**: on login the server issues a `(token, sead)` pair, with `sead` serving as the token-derivation key.
**→ Disproven by §6.26**: the real key is the **long-lived `token`** (`entity.token`); `sead` has nothing to do with
user-token derivation. Nor is the algorithm "md5 truncated to 16 characters" — it is the Go version's
`CalculateDynamicToken` (see §6.26), and **the project has implemented it all along**.

> Corroborating note at the time: the `md5(uid+iid+score+'steve')` in `lobbyGameRankMgr.py` is only a leaderboard
> signature, a completely different thing from user-token; it should not be extrapolated.

#### 4. Side finding: **the g79 gateway body is encrypted**

`gui_2d/ui_main.py:463-471` (complete sample):
```python
data_str = json.dumps(final_data)
url = '/salog-new'
user_uid = setting.get_login_uid()
user_token = utility.encrypt_token(url, data_str)   # token uses the [plaintext] body
content = utility.encrypt_http_content(data_str)     # body uses the [encrypted] form
http_instance.setHeaders({'user-id': str(user_uid),
                          'user-token': user_token,
                          'no_body': 1})
http_instance.set_binary_content(content)             # send the encrypted body
```

- **`user-token` is computed over the plaintext body before encryption**, while the body actually sent is the output of `encrypt_http_content(data_str)`
- This explains what the capture showed: requests with `Content-Length: 2` and a body of `{}` — **those 2 bytes are the encrypted form of the empty string `''`**
- `encrypt_with_tail()` reveals the encryption format: `data + 'abcdefghijklmnopqrstuvwxyz'` (**26 lowercase letters appended at the tail**; decryption restores the padding from the final character)
- The `useHex` argument: response decryption passes `True` (hex encoding), body encryption defaults to `False` (binary)

#### 5. The .so has been extracted, pending further reversing

Exported from the MuMu emulator (official Android client):
```
E:\fateark\mcp\libminecraftpe.so   322,151,000 bytes  arm64
```
- ELF validation passes: `7f 45 4c 46`, 64-bit, `e_type=183` (a non-standard value → **packed/modified**)
- `grep -c "encrypt_token"` hits 1 (the symbol exists), but the binary is compressed, so plaintext ripgrep cannot find it → Ghidra disassembly is needed to localize it

**Note**: MuMu's CPU ABI is `x86_64`, but the APK bundles only the `arm64` .so (executed through houdini translation), so the arm64 build is the correct one.

#### 6. Impact on our project (**overturned by §6.26, kept as a process record**)

| Scenario | Judgement at the time | Reality (see §6.26) |
|---|---|---|
| Calling the g79 gateway externally and independently | ❌ needs `sead` + the `encrypt_token` algorithm | ✅ the algorithm was implemented long ago at `g79.py:calculate_dynamic_token`; only the long-lived `entity.token` is needed |
| Reuse inside the process (grabbing the token while entering the game) | ✅ feasible | ✅ still feasible, but unnecessary — we can compute it locally |
| Only displaying avatars/profile (plaintext HTTP body) | ✅ as long as the body is unencrypted | ✅ correct |

> Measured corroboration: the `user-detail/query/other` request has **a plaintext JSON body** (`{"entity_id":"3100073113",...}`); only sensitive endpoints such as `salog`/`authentication` encrypt their body.

---

## 6.26 ★★★ user-token finally cracked: **the project had already implemented the algorithm**, and the earlier "not cracked" was a misjudgement

### The decisive finding

`calculate_dynamic_token(path, content, token)` at `g79.py:317` is the user-token generation algorithm — it is a
**character-for-character port of the g79client Go reference implementation**, it has been in the project all along, and our
server has been using it all along to call the g79 API successfully. What §6.25 wrote — "the algorithm is inside a native
virtual function, not cracked, and is the biggest obstacle to reuse" — was **my own misjudgement** (I forgot the Go reference
implementation already contained this algorithm).

### The algorithm (Go `CalculateDynamicToken`)

```python
def calculate_dynamic_token(path, content, token) -> str:   # token = long-lived login token
    salt = "0eGsBkhl"
    token_md5 = md5(token).hexdigest()
    payload = token_md5 + content + salt + path.rstrip_one("?")
    payload_md5 = md5(payload).hexdigest()          # 32 hex characters
    binary = "".join(f"{b:08b}" for b in payload_md5.encode())  # 256 bits
    binary = binary[6:] + binary[:6]                # circular left shift by 6 bits
    transformed = bytearray(payload_md5.encode())
    for i in range(32):
        section = binary[i*8 : i*8+8]
        reversed_byte = int(section[::-1], 2)       # reverse every 8 bits
        transformed[i] = reversed_byte ^ payload_md5.encode()[i]
    b64 = base64.b64encode(transformed).decode()
    return b64[:16].replace("+","m").replace("/","o") + "1"   # 17 characters
```

**The `token` argument is the long-lived login token** (`entity.token` from the g79 auth response, i.e.
`self.user_token` at `g79.py:1076/1698`), **not** the native-side
`LOGIN_RANDOM_ENCRYPT_KEY`. Conflating the two is exactly what produced the "cannot be generated externally" misjudgement.

### Verification evidence (two independent lines)

1. **Format pattern matches 100%** (36 recomputations, script referenced in §6.25): the output is always **17 characters**,
   always ends in `1`, maps `+`→`m`/`/`→`o`, is a pure base62 subset, and is identical for identical input (deterministic). This agrees
   item by item with the pattern induced from 30+ capture samples.
   - Example: `calculate_dynamic_token("/rental-server-player", '{"server_id": "4658680138770108095"}', "sometoken123")` → `aL5oNTg8faosuv991` (exactly the shape of the captured `oi1oKLt4un3rrnh41`)
2. **Functional evidence**: our project's server has always called the g79 gateway successfully with `calculate_dynamic_token`
   (the earlier bot-status round trip measured nickname=Seek4W9FP, level=1, skin_number=3).
   If the token were computed incorrectly, every one of those calls would fail.

> Why an exact "triple recomputation" against a capture sample is impossible: the capture only contains the derived 17-character
> user-token; the **long-lived** `entity.token` fed into the algorithm is unavailable (it is an auth-response field that changes on
> every authentication). But the format match plus the server actually calling successfully are together enough to confirm the algorithm.

### How the native side relates to the Go side (clarification)

- Python's `encrypt_token(url, content)` takes only 2 arguments; the long-lived token is read internally by native code from runtime
  state (the `_setting` singleton). Go's `CalculateDynamicToken(path, content, token)` passes the long-lived token explicitly as a
  third argument. Both produce the same 17-character user-token from the same (long-lived token, url, body) — **two implementations
  of one algorithm**.
- Native `nativeEncryptToken` (`0x5F12178`, 964 bytes) goes through a runtime virtual call internally
  (`vtable[0xd78]`, three out-parameters); static analysis can stop there — the Go side already provides a complete, readable implementation.
- `LOGIN_RANDOM_ENCRYPT_KEY = 'b28ca5b4a37e4f68'` (`framework/random_key.py`) is a constant of the login `Enkey` path
  (`clientApp.OnLoginWebServer`) and is **unrelated** to per-request user-token derivation; it was previously mistaken for the key source.

### The Frida dynamic-hooking route (attempted; not viable in this environment)

MuMu x86_64 + the game's arm64 .so executes through **libhoudini translation** → Frida's
`enumerateModules()` cannot see `libminecraftpe.so`; and the MC main process kills itself after attach
(anti-debugging). Conclusion: dynamic hooking is a dead end; static analysis plus the Go reference implementation is the right answer.

### The complete reverse-engineering conclusions, frozen in the repo

The `src/seek_auth/mc_token.py` module docstring freezes: the call-site signature, the native location
(`Java_com_mojang_minecraftpe_MainActivity_nativeEncryptToken @ 0x5F12178`,
964 bytes), the measured token properties (17 characters / trailing `1` / base62), the hypotheses already ruled out, the final algorithm, and
the reason Frida was blocked.

---

## 8. Item-by-Item Endpoint Verification (2026-10-16 fix round)

We checked our project's implementation against the real capture one by one; conclusions below.

### 8.1 ✅ Aligned, no changes needed

| Our method | Official endpoint | Notes |
|---|---|---|
| `enter_rental_server_world` | `/rental-server-world-enter/get` | body `{"server_id","pwd"}` matches exactly; `parse_rental_endpoints()` added to parse the three-line IPs |
| `search_rental_server_by_name` | `/rental-server/query/search-by-name` | body `{"server_name","offset"}` matches |
| `get_user_setting_list` | `/pe-get-user-setting-list` | all 9 keys match the official ones; `settings` subset queries are supported |
| `set_user_setting_list` | `/pe-set-user-setting-list` | body now also sends `skin_type` (measured: for some accounts a skin change does not take effect when only `skin_data` is sent) |
| `calculate_dynamic_token` | user-token derivation | **algorithm is correct** (§6.26); the server has always relied on it to call g79 successfully |

### 8.2 ⚠ Fixed

| Item | Before the fix | After the fix | Basis |
|---|---|---|---|
| **Skin lookup chain** | used the old `/user-game-skin/query/search-by-type` (returns empty on the live service) | switched to `/pe-get-user-setting-list` → `skin_data.item_id` → `/pe-item/query/search-by-id-list` to exchange for the entity | traffic captured from the real official client |
| **user-token documentation conclusion** | §6.25 judged it "not cracked / the biggest obstacle to reuse" | §6.26 corrects it: the algorithm was implemented long ago in `calculate_dynamic_token`, no external obstacle | 36 format recomputations + successful server calls |

### 8.3 ➕ Added (official has it, we lacked it)

| Method | Endpoint | Value |
|---|---|---|
| `get_skin_by_type` | `/pe-item/query/get-skin-by-type` | Skin shop / owned list (`is_purchased=1` for owned only) |
| `get_item_by_id_list` | `/pe-item/query/search-by-id-list` | item_id → entity (`icon`/`preview_icon` URLs), **requires the `hpack:1` header** |
| `query_user_detail_other` | `g79mclobt.minecraft.cn/user-detail/query/other` | The most complete profile (nickname/avatar/avatar frame/level/VIP/developer status), **plaintext with no encryption or decryption, `Content-Type: text/plain`, entity_id accepts any uid → querying other users' profiles** |
| `parse_rental_endpoints` | parses the `rental-server-world-enter/get` response | Three-line BGP IPs + cold-start progress readiness check |

### 8.5 📌 Not yet fixed (low priority)

| Item | Current state | Notes |
|---|---|---|
| `User-Agent` | sends `WPFLauncher/0.0.0.0` | The real client sends `libhttpclient/1.0.0.0`; left alone because it keeps working (changing it needs a regression pass) |
| `pe-user-detail/get` | still the old version | `query_user_detail_other` has been added, but old paths such as `refresh_user_detail` have not been switched over |

---

## 9. To-Do / Unsolved Mysteries

### ✅ Resolved (previously listed as unknown, now cracked or confirmed)

- **~~Where `user-token` comes from~~**: see §6.26. The algorithm **has been implemented in the project all along** at
  `g79.py:calculate_dynamic_token` (character-for-character port of g79client Go), and its input is the long-lived login
  token `entity.token` (a g79 auth-response field, `self.user_token`). The earlier "not cracked / biggest
  obstacle / needs reversing sauth+sead" was all a misjudgement.
- **~~`encrypt_token` algorithm not cracked~~**: same as above. Native `nativeEncryptToken`
  (`0x5F12178`) and the Go version are two implementations of the same algorithm; reversing can stop at the virtual-call boundary.
- **~~`sead` is the user-token key~~**: disproven. `sead` is unrelated to user-token derivation;
  `LOGIN_RANDOM_ENCRYPT_KEY` is a login `Enkey` path constant and equally unrelated.
- **Skin/avatar write endpoints**: captured and measured — `/set-user-head/` (avatar),
  `/pe-set-user-setting-list` (skin), see §6.18, §6.22.

### ⏳ Still to investigate

1. **Mapping between `user-id` and the NetEase uid**: two ids were observed side by side — `3100073113` (MC gateway
   user-id), `952589465` (NetEase account uid, the value our project binds). The mapping endpoint has not been captured
   (`user-personal-page-view` shows both at once but exposes no conversion endpoint).
2. **Rental-server player-list entities**: `search-by-server` returns `entities:[]` but `total:100`,
   and no entity sample was obtained (data only appears once `is_online:true` after joining, see §6.9).
3. **MC-protocol-layer auth after joining**: `rental-server-world-enter/get` only returns IP/port;
   the MC-side handshake auth lives at the game protocol layer (`drpf-g79.proxima.nie.netease.com` is high-frequency telemetry with a
   2-byte response, not auth).
4. **`home-shop-all` sharded loading**: three responses of 5870 / 93473 / 136016 bytes; the sharding mechanism
   and its parameters have not been analysed.
5. **Which endpoints require an encrypted body**: measured, the bodies of `user-detail/query/other`,
   `pe-get-user-setting-list`, `rental-server-*` etc. are **plaintext JSON**;
   `/salog`, `/salog-new`, `/authentication/update` encrypt with `encrypt_http_content`
   (an empty string encrypts to 2 bytes). The full list has not been verified endpoint by endpoint.
6. **Which endpoint issues `sead`/`token`**: in `NetWorkManager.start_reconnect` they come back as
   `res.entity.token` / `res.entity.sead`, but the concrete endpoint was not captured (a reconnect-specific endpoint).
   Note: this `token` is the long-lived token fed into `calculate_dynamic_token`.
7. **`pe-get-user-setting` vs `pe-get-user-setting-list`**: two different endpoints
   (the former is singular and called at login; the latter has `-list` and is called from the outfit screen). Their purposes and
   parameters differ — do not mix them up.

---

## Appendix: Capture Method (reusable)

```powershell
# 1. connect the emulator + adb reverse (works around the Windows firewall blocking inbound 8080)
$adb = "E:\Program Files\Netease\MuMu\nx_main\adb.exe"
& $adb connect 127.0.0.1:16384
& $adb -s 127.0.0.1:16384 reverse tcp:8080 tcp:8080

# 2. point the emulator at the host proxy
adb -s 127.0.0.1:16384 shell settings put global http_proxy 127.0.0.1:8080

# 3. lock portrait (with user_rotation=1, screenshot coordinates and the input tap coordinate system are offset, so every tap lands wrong)
adb -s 127.0.0.1:16384 shell settings put system user_rotation 0
adb -s 127.0.0.1:16384 shell settings put system accelerometer_rotation 0

# 4. clean up afterwards
adb -s 127.0.0.1:16384 shell settings put global http_proxy :0
```

mitmproxy web token: `9bcd074caf9ef9b1b2dd6fab1c73a619`

**Pitfalls recorded**:
- The channel login page is H5 (WebView); `adb input tap/text` has no effect on it (`mInputShown` stays false), so the **user has to type manually**.
- `wm size` reports `720x1280`, but screenshots are `1280x720` in landscape — coordinates have to be inferred from the current rotation state.
- MuMu's bundled adb path: `E:\Program Files\Netease\MuMu\nx_main\adb.exe`; the host PATH has no adb.
- uiautomator dump produces no output on the game screen (self-drawn views).

---

## 10. Guest Registration + Real-Name + PE Auth, the Complete Chain (2026-10-17 capture of com.netease.x19)

> Source: MuMu emulator running com.netease.x19 (NetEase official MC), captured with mitmweb → exported via `/flows/dump` and parsed with `mitmproxy.io.FlowReader`.
> dump file: `E:\fateark\mcp\guest_capture2.har` (2.5MB, 117 flows)
> Key constants: device_id=`amawvuyac63iw44m-d`, user_id=`aibgvu3okopwreyt`, game_id=`aecfrxodyqaaaajp-g-x19`, **app_channel=netease**

### 10.1 The complete endpoint sequence (13 steps)

| Step | Endpoint | Status | Key points |
|---|---|---|---|
| 1 | `GET protocol.unisdk.netease.com/.../latest.json?data=<base64>` | 304 | decoded data=`{"gameid":"x19","app_channel":"netease","platform":"a"}` |
| 2 | `POST mgbsdk.matrix.netease.com/x19/sdk/get_sdk_config_info` | 200 | SDK configuration |
| 3 | `GET mgbsdk.../get_sdk_aas_config?login_channel=netease&app_channel=netease` | 200 | Anti-addiction rules (2KB) |
| 4 | `GET service.mkey.163.com/mpay/games/{game_id}/config` | 200 | MPay configuration (30KB) |
| 5 | **`POST .../devices`** | **201** | Device registration. 756B form (with mac/udid/brand/model/resolution/ext_ci) → response `{"device":{"id":"amawvuyac63iw44m-d","key":"30347a65653434706e67396970366230"}}` |
| 6 | `POST .../devices/upload` | 200 | Device detail upload (785B) → `{"upload_time":1792241164}` |
| 7 | **`POST .../devices/{device_id}/users/by_guest`** | **400** | Guest creation **blocked by risk control**. 543B form (`params` is an AES-encrypted `"{}"`) → `{"code":1351,"reason":"Account has security risk","verify_url":"https://...reverify/upload_sms?...&ticket=qbzkvuqujuw8p6cn"}` |
| 8 | `GET .../reverify/upload_sms?code=081368&ticket=...` | 200 | WebView SMS verification page (18KB HTML, title "Login Security Verification") |
| 9 | **`POST .../reverify/upload_sms/result`** | 200 | Verification succeeded! `{"user":{"token":"1-eyJ...","id":"aibgvu3okopwreyt","login_type":2,"login_channel":"netease","client_username":"Player opwreyt","udid":"5vsnzda43ebcz3eyvp3dcy3akx8fxy03"}}` |
| 10 | **`POST mgbsdk.../uni_sauth`** | 200 | sauth authentication. `app_channel=netease, sdkuid=aibgvu3okopwreyt` → `aid=992687485` (NetEase uid) |
| 11 | `POST mgbsdk.../check_enter` | **405** | Not real-name verified: `"unrealname online (account) time limit"` |
| 12 | `GET .../users/{user_id}/info?token=1-...` | 200 | `realname_status=0, need_aas=true` |
| 13 | `POST g79obtapigtcoregray.minecraft.cn/authentication/reconnect` | 200 | 66B hex → 258B hex (encrypted authentication) |

### 10.2 Real-name verification chain (3 steps)

| Step | Endpoint | Status | Key points |
|---|---|---|---|
| 14 | **`POST .../realname/verify`** | 200 | Verify first: `device_id + user_id + token + realname(URL-encoded) + id_region=86 + id_num` → `{"need_aas":false,"realname_type":"adult"}` |
| 15 | **`POST .../realname/update_by_token`** | 200 | Then submit (**parameters identical**) → the same `{"need_aas":false,"realname_type":"adult"}` |
| 16 | `GET mgbsdk.../client_query_aas` | 200 | `{"aas_guide":1,"age_range":4}` = adult |

### 10.3 PE auth after real-name verification (entering the game)

| Step | Endpoint | Status | Key points |
|---|---|---|---|
| 17 | **`POST g79obtapigtcoregray.minecraft.cn/pe-authentication`** | **200** | ★ **PE authentication succeeded!** Request encrypted (~300B hex), response 5122B hex. The domain is `g79obtapigtcoregray` (neither `g79apigatewayobt` nor `x19obtcore`) |

### 10.4 Comparison with mpay.py

| Item | Real capture | Our mpay.py | Status |
|---|---|---|---|
| Device registration path | `/mpay/games/{game_id}/devices` | ✅ matches | ✅ |
| Device registration response | `{"device":{"id":"...","key":"..."}}` | ✅ `self.device_id`, `self.device_key` | ✅ |
| Guest creation path | `.../devices/{device_id}/users/by_guest` | ✅ `create_guest()` | ✅ |
| `params` encryption | AES-ECB(`device_key`, `"{}"`) → hex | ✅ `_aes_ecb_encrypt` | ✅ |
| Risk-control response | HTTP 400, `code:1351`, `verify_url` | ✅ `MpayVerifyRequiredError` | ✅ |
| Guest credential | `user.token` + `user.id` | ✅ `sdkuid` + `sessionid` | ✅ |
| `app_channel` | `netease` | ✅ `app_channel:"netease"` in `build_sauth_cookie` | ✅ |
| Real-name path | `/mpay/api/users/realname/update_by_token` | ✅ `auth_realname()` | ✅ |
| `id_region` | `86` | ✅ present | ✅ |
| Real-name verify first | `/mpay/api/users/realname/verify` | ❌ **we have no verify step** | ⚠️ |

### 10.5 Summary of new findings

1. **Real-name verification is two steps**: `verify` (validation) first, then `update_by_token` (submission), with identical parameters. We only have the second — **we are missing verify**.
2. **PE auth domain**: `g79obtapigtcoregray.minecraft.cn` (the `x19obtcore.nie.netease.com` in our code is the heartbeat domain, not the PE domain).
3. **SMS verification goes through a WebView** (`reverify/upload_sms` returns an HTML page), not a pure API call — which explains why our "auto-generate" stalls at risk control: we cannot render a WebView server-side to complete verification.
4. **`check_enter` code 405 is an anti-addiction restriction** (you cannot play without real-name verification), not an authentication failure. It clears automatically once verification is done.
5. **MPay token format** (base64-decoded): `{"si":"<sha1>","odi":"<device_id>","s":"<32-character session>","u":"<user_id>","t":2,"prs":128,"g_i":"<game_id>","sa":-6}`

### 10.6 Location of the dump file

```
E:\fateark\mcp\guest_capture2.har   2,512,703 bytes  (mitmproxy tnetstring format)
```
Parsed with `mitmproxy.io.FlowReader`:
```python
from mitmproxy.io import FlowReader
with open("guest_capture2.har", "rb") as f:
    for flow in FlowReader(f).stream():
        print(flow.request.method, flow.request.host, flow.request.path)
        print(flow.response.content)  # ← full body
```
