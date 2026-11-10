"""NetEase MC (g79) official API route table.

Source: ``mcp/vanilla_decompiled/gui_2d/ui_service/*.py`` -- the official client's
decompiled vanilla.mcp source (3895 of 3903 files decompiled). These files are the API route
table of the official ``ui_request`` layer, more authoritative than our mitmproxy reverse work.

**The "hostName" field is what matters**: it says which domain each endpoint should hit --
``WebServerUrl`` / ``CoreServerUrl`` / ``ApiGatewayUrl`` (all three delivered by
``release.json``). Our early code guessed from packet captures and often got it wrong.

Cross-checked against captures: ``E:\\fateark\\seek-auth\\docs\\mc-official-api-notes.md``
records live samples we captured on 2026-10-16 with mitmproxy against the official Android
client. Where both sources agree, the entry is marked ``[verified]``.

Usage::

    from seek_auth.mc_api import RENT_GAME, USER

    spec = RENT_GAME["get_server_list"]
    spec["url"]        # '/rental-server/query/available-by-sort-type'
    spec["host"]       # 'WebServerUrl'
    spec["params"]     # {...}
"""

from __future__ import annotations

from typing import Any, ClassVar

# ── domain key names (matching the fields in release.json) ──
WEB = "WebServerUrl"
CORE = "CoreServerUrl"
GATEWAY = "ApiGatewayUrl"


def _spec(url: str, host: str = WEB, **params: Any) -> dict[str, Any]:
    """Build one endpoint spec. A None in ``params`` means "optional / pass on demand"."""
    out: dict[str, Any] = {"url": url, "host": host}
    if params:
        out["params"] = {k: v for k, v in params.items() if v is not None}
    return out


# ════════════════════════════════════════════════════════════════════
# Rental servers (rent_game_service.py, 27 official endpoints)
# ════════════════════════════════════════════════════════════════════

RENT_GAME: dict[str, dict[str, Any]] = {
    # ── queries ──
    "get_server_list": _spec(
        "/rental-server/query/available-by-sort-type",
        offset="", sort_type="", order_type="",
    ),                                                                  # [verified]
    "get_my_server_list": _spec(
        "/my-rental-server/query/search-by-user",
        offset="", length="", need_storage="",   # need_storage=1 also returns saves (slow)
    ),                                                                  # [verified]
    "get_search_server_list": _spec(
        "/rental-server/query/search-by-name", server_name="", offset="",
    ),                                                                  # [verified]
    "get_friend_server_list": _spec(
        "/rental-server/query/available-friend-server",
        offset="", sort_type="", order_type="", world_name_key="",
    ),
    "get_favorite_server_list": _spec(
        "/rental-server-favorite/get-all", offset="",
    ),                                                                  # [verified]
    "is_favorite_server": _spec(
        "/rental-server-favorite/query-status", server_id="",
    ),                                                                  # [verified]
    "set_favorite_server": _spec(
        "/rental-server-favorite/update", server_id="", is_favorite="",
    ),
    "get_recent_visit_server_list": _spec(
        "/rental-server/query/recent-visit-server", offset="",
    ),                                                                  # [verified]
    "get_server_detail": _spec(
        "/rental-server-details/get", server_id="",
    ),                                                                  # [verified]
    "get_single_player": _spec(
        "/rental-server-player/query/search-by-user-server", server_id="",
    ),                                                                  # [verified]
    "create_player": _spec(
        "/rental-server-player", server_id="",
    ),                                                                  # [verified]
    "get_server_enter_info": _spec(
        "/rental-server-world-enter/get", server_id="", pwd="",
    ),                                                                  # [verified]
    "get_rent_server_status": {"url": "/rental-server-status", "host": WEB, "method": "GET"},
    "get_server_control_status": _spec(
        "/rental-server-control/get-status", server_id="",
    ),
    "is_like_server": _spec("/rental-server-like/get", server_id=""),    # [verified]
    "set_like_server": _spec(
        "/rental-server-like/update", server_id="", is_like="",
    ),                                                                  # [verified]
    "get_players": _spec(
        "/rental-server-player/query/search-by-server",
        server_id="", is_online="", status="", order_type="", offset="", length="",
    ),                                                                  # [verified]
    # ── plans / activation ──
    "get_server_meals": {"url": "/rental-server-meal/query/available", "host": WEB},
    "get_server_meal": _spec("/rental-server-meal/get", meal_id=""),
    "buy_server": _spec("/my-rental-server", meal_id=""),
    "renew_server": _spec("/rental-server-keep", entity_id="", meal_id=""),
    "change_server_meal": _spec(
        "/rental-server-meal-change", server_id="", meal_id="",
    ),
    "get_server_capacity": _spec(
        "/my-rental-server-info/query/info", server_id="",
    ),
    # ── settings ──
    "set_server_properties": _spec(
        "/my-rental-server/update",
        server_id="", server_name="", image_url="",
        visibility="", pwd="", min_level="", brief_summary="",
    ),
    "set_server_status": _spec(
        "/rental-server-control/update",
        status="", version="", server_id="",
    ),
    # ── world / backups ──
    "init_server": _spec(
        "/my-rental-server/initialize",
        server_id="", server_version="", official_mods="", params="",
    ),
    "get_backup_server_list": _spec(
        "/rental-server-backup/query/search-by-server", world_id="", sid="",
    ),
    "create_backup": _spec(
        "/rental-server-backup-upload/create-async",
        world_id="", backup_id="", backup_name="", sid="",
    ),
    "restore_backup": _spec(
        "/rental-server-backup-restore",
        world_id="", backup_id="", sid="",
    ),
    "get_world_setting": _spec(
        "/rental-server-world-settings/get", world_id="", server_id="",
    ),
    "set_world_setting": _spec(
        "/rental-server-world-settings/update",
        server_id="", world_name="", game_mode="", game_diff="",
        cheat_mode="", pvp="", world_type="", world_seed="",
    ),
    "sync_world_tier": _spec("/my-rental-server/sync_world_tier", server_id=""),
    "copy_rental_save_to_domain": _spec(
        "/domain-server/copy-rental-save-to-domain",
        rental_sid="", sid="", backup_id="",
    ),
    "set_player_status": _spec(
        "/rental-server-player/update",
        entity_id="", status="", is_online="",
    ),
}


# ════════════════════════════════════════════════════════════════════
# Users / cosmetics / profile (user_service.py)
# ════════════════════════════════════════════════════════════════════

USER: dict[str, dict[str, Any]] = {
    # ── nickname ──
    "get_random_name": _spec("/nickname-init/get-random-name"),   # random nickname
    "init_pe_name": _spec("/nickname-setting", name=""),           # first-time nickname
    "change_pe_name": _spec("/pe-nickname-setting/update", name=""),  # [verified]
    # ── avatars ──
    "get_user_head_url_v2": _spec("/user-head-url-v2"),           # [verified] avatar library
    "set_user_head_url": _spec(
        "/set-user-head/", head_image="", is_init="", rollback_last="",
    ),                                                            # [verified] slash-terminated
    # ── avatar frames ──
    "get_user_head_frame": _spec("/user-head-frame"),
    "set_user_head_frame": _spec("/user-head-frame"),
    # ── signature / privacy ──
    "set_user_signature": _spec("/personal-info/update-info", signature=""),
    "set_data_visible": _spec(
        "/user-stat/set-data-visible", data_type="", visible="",
    ),
    "get_sdkinfo": {"url": "/user-sdkinfo", "host": WEB, "method": "POST"},
    # ── details / statistics ──
    "get_pe_my_detail": {"url": "/pe-user-detail/get", "host": CORE},
    "get_user_appearance": _spec(
        "/pe-get-other-user-setting-list",     # query **another user's** cosmetics
        user_id="", settings="", with_pet_info="",
    ),
    "get_user_like": _spec("/user-stat/get-user-state", search_id=""),  # [verified]
    "user_detail_extend": {"url": "/user-detail-extend", "host": WEB, "method": "POST"},
    "get_user_social_setting": _spec("/interconn/web/user-social-setting/get"),
    # ── after login ──
    "get_pe_user_login_after": _spec("/pe-user-login-after", client_type="cocos"),
    # ── ban checks ──
    "get_user_game_ban": _spec("/check-user-game-ban", gameType=""),
    # ── purchase history / achievements ──
    "get_user_item_purchase": _spec(
        "/pe-user-item-purchase/",
        first_type_id="", offset="", length="",
        channel_id="", order_flag="", asc_flag="", filter_type="",
    ),
    "pe_user_item_purchase_operate": _spec(
        "/pe-user-item-purchase-operate",
        first_type_id="", offset="", length="",
        channel_id="", order_flag="", asc_flag="", filter_type="",
    ),
    "get_user_achievement_lobby_item": _spec(
        "/pe-item/get-user-achievement-lobby-item",
        offset="", length="", page="",
    ),
    "get_pe_user_game_achievement": _spec(
        "/pe-game/get-pe-user-game-achievement", offset="", length="", page="",
    ),
    "get_achievement_progress": _spec(
        "/achievement/query-progress", data="",
    ),
    "get_cur_season_mod_list": {
        "url": "/pe-season-mod/get-current-season-list", "host": GATEWAY, "hpack": True,
    },
    # ── cosmetic settings (skins) ──
    "get_user_setting_list": _spec(
        "/pe-get-user-setting-list", settings="",
    ),                                                            # [verified]
    "set_user_setting_list": _spec(
        "/pe-set-user-setting-list", data="",
    ),                                                            # [verified]
    "set_new_guide_skin": _spec("/pe-new-guide/set-skin"),
}


# ════════════════════════════════════════════════════════════════════
# Multiplayer lobby (lobby_game_service.py)
# ════════════════════════════════════════════════════════════════════

LOBBY_GAME: dict[str, dict[str, Any]] = {
    "enter_main_city": _spec("/enter-main-city"),
    "leave_main_city": _spec("/leave-main-city"),
    "get_recommend_list": _spec(
        "/online-lobby-room/query/get-recommend-list", offset="", length="",
    ),
    "get_personalise_recommend_list": _spec(
        "/online-lobby-room/query/get-personalise-recommend-list", offset="", length="",
    ),
    "get_theme_list": _spec("/theme/get-list"),
    "list_res_id_by_type": _spec("/online-lobby-room/query/list-res-id-by-type"),
    "get_friend_playing_room": _spec(
        "/online-lobby-room/query/friend-playing-room", offset="",
    ),
    "room_with_tags": _spec("/room-with-tags"),
    "room_with_friend": _spec("/room-with-friend"),
    "room_related": _spec("/room-related"),
    "room_list": _spec("/room-list"),
    "cpp_version_map": _spec("/cpp-version-map"),
    "get_recent_play_res_list": _spec(
        "/online-lobby-room/query/recent-play-res-list", offset="",
    ),
    "online_lobby_collection": _spec("/online-lobby-collection"),
    "delete_collection": _spec("/online-lobby-collection/delete"),
    "get_collection_list": _spec("/online-lobby-collection/get-list"),
    "get_backup_list": _spec(
        "/online-lobby-backup/query/list-by-user", offset="",
    ),
    "create_backup": _spec("/online-lobby-backup/create"),
    "pe_shop_item_query_all": _spec("/pe-shop-item/query-all"),
    "list_room_by_res_id": _spec(
        "/online-lobby-room/query/list-room-by-res-id", offset="",
    ),
    "room_match": _spec("/online-lobby-room-match"),
    "get_room": _spec("/online-lobby-room/get"),
    "get_multi_room_info": _spec("/online-lobby-room/get-multi-room-info"),
    "online_lobby_game_enter": _spec("/online-lobby-game-enter"),
    "lib_item_tags": _spec("/pe-item/query/lib-item-tags"),        # [verified]
    "search_lobby_res_by_keyword": _spec(
        "/pe-item/query/search-lobby-res-by-keyword", offset="", length="", keyword="",
    ),
    "search_by_name_v2": _spec(
        "/online-lobby-room/query/search-by-name-v2", offset="", keyword="",
    ),
    "room_with_name": _spec("/room-with-name"),
}


# ════════════════════════════════════════════════════════════════════
# Rental server state machine (official constants from rent_game_const.py)
# ════════════════════════════════════════════════════════════════════

class RentServerStatus:
    """Official rental server status codes and their display names."""

    CLOSE = 0
    OPEN = 1
    UNINITIALIZED = 2
    OPENING = 3
    CLOSING = 4
    MAINTENANCE = 6
    INITIALING = 7
    DOCKER_UNAVAILABLE = 8
    STORAGE_FULL = 9
    UPDATING = 10

    NAME: ClassVar[dict[int, str]] = {
        CLOSE: "closed",
        OPEN: "open",
        UNINITIALIZED: "uninitialized",
        OPENING: "opening",
        CLOSING: "closing",
        MAINTENANCE: "under maintenance",
        DOCKER_UNAVAILABLE: "upgrading",
        STORAGE_FULL: "disk full",
        UPDATING: "updating",
    }

    # Maps the "clickable operations" on the control panel: target state -> state to send.
    # For example the UPDATING state must send CLOSE (it cannot really be set to 10).
    CONTROL_MAP: ClassVar[dict[int, int]] = {
        CLOSE: CLOSE,
        OPEN: OPEN,
        UNINITIALIZED: UNINITIALIZED,
        UPDATING: CLOSE,
    }


class PlayerStatus:
    """Rental server player status (the ``status`` param of ``search-by-server``)."""

    NORMAL = 0
    IN_BLACKLIST = 1


RENT_SERVER_PASSWORD_LENGTH = 6
"""The rental server password is always 6 characters (official ``RENT_SERVER_PASSWORD_LENGTH``)."""

RENT_SERVER_ICONS = [15, 16, 17, 18, 19, 20, 21]
"""Selectable rental server icon indices (7 officially; captures showed 1-5, official is 15-21)."""


# ════════════════════════════════════════════════════════════════════
# Avatar entity fields (user-head-url-v2 as captured + official)
# ════════════════════════════════════════════════════════════════════

HEAD_URL_V2_FIELDS = (
    "id", "type", "url", "pc_url", "static_url", "tips", "name",
    "status", "first_type", "item_id", "item_name",
    "jump_type", "jump_target", "is_gif",
)
"""Fields of each entry in ``/user-head-url-v2``. ``status``: 0=not owned, 1=owned;
``type``: 0=static, 1=animated GIF; static ``item_id`` starts at 2000001."""


__all__ = [
    "CORE",
    "GATEWAY",
    "HEAD_URL_V2_FIELDS",
    "LOBBY_GAME",
    "RENT_GAME",
    "RENT_SERVER_ICONS",
    "RENT_SERVER_PASSWORD_LENGTH",
    "USER",
    "WEB",
    "PlayerStatus",
    "RentServerStatus",
]
