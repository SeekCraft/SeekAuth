"""NetEase MPay guest account creation (ported from funauth-2 g79client, Go).

Flow (see ``auth/funauth/funauth-2-main/modules/g79client/account/mpay/``):

1. ``POST /mpay/games/{project}/devices`` registers a device (201 returns ``key``/``id``);
2. ``POST /mpay/games/{project}/devices/{id}/users/by_guest`` creates the guest
   (also 201; if risk control steps in it returns 200/4xx + ``{"code","reason","verify_url"}``
   -- the user opens ``verify_url`` on the official NetEase page to pass verification
   (anti-addiction / human check) and then retries this call unchanged);
3. on success take ``user.id``/``user.token`` to build the sauth cookie (``is_unisdk_guest=1``)
   and hand it to :func:`seek_auth.g79.G79Client.authenticate_with_sauth` to finish NetEase-side
   authentication and binding.

No real-name data and no image captcha are needed anywhere: verification happens on the
official NetEase ``verify_url`` page.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from collections.abc import Mapping
from typing import Any

import httpx

MPAY_BASE_URL = "https://service.mkey.163.com"
MPAY_PROJECT_ID = "aecfrxodyqaaaajp-g-x19"
MPAY_USER_AGENT = "com.netease.x19/840268037 NeteaseMobileGame/a5.2.0 (23117RK66C;32)"

_DEFAULT_GV = "840268037"
_DEFAULT_GVN = "3.3.15.268037"
_DEFAULT_CV = "a5.2.0"
_DEFAULT_SV = "32"
_DEFAULT_CLOUD_EXTRA = "e30="
_DEFAULT_OPT_FIELDS = (
    "nickname,avatar,realname_status,mobile_bind_status,exit_popup_info,"
    "mask_related_mobile,related_login_status"
)
_DEFAULT_RAM = "8034369536"
_DEFAULT_ROM = "128849018880"
_DEFAULT_MCOUNT_APP_KEY = "EEkEEXLymcNjM42yLY3Bn6AO15aGy4yq"


class MpayError(Exception):
    """MPay API failure (network / protocol layer)."""


class MpayVerifyRequiredError(MpayError):
    """MPay requires the user to pass verification on the official NetEase page.

    :param verify_url: official NetEase verification page (may be empty -- retry later then).
    :param reason: the reason text returned by NetEase.
    :param code: the error code returned by NetEase.
    """

    def __init__(self, verify_url: str, reason: str, code: int) -> None:
        self.verify_url = verify_url
        self.reason = reason
        self.code = code
        # Extract the ticket from verify_url (used by poll_verify_result)
        self.ticket = ""
        if verify_url:
            from urllib.parse import parse_qs, urlparse

            qs = parse_qs(urlparse(verify_url).query)
            self.ticket = (qs.get("ticket") or [""])[0]
        hint = f"MPay requires verification code={code} reason={reason or 'unspecified'}"
        if verify_url:
            hint += f" verify_url={verify_url}"
        super().__init__(hint)


def _hex(n: int) -> str:
    return secrets.token_hex(n)


def _mac_hex() -> str:
    """Hex string for a random MAC (mirrors Go ``randomHex(16)``, no colon separators)."""
    return _hex(16)


def _md5_hex(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def _aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """AES-ECB + PKCS7 (mirrors Go ``utils.AesECBEncrypt``)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    padder = PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(padded) + enc.finalize()


class MpayClient:
    """MPay guest account client. One instance = one virtual device + one guest account."""

    def __init__(self, http: httpx.AsyncClient | None = None) -> None:
        self._http = http or httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": MPAY_USER_AGENT},
        )
        self.device_id = ""
        self.device_key = ""
        self._unique_id = ""
        self._udid = ""
        self._mac = ""
        self._mcount_id = ""
        self._transid = ""

    async def aclose(self) -> None:
        await self._http.aclose()

    # ── device state export / restore ──

    def dump_device(self) -> dict[str, str]:
        """Export the registered device so the caller can stash it and reuse it on retry.

        NetEase binds a device fingerprint **once, at registration**: after risk control demands
        verification, the user verifies *this* device, and retrying on a fresh device triggers
        risk control again (an observed infinite loop). So the state must be carried out.
        """
        return {
            "device_id": self.device_id,
            "device_key": self.device_key,
            "unique_id": self._unique_id,
            "udid": self._udid,
            "mac": self._mac,
            "mcount_id": self._mcount_id,
            "transid": self._transid,
        }

    def load_device(self, data: Mapping[str, str]) -> None:
        """Restore device state exported by :meth:`dump_device` (skipping device registration)."""
        self.device_id = str(data.get("device_id") or "")
        self.device_key = str(data.get("device_key") or "")
        self._unique_id = str(data.get("unique_id") or "")
        self._udid = str(data.get("udid") or "")
        self._mac = str(data.get("mac") or "")
        self._mcount_id = str(data.get("mcount_id") or "")
        self._transid = str(data.get("transid") or "")
        if not self.device_id or not self.device_key:
            raise MpayError("incomplete restored device info (device_id/device_key missing)")

    # ── internals ──

    def _base_form(self) -> dict[str, str]:
        return {
            "game_id": MPAY_PROJECT_ID,
            "gv": _DEFAULT_GV,
            "gvn": _DEFAULT_GVN,
            "cv": _DEFAULT_CV,
            "sv": _DEFAULT_SV,
            "app_type": "games",
            "app_mode": "2",
            "app_channel": "netease",
            "mcount_app_key": _DEFAULT_MCOUNT_APP_KEY,
            "mcount_transaction_id": self._mcount_id,
            "transid": self._transid,
            "_cloud_extra_base64": _DEFAULT_CLOUD_EXTRA,
            "sc": "1",
        }

    async def _post_form(self, path: str, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
        r = await self._http.post(f"{MPAY_BASE_URL}{path}", data=form)
        try:
            body: dict[str, Any] = r.json()
        except ValueError as e:
            raise MpayError(f"MPay response is not JSON: {r.text[:120]!r}") from e
        return r.status_code, body

    @staticmethod
    def _check_verify(body: dict[str, Any]) -> None:
        """MPay error convention: a ``code`` field means a business error.

        Mirrors funauth-2 ``checkMPayError``: a success response has no code; when verification
        is needed it returns ``{"code","reason","verify_url"}``. verify_url is the official
        NetEase page; the user verifies in a browser and then retries.
        """
        code = body.get("code")
        if code is None:
            return
        raise MpayVerifyRequiredError(
            str(body.get("verify_url") or ""),
            str(body.get("reason") or ""),
            int(code),
        )

    # ── public API ──

    async def register_device(self) -> None:
        """Register a virtual device (201 Created returns key/id).

        Note: frequent calls trigger risk control; production should cache and reuse devices.
        """
        ts = int(time.time())
        self._unique_id = f"{uuid.uuid4()}{ts}20114"
        self._udid = _hex(8)
        self._mac = _mac_hex()
        self._mcount_id = f"{self._udid}_{ts}114_307044629"
        self._transid = f"{self._udid}_{ts}10114_399039478"

        # Device shape mirrors Go buildDeviceForm: Android tablet (MuMu emulator
        # 23117RK66C), matching the model declared in the User-Agent -- NetEase builds
        # device fingerprints from these fields; a wrong shape means "user login expired".
        form = {
            "mac": self._mac,
            "urs_udid": _hex(20),
            "init_urs_device": "0",
            "unique_id": self._unique_id,
            "brand": "Redmi",
            "device_name": "MuMu",
            "device_type": "tablet",
            "device_model": "23117RK66C",
            "resolution": "900*1600",
            "system_name": "Android",
            "system_version": "12",
            "udid": self._udid,
            "app_channel": "netease",
            "ext_ci": _hex(32),
            "ci_code": "3",
            "game_id": MPAY_PROJECT_ID,
            "gv": _DEFAULT_GV,
            "gvn": _DEFAULT_GVN,
            "cv": _DEFAULT_CV,
            "sv": _DEFAULT_SV,
            "app_type": "games",
            "app_mode": "2",
            "mcount_app_key": _DEFAULT_MCOUNT_APP_KEY,
            "mcount_transaction_id": self._mcount_id,
            "transid": self._transid,
            "_cloud_extra_base64": _DEFAULT_CLOUD_EXTRA,
        }
        status, body = await self._post_form(
            f"/mpay/games/{MPAY_PROJECT_ID}/devices", form
        )
        if status != 201:
            self._check_verify(body)
            raise MpayError(f"device registration failed HTTP {status}: {body}")
        dev = body.get("device") or {}
        self.device_id = str(dev.get("id") or "")
        self.device_key = str(dev.get("key") or "")
        if not self.device_id or not self.device_key:
            raise MpayError(f"device response is missing id/key: {body}")

    async def create_guest(self) -> dict[str, Any]:
        """Create a guest account, returning ``{"sdkuid","sessionid",...}``.

        Raises :class:`MpayVerifyRequiredError` (carrying ``verify_url``) when MPay risk control
        triggers -- the caller passes it on so the user can verify and then retry.

        ``params`` mirrors Go ``Guest()``: AES-ECB(device.key) over ``"{}"``, then hex --
        not arbitrary bytes; NetEase decrypts with the device key to validate them.
        """
        if not self.device_id or not self.device_key:
            raise MpayError("device not registered, call register_device() first")

        encrypted = _aes_ecb_encrypt(bytes.fromhex(self.device_key), b"{}")
        form = self._base_form()
        form.update({
            "opt_fields": _DEFAULT_OPT_FIELDS,
            "params": encrypted.hex(),
        })
        status, body = await self._post_form(
            f"/mpay/games/{MPAY_PROJECT_ID}/devices/{self.device_id}/users/by_guest",
            form,
        )
        if status != 201:
            self._check_verify(body)
            raise MpayError(f"guest creation failed HTTP {status}: {body}")
        self._check_verify(body)

        user = body.get("user") or {}
        token = user.get("token") or ""
        uid = user.get("id") or ""
        if not token or not uid:
            raise MpayError(f"guest response is missing user.token/user.id: {body}")
        # The server may echo back udid; follow it
        if user.get("udid"):
            self._udid = str(user["udid"])
        return {"sdkuid": str(uid), "sessionid": str(token), "udid": self._udid, "deviceid": self.device_id}

    async def poll_verify_result(self, ticket: str) -> dict[str, Any] | None:
        """Fetch the verification result by ticket after the user passes SMS verification.

        2026-10-17 mitmproxy capture confirmed: once the user completes SMS verification inside
        the ``verify_url`` (WebView page), the WebView itself POSTs
        ``/mpay/api/reverify/upload_sms/result`` -> a full ``user`` object (token/id/login_type).

        **This is the key fix for "user verified but the retry still fails"**: the old code only
        made the user open ``verify_url``, but the result stayed inside the WebView and the server
        could not see it; on retry ``create_guest()`` hit ``by_guest`` again -- by then NetEase may
        have created the guest but with a wrong device binding, triggering risk control again.

        This method is called **first** on the retry path: it asks NetEase, with ``ticket``,
        whether verification passed. If so the credentials come back and ``by_guest`` is skipped.

        :param ticket: the ``ticket`` query-string param from ``verify_url``.
        :return: guest credentials ``{"sdkuid","sessionid","udid","deviceid"}``;
            None when verification is unfinished or the ticket is invalid.
        """
        if not ticket:
            return None
        form = {
            "ticket": ticket,
            "lang": "",
            "cv": _DEFAULT_CV,
            "gv": _DEFAULT_GV,
            "app_mode": "2",
            "app_channel": "netease",
            "chg_pwd": "0",
            "gas_env": "",
        }
        try:
            r = await self._http.post(
                f"{MPAY_BASE_URL}/mpay/api/reverify/upload_sms/result",
                data=form,
            )
            if r.status_code != 200:
                return None
            body = r.json()
        except Exception:  # noqa: BLE001
            return None
        user = body.get("user")
        if not isinstance(user, dict):
            return None
        token = user.get("token") or ""
        uid = user.get("id") or ""
        if not token or not uid:
            return None
        if user.get("udid"):
            self._udid = str(user["udid"])
        return {"sdkuid": str(uid), "sessionid": str(token), "udid": self._udid, "deviceid": self.device_id}

    def build_sauth_cookie(self, guest: dict[str, str]) -> str:
        """Assemble guest credentials into a ``{"sauth_json": "<embedded JSON>"}`` cookie.

        Fields mirror funauth-2 ``newSauth`` + ``WPLauncherCookieMpay``;
        ``is_unisdk_guest=1`` (the guest marker). Note the double encoding: the value of
        ``sauth_json`` is a **string** (embedded JSON), not an object -- both the g79-side
        ``_unwrap_sauth`` and the cookies.txt line format expect that shape, so an object
        raises a SauthJSON parse error.
        """
        sauth = {
            "aim_info": '{"aim":"127.0.0.1","country":"CN","tz":"+0800","tzid":""}',
            "app_channel": "netease",
            "client_login_sn": secrets.token_hex(8).upper(),
            "deviceid": guest["deviceid"],
            "gameid": "x19",
            "gas_token": "",
            "get_access_token": "1",
            "ip": "127.0.0.1",
            "is_unisdk_guest": 1,
            "login_channel": "netease",
            "platform": "ad",
            "sdk_version": "5.16.0",
            "sdkuid": guest["sdkuid"],
            "sessionid": guest["sessionid"],
            "source_app_channel": "netease",
            "source_platform": "ad",
            "udid": guest["udid"],
        }
        inner = json.dumps(sauth, separators=(",", ":"), ensure_ascii=False)
        return json.dumps(
            {"sauth_json": inner}, separators=(",", ":"), ensure_ascii=False
        )

    # ── real name (mirrors Go ``Device.AuthRealName``) ──

    async def auth_realname(
        self, guest: Mapping[str, str], realname: str, id_num: str
    ) -> None:
        """Submit real-name verification (``/mpay/api/users/realname/update_by_token``).

        :param guest: guest credentials containing ``sdkuid``/``sessionid``.
        :param realname: the real name.
        :param id_num: the ID card number.

        Real-name data is **only forwarded to NetEase and never stored here** (there is no
        reason to keep legally identifying data). Only needed when NetEase explicitly asks
        (``need_realname_auth``); the official page can do it too, so prefer sending users there.
        """
        if not realname or not id_num:
            raise MpayError("real-name verification needs a name and an ID number")
        form = self._base_form()
        form.update({
            "device_id": self.device_id,
            "user_id": str(guest.get("sdkuid") or ""),
            "token": str(guest.get("sessionid") or ""),
            "realname": realname,
            "id_region": "86",
            "id_num": id_num,
        })
        status, body = await self._post_form(
            "/mpay/api/users/realname/update_by_token", form
        )
        if status != 200:
            self._check_verify(body)
            raise MpayError(f"real-name verification failed HTTP {status}: {body}")
        self._check_verify(body)
