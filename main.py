import os
import asyncio
import httpx
import hmac
import hashlib
import json
import time
import uuid
from urllib.parse import parse_qsl
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from firebase_db import db
from google.cloud import firestore as gcf
from google.cloud.firestore_v1.field_path import FieldPath

load_dotenv()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
BOT_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
DELIVERY_BOT_TOKEN = (os.getenv("DELIVERY_BOT_TOKEN") or "").strip()
MONETAG_POSTBACK_SECRET = (os.getenv("MONETAG_POSTBACK_SECRET") or "").strip()
MONETAG_ZONE_ID = "12170493"
# Optional. Example: https://t.me/YourBot/appshortname  (the Mini App direct link, without ?startapp=)
# If empty, the link is built as https://t.me/<bot_username>?startapp=ref_<id> (needs a Main Mini App in BotFather).
REFERRAL_LINK_BASE = (os.getenv("REFERRAL_LINK_BASE") or "").strip().rstrip("/")
DAILY_AD_COIN_LIMIT = 10  # max coin ads per user per day
AD_REWARD_COINS = 2        # coins earned per watched ad
REFERRAL_REWARD_COINS = 5  # coins the referrer gets when a friend watches their first video
VIDEO_COIN_COST = 3        # coins needed to get one video without ads
JOIN_BONUS_COINS = 5       # coins a brand-new user gets on first join
CHECKIN_REWARD_COINS = 1   # coins for the daily check-in
SHARE_VIDEO_REWARD_COINS = 2  # coins the sharer gets when someone watches a video from their link
DAY_RESET_UTC_OFFSET_HOURS = int(os.getenv("DAY_RESET_UTC_OFFSET_HOURS") or 6)  # daily counter resets at local midnight (default UTC+6)

# Render environment variables:
# TELEGRAM_WEBHOOK_SECRET = a long random string (letters, numbers, _ and -)
# WEBHOOK_URL = https://telegram-video-miniapp.onrender.com/telegram/webhook
TELEGRAM_WEBHOOK_SECRET = (os.getenv("TELEGRAM_WEBHOOK_SECRET") or "").strip()
WEBHOOK_URL = (
    os.getenv("WEBHOOK_URL")
    or "https://telegram-video-miniapp.onrender.com/telegram/webhook"
).strip()

app = FastAPI(
    title="Telegram Video Mini App API",
    description="Backend API for Telegram Video Mini App"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to your Vercel domain before production hardening.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Video(BaseModel):
    title: str
    category: str = ""  # Backward compatibility with videos saved using one category.
    categories: list[str] = []
    status: str = "active"
    thumbnail: str = ""
    # Optional Telegram fields. Existing dashboard requests can omit these.
    telegram_file_id: str | None = None
    channel_chat_id: str | None = None
    channel_message_id: int | None = None


class AdminLogin(BaseModel):
    username: str
    password: str


class Thumbnail(BaseModel):
    file_id: str


class Category(BaseModel):
    name: str


class TelegramAuthRequest(BaseModel):
    init_data: str


class AdSessionRequest(BaseModel):
    init_data: str
    video_id: str


class AdStatusRequest(BaseModel):
    init_data: str
    session_id: str


class VideoProgressRequest(BaseModel):
    init_data: str
    video_id: str = ""
    video_ids: list[str] | None = None


class UseCoinRequest(BaseModel):
    init_data: str
    video_id: str


def verify_telegram_init_data(init_data: str):
    """Verify Telegram Mini App initData using the bot token."""
    if not BOT_TOKEN:
        raise HTTPException(status_code=500, detail="Telegram bot token missing")

    try:
        pairs = parse_qsl(init_data, keep_blank_values=True, strict_parsing=True)
        values = dict(pairs)
        if len(values) != len(pairs):
            raise ValueError("Duplicate initData fields")

        received_hash = values.pop("hash", None)
        if not received_hash:
            raise ValueError("Missing hash")

        data_check_string = "\n".join(
            f"{key}={value}" for key, value in sorted(values.items())
        )
        secret_key = hmac.new(
            b"WebAppData", BOT_TOKEN.encode("utf-8"), hashlib.sha256
        ).digest()
        calculated_hash = hmac.new(
            secret_key, data_check_string.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(calculated_hash, received_hash):
            raise ValueError("Invalid Telegram signature")

        auth_date = int(values.get("auth_date", "0"))
        now = int(time.time())
        if auth_date <= 0 or auth_date > now + 60 or now - auth_date > 86400:
            raise ValueError("Expired or invalid auth_date")

        user = json.loads(values.get("user", ""))
        if not isinstance(user, dict) or not user.get("id"):
            raise ValueError("Telegram user data missing")
        if _is_banned(str(user["id"])):
            raise HTTPException(status_code=403, detail="Your account has been blocked")
        return user, auth_date

    except (ValueError, TypeError, json.JSONDecodeError):
        raise HTTPException(
            status_code=401, detail="Invalid or expired Telegram initData"
        )


# =========================
# REFERRAL / REWARD COIN HELPERS
# =========================

def _get_start_param(init_data: str) -> str:
    """start_param is part of the signed initData; call only after verify_telegram_init_data."""
    try:
        return dict(parse_qsl(init_data, keep_blank_values=True)).get("start_param", "") or ""
    except ValueError:
        return ""


_bot_username_cache = {}


def _build_referral_link(telegram_id: str) -> str:
    base = REFERRAL_LINK_BASE
    if not base:
        name = _bot_username_cache.get("name")
        if not name and BOT_TOKEN:
            try:
                result = httpx.get(f"https://api.telegram.org/bot{BOT_TOKEN}/getMe", timeout=10).json()
                name = (result.get("result") or {}).get("username", "") if result.get("ok") else ""
                if name:
                    _bot_username_cache["name"] = name
            except Exception as exc:
                print("BOT USERNAME LOOKUP ERROR:", repr(exc))
        if not name:
            return ""
        base = f"https://t.me/{name}"
    return f"{base}?startapp=ref_{telegram_id}"


@gcf.transactional
def _reward_referrer_tx(tx, referral_ref, referrer_ref):
    snap = referral_ref.get(transaction=tx)
    if not snap.exists or (snap.to_dict() or {}).get("status") != "pending":
        return False  # no referral, or already rewarded
    now = int(time.time())
    tx.set(referrer_ref, {"coins": gcf.Increment(REFERRAL_REWARD_COINS), "referral_count": gcf.Increment(1)}, merge=True)
    tx.update(referral_ref, {"status": "rewarded", "rewarded_at": now})
    tx.set(db.collection("coin_logs").document(), {
        "telegram_id": referrer_ref.id, "type": "earn", "amount": REFERRAL_REWARD_COINS,
        "reason": "referral_first_video", "friend_id": referral_ref.id, "created_at": now,
    })
    return True


def reward_referrer_for_first_video(friend_id: str) -> bool:
    """Give the referrer 1 coin the first time a referred friend gets a video. Safe to call repeatedly."""
    referral_ref = db.collection("referrals").document(str(friend_id))
    snap = referral_ref.get()
    if not snap.exists:
        return False
    data = snap.to_dict() or {}
    referrer_id = str(data.get("referrer_id") or "")
    if data.get("status") != "pending" or not referrer_id:
        return False
    return _reward_referrer_tx(db.transaction(), referral_ref, db.collection("users").document(referrer_id))


@gcf.transactional
def _spend_coin_tx(tx, user_ref):
    snap = user_ref.get(transaction=tx)
    coins = int((snap.to_dict() or {}).get("coins", 0) or 0) if snap.exists else 0
    if coins < VIDEO_COIN_COST:
        return -1
    tx.update(user_ref, {"coins": coins - VIDEO_COIN_COST})
    return coins - VIDEO_COIN_COST


def _today_key() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() + DAY_RESET_UTC_OFFSET_HOURS * 3600))


def _ads_today(telegram_id: str) -> int:
    snap = db.collection("coin_ad_daily").document(f"{telegram_id}_{_today_key()}").get()
    return int((snap.to_dict() or {}).get("count", 0) or 0) if snap.exists else 0


@gcf.transactional
def _claim_ad_coin_tx(tx, session_ref, daily_ref, user_ref, telegram_id):
    session = session_ref.get(transaction=tx).to_dict() or {}
    if session.get("status") == "claimed":
        return "already"
    daily = daily_ref.get(transaction=tx)
    count = int((daily.to_dict() or {}).get("count", 0) or 0) if daily.exists else 0
    if count >= DAILY_AD_COIN_LIMIT:
        return "limit"
    now = int(time.time())
    tx.set(daily_ref, {"telegram_id": telegram_id, "count": count + 1, "updated_at": now}, merge=True)
    tx.set(user_ref, {"coins": gcf.Increment(AD_REWARD_COINS)}, merge=True)
    tx.update(session_ref, {"status": "claimed", "claimed_at": now})
    tx.set(db.collection("coin_logs").document(), {
        "telegram_id": telegram_id, "type": "earn", "amount": AD_REWARD_COINS,
        "reason": "watch_ad", "created_at": now,
    })
    return "ok"


from datetime import datetime, timedelta, timezone


def _week_key() -> str:
    """Date (YYYY-MM-DD) of this week's Sunday; the week resets Saturday midnight / Sunday 00:00 local time."""
    now = datetime.now(timezone.utc) + timedelta(hours=DAY_RESET_UTC_OFFSET_HOURS)
    return (now.date() - timedelta(days=(now.weekday() + 1) % 7)).isoformat()


def _count_weekly_view(video_id: str):
    """Count one watched (delivered) video for the weekly Trending list. Never raises."""
    try:
        week = _week_key()
        db.collection("video_weekly_stats").document(f"{week}_{video_id}").set({
            "week": week,
            "video_id": video_id,
            "count": gcf.Increment(1),
            "updated_at": int(time.time()),
        }, merge=True)
        _cache_clear("trending", "admin_stats")
    except Exception as exc:
        print("WEEKLY STATS ERROR:", repr(exc))


def _cleanup_expired_records(now: int):
    """Bounded cleanup of expired sessions and old terminal/analytics records."""
    cutoff_2d = now - 2 * 86400
    cutoff_30d = now - 30 * 86400
    cutoff_90d = now - 90 * 86400
    targets = (("ad_sessions", "expires_at", cutoff_2d), ("coin_ad_sessions", "expires_at", cutoff_2d))
    for collection_name, field, cutoff in targets:
        try:
            docs = db.collection(collection_name).where(field, "<", cutoff).limit(200).stream()
            batch = db.batch(); count = 0
            for doc in docs:
                batch.delete(doc.reference); count += 1
                if count >= 200: break
            if count: batch.commit()
        except Exception as exc:
            print("CLEANUP ERROR", collection_name, repr(exc))
    # Only terminal jobs are eligible; pending work is never removed by cleanup.
    for collection_name in ("scheduled_deletions", "broadcast_deliveries"):
        for state in ("deleted", "sent", "error"):
            try:
                docs = db.collection(collection_name).where("status", "==", state).where(
                    "created_at", "<", cutoff_30d
                ).order_by("created_at").limit(200).stream()
                batch = db.batch(); count = 0
                for doc in docs:
                    batch.delete(doc.reference); count += 1
                    if count >= 200: break
                if count: batch.commit()
            except Exception as exc:
                print("CLEANUP ERROR", collection_name, state, repr(exc))
    for collection_name, field, cutoff in (
        ("monetag_events", "received_at", cutoff_30d),
        ("coin_ad_daily", "updated_at", cutoff_90d),
        ("video_weekly_stats", "updated_at", cutoff_90d),
    ):
        try:
            docs = db.collection(collection_name).where(field, "<", cutoff).limit(200).stream()
            batch = db.batch(); count = 0
            for doc in docs:
                batch.delete(doc.reference); count += 1
                if count >= 200: break
            if count: batch.commit()
        except Exception as exc:
            print("CLEANUP ERROR", collection_name, repr(exc))


async def auto_delete_worker():
    """Process persistent scheduled deletions; jobs survive Render restarts."""
    last_cleanup = 0
    while True:
        try:
            now = int(time.time())
            if now - last_cleanup >= 3600:
                await asyncio.to_thread(_cleanup_expired_records, now)
                last_cleanup = now
            # Query only due jobs; the two-field composite index is provided separately.
            jobs = db.collection("scheduled_deletions").where(
                "status", "==", "pending"
            ).where("delete_at", "<=", now).order_by("delete_at").limit(100).stream()

            async with httpx.AsyncClient(timeout=20) as client:
                for job in jobs:
                    data = job.to_dict() or {}
                    if int(data.get("delete_at", now + 1)) > now:
                        continue
                    chat_id = data.get("chat_id")
                    message_id = data.get("message_id")
                    if data.get("job_type") == "notice":
                        expected_ids = {int(x) for x in (data.get("video_message_ids") or [])}
                        if expected_ids:
                            related = db.collection("scheduled_deletions").where("session_id", "==", data.get("session_id")).stream()
                            deletion_states = {
                                int((item.to_dict() or {}).get("message_id")): (item.to_dict() or {}).get("status")
                                for item in related
                                if (item.to_dict() or {}).get("message_id") is not None
                            }
                            if any(deletion_states.get(mid) != "deleted" for mid in expected_ids):
                                # Avoid re-reading an overdue notice every 15 seconds while media deletion retries.
                                job.reference.update({"delete_at": now + 60, "last_wait_at": now})
                                continue
                        if not DELIVERY_BOT_TOKEN:
                            print("Deletion notice paused: DELIVERY_BOT_TOKEN is not configured.")
                            continue
                        try:
                            notice_response = await client.post(
                                f"https://api.telegram.org/bot{DELIVERY_BOT_TOKEN}/sendMessage",
                                json={"chat_id": chat_id, "text": data.get("notice_text") or "🗑️ ভিডিওটি মুছে ফেলা হয়েছে।", "disable_web_page_preview": True}
                            )
                            notice_result = notice_response.json()
                            if notice_result.get("ok"):
                                notice_message_id = (notice_result.get("result") or {}).get("message_id")
                                notice_settings = _get_app_settings()
                                notice_delete_minutes = int(notice_settings.get("deletion_notice_auto_delete_minutes", 720))
                                if notice_message_id and notice_delete_minutes > 0:
                                    db.collection("scheduled_deletions").add({
                                        "chat_id": int(chat_id), "message_id": int(notice_message_id),
                                        "delete_at": now + notice_delete_minutes * 60,
                                        "status": "pending", "created_at": now,
                                        "session_id": str(data.get("session_id") or "") + "_notice",
                                    })
                                job.reference.set({"status": "sent", "sent_at": now, "notice_message_id": notice_message_id, "notice_auto_delete_minutes": notice_delete_minutes}, merge=True)
                            else:
                                job.reference.set({"status": "error", "error": str(notice_result)[:500]}, merge=True)
                        except Exception as exc:
                            print("DELETION NOTICE ERROR:", repr(exc))
                        continue
                    if not chat_id or not message_id:
                        job.reference.set({"status": "error", "error": "Missing message details"}, merge=True)
                        continue
                    if not DELIVERY_BOT_TOKEN:
                        print("Auto-delete paused: DELIVERY_BOT_TOKEN is not configured.")
                        break
                    try:
                        response = await client.post(
                            f"https://api.telegram.org/bot{DELIVERY_BOT_TOKEN}/deleteMessage",
                            json={"chat_id": chat_id, "message_id": int(message_id)},
                        )
                        result = response.json()
                        # Telegram may report the message is already deleted or too old.
                        if result.get("ok") or "message to delete not found" in str(result).lower():
                            job.reference.set({"status": "deleted", "deleted_at": now}, merge=True)
                        else:
                            job.reference.set({"status": "error", "error": str(result)[:500]}, merge=True)
                    except Exception as exc:
                        print("AUTO DELETE JOB ERROR:", repr(exc))

            # Broadcast deliveries use the same persistent worker.
            pending_cast_deletes = db.collection("broadcast_deliveries").where(
                "status", "==", "pending"
            ).where("delete_at", "<=", now).order_by("delete_at").limit(100).stream()
            async with httpx.AsyncClient(timeout=20) as client:
                for job in pending_cast_deletes:
                    data = job.to_dict() or {}
                    if int(data.get("delete_at", now + 1)) > now:
                        continue
                    deleted_ok = await _delete_delivery_messages(client, data)
                    if deleted_ok:
                        job.reference.set({"status": "deleted", "deleted_at": now}, merge=True)
                    else:
                        job.reference.set({"last_delete_attempt": now, "delete_attempts": gcf.Increment(1)}, merge=True)

        except Exception as exc:
            print("AUTO DELETE WORKER ERROR:", repr(exc))
        await asyncio.sleep(15)


@app.on_event("startup")
async def register_telegram_webhook():
    """Register this Render URL as the bot webhook when the app starts."""
    app.state.auto_delete_task = asyncio.create_task(auto_delete_worker())
    app.state.publish_task = asyncio.create_task(publish_worker())
    _refresh_coin_settings(force=True)
    if not TELEGRAM_WEBHOOK_SECRET or not WEBHOOK_URL:
        print("Telegram webhook setup skipped: required environment variable missing.")
        return

    # The main bot receives channel uploads and handles /start + Verify callbacks.
    tokens = [BOT_TOKEN] if BOT_TOKEN else []
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            for token in tokens:
                response = await client.post(
                    f"https://api.telegram.org/bot{token}/setWebhook",
                    json={
                        "url": WEBHOOK_URL,
                        "secret_token": TELEGRAM_WEBHOOK_SECRET,
                        "allowed_updates": ["channel_post", "edited_channel_post", "message", "callback_query"],
                    },
                )
                response.raise_for_status()
                result = response.json()
                if result.get("ok"):
                    print("Telegram webhook registered successfully for a configured bot.")
                else:
                    print("Telegram webhook registration failed:", result)
    except Exception as exc:
        # Do not prevent FastAPI from starting if Telegram is temporarily unavailable.
        print("TELEGRAM WEBHOOK SETUP ERROR:", repr(exc))


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request):
    """Receive new video posts from the Telegram channel."""
    if not TELEGRAM_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook is not configured")

    supplied_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not hmac.compare_digest(supplied_secret, TELEGRAM_WEBHOOK_SECRET):
        raise HTTPException(status_code=403, detail="Invalid webhook secret")

    update = await request.json()

    # Delivery bot entry point: /start shows Join Channel + Verify buttons.
    incoming = update.get("message") or {}
    incoming_text = str(incoming.get("text") or "").strip()
    if incoming_text.split(" ", 1)[0].split("@", 1)[0] == "/start":
        chat_id = (incoming.get("chat") or {}).get("id")
        settings = _get_app_settings()
        channel = settings.get("join_channel") or "@ViralDuniyaaBD"
        keyboard = {"inline_keyboard": [[
            {"text": "📢 Join Channel", "url": "https://t.me/" + channel.lstrip("@")},
            {"text": "✅ Verify", "callback_data": "verify_join"},
        ]]}
        text = "ভিডিও পেতে প্রথমে আমাদের চ্যানেলে Join করুন, তারপর Verify বাটনে চাপ দিন।"
        if not settings.get("join_verification_enabled"):
            text = "স্বাগতম! এখন Mini App থেকে ভিডিও নিতে পারবেন।"
            keyboard = None
        if chat_id and BOT_TOKEN:
            async with httpx.AsyncClient(timeout=15) as client:
                await client.post(
                    f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                    json={"chat_id": chat_id, "text": text, **({"reply_markup": keyboard} if keyboard else {})}
                )
        return {"success": True, "message": "Start handled"}

    callback = update.get("callback_query") or {}
    if callback:
        callback_id = callback.get("id")
        callback_data = callback.get("data")
        callback_user = callback.get("from") or {}
        if callback_data == "verify_join" and callback_user.get("id"):
            joined = False
            try:
                joined = _channel_membership(str(callback_user["id"]))
            except HTTPException as exc:
                if callback_id and BOT_TOKEN:
                    async with httpx.AsyncClient(timeout=15) as client:
                        await client.post(
                            f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery",
                            json={"callback_query_id": callback_id, "text": exc.detail, "show_alert": True}
                        )
                return {"success": True, "message": "Verification unavailable"}
            async with httpx.AsyncClient(timeout=15) as client:
                if callback_id:
                    await client.post(
                        f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery",
                        json={"callback_query_id": callback_id,
                              "text": "Membership verified!" if joined else "আগে চ্যানেলে Join করুন।",
                              "show_alert": not joined}
                    )
                if joined and (callback.get("message") or {}).get("chat", {}).get("id"):
                    await client.post(
                        f"https://api.telegram.org/bot{BOT_TOKEN}/editMessageText",
                        json={"chat_id": callback["message"]["chat"]["id"],
                              "message_id": callback["message"]["message_id"],
                              "text": "✅ আপনার Channel Membership Verify হয়েছে। এখন Mini App থেকে ভিডিও নিতে পারবেন।"}
                    )
            return {"success": True, "joined": joined}
        return {"success": True, "message": "Callback ignored"}

    message = update.get("channel_post") or update.get("edited_channel_post")
    if not message:
        return {"success": True, "message": "Update ignored"}

    chat = message.get("chat") or {}
    chat_id = str(chat.get("id", ""))
    message_id = message.get("message_id")
    if not chat_id or not message_id:
        return {"success": True, "message": "Channel message information missing"}

    # Save channel photos to the same collection used by the Admin Dashboard gallery.
    # Use the largest Telegram photo size and a stable ID to avoid duplicate entries.
    photos = message.get("photo") or []
    largest_photo = max(
        (photo for photo in photos if photo.get("file_id")),
        key=lambda photo: int(photo.get("file_size", 0) or 0),
        default=None,
    )
    image_document = message.get("document") or {}
    document_is_image = str(image_document.get("mime_type") or "").lower().startswith("image/")
    image_file = largest_photo or (
        image_document if document_is_image and image_document.get("file_id") else None
    )
    if image_file:
        thumbnail_id = f"{chat_id}_{message_id}"
        db.collection("thumbnails").document(thumbnail_id).set({
            "file_id": image_file["file_id"],
            "channel_chat_id": chat_id,
            "channel_message_id": int(message_id),
            "caption": (message.get("caption") or "").strip(),
            "source": "channel",
            "created_at": int(message.get("date") or time.time()),
            "updated_at": int(time.time()),
        }, merge=True)
        if message.get("media_group_id"):
            _add_album_item(chat_id, str(message["media_group_id"]), message, "photo")
        return {
            "success": True,
            "message": "Channel thumbnail saved",
            "thumbnail_id": thumbnail_id,
        }

    video = message.get("video")
    if not video or not video.get("file_id"):
        return {"success": True, "message": "Channel post ignored (not a photo or video)"}

    if message.get("media_group_id"):
        _add_album_item(chat_id, str(message["media_group_id"]), message, "video")
        return {"success": True, "message": "Album video saved"}

    # One Firestore document per channel message prevents duplicate video records.
    document_id = f"{chat_id}_{message_id}"
    video_ref = db.collection("videos").document(document_id)
    existing = video_ref.get()
    old_data = existing.to_dict() if existing.exists else {}

    caption = (message.get("caption") or "").strip()
    file_name = (video.get("file_name") or "").strip()
    title = old_data.get("title") or caption or file_name or "New Telegram Video"

    video_data = {
        "title": title,
        "category": old_data.get("category", ""),
        "status": old_data.get("status", "pending"),
        "thumbnail": old_data.get("thumbnail", ""),
        "telegram_file_id": video["file_id"],
        "channel_chat_id": chat_id,
        "channel_message_id": int(message_id),
        "duration": video.get("duration"),
        "file_name": file_name,
        "updated_at": int(time.time()),
    }
    if not existing.exists:
        video_data["created_at"] = int(time.time())

    video_ref.set(video_data, merge=True)
    return {"success": True, "message": "Channel video saved", "video_id": document_id}


# Small process-local TTL caches reduce repeated Firestore reads. Cache is invalidated on writes.
_TTL_CACHE = {}
_CATEGORY_CACHE_TTL = 300
_SETTINGS_CACHE_TTL = 30
_STATS_CACHE_TTL = 30

def _cache_get(key):
    item = _TTL_CACHE.get(key)
    if not item or item[0] <= time.time():
        _TTL_CACHE.pop(key, None)
        return None
    return item[1]

def _cache_set(key, value, ttl):
    _TTL_CACHE[key] = (time.time() + ttl, value)
    return value

def _cache_clear(*keys):
    for key in keys:
        _TTL_CACHE.pop(key, None)

@app.post("/auth/telegram")
def telegram_login(payload: TelegramAuthRequest):
    user, auth_date = verify_telegram_init_data(payload.init_data)
    telegram_id = str(user["id"])
    user_ref = db.collection("users").document(telegram_id)
    existing = user_ref.get()
    now = int(time.time())

    profile_fields = {
        "telegram_id": telegram_id,
        "first_name": user.get("first_name", ""),
        "last_name": user.get("last_name", ""),
        "username": user.get("username", ""),
        "language_code": user.get("language_code", ""),
        "photo_url": user.get("photo_url", ""),
    }
    is_new_user = not existing.exists
    old_user = existing.to_dict() or {}
    profile_changes = {k: v for k, v in profile_fields.items() if old_user.get(k, "") != v}
    # last_seen is written at most once per 15 minutes; auth still refreshes the session response.
    if is_new_user or now - int(old_user.get("last_seen", 0) or 0) >= 900:
        profile_changes["last_seen"] = now
    if is_new_user:
        profile_changes["created_at"] = now
    if profile_changes:
        user_ref.set(profile_changes, merge=True)
    # Preserve the original auth response shape without forcing a last_seen database write.
    profile = {**profile_fields, "last_seen": now, "telegram_auth_date": auth_date}

    # Join bonus: once per new user. create() fails if the log already exists, so it can never be given twice.
    join_bonus_given = False
    if is_new_user:
        try:
            db.collection("coin_logs").document(f"join_{telegram_id}").create({
                "telegram_id": telegram_id, "type": "earn", "amount": JOIN_BONUS_COINS,
                "reason": "join_bonus", "created_at": now,
            })
            user_ref.set({"coins": gcf.Increment(JOIN_BONUS_COINS)}, merge=True)
            join_bonus_given = True
        except Exception as exc:
            print("JOIN BONUS ERROR:", repr(exc))

    # Referral: only a brand-new user who opened a valid ref_ link is counted.
    if is_new_user and _get_app_settings()["referral_enabled"]:
        try:
            start_param = _get_start_param(payload.init_data)
            if start_param.startswith("ref_"):
                referrer_id = start_param[4:].strip()
                if (
                    referrer_id.isdigit()
                    and referrer_id != telegram_id
                    and db.collection("users").document(referrer_id).get().exists
                ):
                    # create() fails if a referral already exists, so a user can never get two referrers.
                    db.collection("referrals").document(telegram_id).create({
                        "referrer_id": referrer_id,
                        "friend_id": telegram_id,
                        "status": "pending",
                        "created_at": now,
                    })
                    user_ref.set({"referred_by": referrer_id}, merge=True)
        except Exception as exc:
            print("REFERRAL SAVE ERROR:", repr(exc))

    # Shared video link (v_<video_id>_<sharer_id>): remember the visit so the sharer is rewarded when this user watches it.
    try:
        param = _get_start_param(payload.init_data) if _get_app_settings()["video_share_enabled"] else ""
        if param.startswith("v_") and len(param.split("_", 2)) == 3:
            _, shared_video, sharer_id = param.split("_", 2)
            already_watched = (
                db.collection("user_video_progress").document(f"{telegram_id}_{shared_video}").get().to_dict() or {}
            ).get("status") == "unlocked"
            if (
                sharer_id.isdigit() and sharer_id != telegram_id and not already_watched
                and db.collection("users").document(sharer_id).get().exists
                and db.collection("videos").document(shared_video).get().exists
            ):
                # create() fails if a visit already exists, so the first sharer keeps the credit.
                db.collection("share_visits").document(f"{telegram_id}_{shared_video}").create({
                    "sharer_id": sharer_id, "viewer_id": telegram_id, "video_id": shared_video,
                    "status": "pending", "created_at": now,
                })
    except Exception as exc:
        print("SHARE VISIT ERROR:", repr(exc))

    user_data = user_ref.get().to_dict() or {}
    return {
        "success": True,
        "message": "Telegram authentication successful",
        "user": profile,
        "coins": int(user_data.get("coins", 0) or 0),
        "join_bonus": JOIN_BONUS_COINS,
        "join_bonus_given": join_bonus_given,
        "referral_count": int(user_data.get("referral_count", 0) or 0),
        "checkin_reward": CHECKIN_REWARD_COINS,
        "share_reward": SHARE_VIDEO_REWARD_COINS,
        "checked_in_today": user_data.get("last_checkin") == _today_key(),
        "referral_link": _build_referral_link(telegram_id) if _get_app_settings()["referral_enabled"] else "",
        "ads_today": _ads_today(telegram_id),
        "ads_limit": DAILY_AD_COIN_LIMIT,
        "video_cost": VIDEO_COIN_COST,
        "ad_reward": AD_REWARD_COINS,
        "referral_reward": REFERRAL_REWARD_COINS,
    }


@app.post("/video-progress/list")
def list_video_progress(payload: VideoProgressRequest):
    """Return this Telegram user's clicked/unlocked state for each video."""
    user, _ = verify_telegram_init_data(payload.init_data)
    telegram_id = str(user["id"])
    requested_ids = list(dict.fromkeys(str(x) for x in (payload.video_ids or []) if x))[:30]
    progress = {}
    if payload.video_ids is not None:
        # Progress documents have deterministic IDs; read only the current page's records.
        for video_id in requested_ids:
            snap = db.collection("user_video_progress").document(f"{telegram_id}_{video_id}").get()
            data = snap.to_dict() or {}
            if data.get("status") in ("clicked", "unlocked"):
                progress[video_id] = data["status"]
    else:
        # Backward compatibility for older clients; new clients always send page IDs.
        for record in db.collection("user_video_progress").where("telegram_id", "==", telegram_id).stream():
            data = record.to_dict() or {}
            video_id = str(data.get("video_id") or "")
            if video_id and data.get("status") in ("clicked", "unlocked"):
                progress[video_id] = data["status"]
    return {"success": True, "progress": progress}


@app.post("/video-progress/view")
def mark_video_clicked(payload: VideoProgressRequest):
    """Record a thumbnail click without downgrading an already-unlocked video."""
    user, _ = verify_telegram_init_data(payload.init_data)
    if not payload.video_id:
        raise HTTPException(status_code=400, detail="Video ID is required")
    video_ref = db.collection("videos").document(payload.video_id)
    if not video_ref.get().exists:
        raise HTTPException(status_code=404, detail="Video not found")

    telegram_id = str(user["id"])
    progress_ref = db.collection("user_video_progress").document(
        f"{telegram_id}_{payload.video_id}"
    )
    existing = progress_ref.get()
    old_data = existing.to_dict() if existing.exists else {}
    if old_data.get("status") not in ("clicked", "unlocked"):
        progress_ref.set({
            "telegram_id": telegram_id,
            "video_id": payload.video_id,
            "status": "clicked",
            "clicked_at": old_data.get("clicked_at", int(time.time())),
            "updated_at": int(time.time()),
        }, merge=True)
    return {"success": True}


@app.post("/ad-sessions")
def create_ad_session(payload: AdSessionRequest):
    """Create two unique Monetag ymid values for one video-unlock attempt."""
    user, _ = verify_telegram_init_data(payload.init_data)
    _require_channel_membership(str(user["id"]))
    telegram_id = str(user["id"])
    video_ref = db.collection("videos").document(payload.video_id)
    video_snapshot = video_ref.get()
    if not video_snapshot.exists:
        raise HTTPException(status_code=404, detail="Video not found")
    video = video_snapshot.to_dict() or {}
    if video.get("status", "active") != "active":
        raise HTTPException(status_code=403, detail="This video is not active")
    if not video.get("channel_chat_id") or not video.get("channel_message_id"):
        raise HTTPException(status_code=409, detail="This video is not connected to a Telegram channel message")

    session_id = uuid.uuid4().hex
    ymid1 = f"{session_id}_a1"
    ymid2 = f"{session_id}_a2"
    now = int(time.time())
    db.collection("ad_sessions").document(session_id).set({
        "telegram_id": telegram_id,
        "video_id": payload.video_id,
        "ymid1": ymid1,
        "ymid2": ymid2,
        "created_at": now,
        "expires_at": now + 1800,
        "min_ad_gap_seconds": max(1, _get_app_settings()["popup_min_seconds"] - 1),
        "status": "waiting_ads",
    })
    return {"success": True, "session_id": session_id, "ymid1": ymid1, "ymid2": ymid2}


@app.get("/monetag/postback")
def monetag_postback(
    secret: str = "", ymid: str = "", zone_id: str = "",
    event_type: str = "", reward_event_type: str = "",
    telegram_id: str = "", estimated_price: str = "",
):
    """Accept only Monetag-confirmed valued impression postbacks."""
    if not MONETAG_POSTBACK_SECRET or not hmac.compare_digest(secret, MONETAG_POSTBACK_SECRET):
        raise HTTPException(status_code=403, detail="Invalid postback secret")
    if zone_id != MONETAG_ZONE_ID or event_type != "impression" or reward_event_type != "valued" or not ymid:
        return {"success": True, "ignored": True}

    # Coin ad (watch one ad, earn one coin): ymid is <session_id>_c1
    if ymid.endswith("_c1"):
        coin_snap = db.collection("coin_ad_sessions").document(ymid[:-3]).get()
        if not coin_snap.exists:
            return {"success": True, "ignored": True}
        coin_session = coin_snap.to_dict() or {}
        if int(coin_session.get("expires_at", 0)) < int(time.time()):
            return {"success": True, "ignored": True}
        if telegram_id and telegram_id != str(coin_session.get("telegram_id")):
            return {"success": True, "ignored": True}
        _save_ad_event(ymid, {
            "session_id": ymid[:-3],
            "telegram_id": str(coin_session.get("telegram_id")),
            "event_type": event_type,
            "reward_event_type": reward_event_type,
            "zone_id": zone_id,
            "estimated_price": estimated_price,
        })
        return {"success": True}

    session_id = ymid[:-3] if ymid.endswith("_a1") or ymid.endswith("_a2") else ""
    slot = ymid[-2:] if session_id else ""
    if not session_id or slot not in ("a1", "a2"):
        return {"success": True, "ignored": True}
    session_ref = db.collection("ad_sessions").document(session_id)
    session_snapshot = session_ref.get()
    if not session_snapshot.exists:
        return {"success": True, "ignored": True}
    session = session_snapshot.to_dict() or {}
    if int(session.get("expires_at", 0)) < int(time.time()):
        return {"success": True, "ignored": True}
    if telegram_id and telegram_id != str(session.get("telegram_id")):
        return {"success": True, "ignored": True}

    # Document ID is ymid, making repeated Monetag retries idempotent (the first postback time is kept).
    _save_ad_event(ymid, {
        "session_id": session_id,
        "telegram_id": str(session.get("telegram_id")),
        "event_type": event_type,
        "reward_event_type": reward_event_type,
        "zone_id": zone_id,
        "estimated_price": estimated_price,
    })
    return {"success": True}


@app.post("/ad-status")
def get_ad_status(payload: AdStatusRequest):
    user, _ = verify_telegram_init_data(payload.init_data)
    ref = db.collection("ad_sessions").document(payload.session_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Ad session not found")
    data = snap.to_dict() or {}
    if str(data.get("telegram_id")) != str(user["id"]):
        raise HTTPException(status_code=403, detail="This ad session belongs to another user")
    if int(data.get("expires_at", 0)) < int(time.time()):
        raise HTTPException(status_code=410, detail="Ad session expired. Please try again")
    first = db.collection("monetag_events").document(data["ymid1"]).get().exists
    second = db.collection("monetag_events").document(data["ymid2"]).get().exists
    return {"success": True, "ad1_verified": first, "ad2_verified": second, "verified_count": int(first) + int(second)}


# =========================
# MULTI-MEDIA VIDEO ENTRIES
# One entry (videos document) can hold several videos and pictures in `media_items`.
# Each item is sent to the user as its own message, with protect_content so it cannot be saved, downloaded or forwarded.
# =========================

def _video_media_items(video: dict) -> list:
    items = [
        i for i in (video.get("media_items") or [])
        if isinstance(i, dict) and i.get("chat_id") and i.get("message_id")
    ]
    if not items and video.get("channel_chat_id") and video.get("channel_message_id"):
        items = [{"chat_id": str(video["channel_chat_id"]), "message_id": int(video["channel_message_id"]), "type": "video"}]
    return sorted(items, key=lambda i: int(i["message_id"]))


def _add_album_item(chat_id: str, group_id: str, message: dict, kind: str):
    """Channel albums (several videos/photos posted together) become ONE pending entry."""
    doc_id = f"g_{chat_id}_{group_id}"
    ref = db.collection("videos").document(doc_id)
    now = int(time.time())
    message_id = int(message["message_id"])
    caption = (message.get("caption") or "").strip()
    try:
        ref.create({
            "title": caption or "New Telegram Album", "category": "", "categories": [], "status": "pending",
            "thumbnail": "", "channel_chat_id": chat_id, "channel_message_id": message_id,
            "media_items": [], "created_at": now, "updated_at": now,
        })
    except Exception:
        pass  # already created by another album message
    ref.update({"media_items": gcf.ArrayUnion([{"chat_id": chat_id, "message_id": message_id, "type": kind}]), "updated_at": now})
    if caption:
        data = ref.get().to_dict() or {}
        if data.get("title") in ("", "New Telegram Album"):
            ref.update({"title": caption})


async def _send_media_items(user_id: int, video: dict) -> list:
    """Send every item one by one. Returns the message ids that were delivered."""
    items = _video_media_items(video)
    if not items:
        raise HTTPException(status_code=409, detail="Video source message is missing")
    sent = []
    async with httpx.AsyncClient(timeout=60) as client:
        for item in items:
            for attempt in range(2):
                response = await client.post(
                    f"https://api.telegram.org/bot{DELIVERY_BOT_TOKEN}/copyMessage",
                    json={
                        "chat_id": user_id, "from_chat_id": item["chat_id"],
                        "message_id": int(item["message_id"]), "protect_content": True,
                    },
                )
                result = response.json()
                if result.get("ok"):
                    sent.append(int(result["result"]["message_id"]))
                    break
                if response.status_code == 429 and attempt == 0:
                    await asyncio.sleep(int((result.get("parameters") or {}).get("retry_after", 1)) + 1)
                    continue
                print("VIDEO DELIVERY ERROR:", result)
                break
            await asyncio.sleep(0.3)
    return sent


def _schedule_deletions(chat_id: int, message_ids: list, session_id: str, delete_at: int, now: int):
    for message_id in message_ids:
        db.collection("scheduled_deletions").add({
            "chat_id": chat_id, "message_id": message_id, "delete_at": delete_at,
            "status": "pending", "created_at": now, "session_id": session_id,
        })


def _video_delete_minutes(video: dict, settings: dict) -> int:
    """Use a per-video override when set; otherwise use the global default."""
    try:
        override = int(video.get("auto_delete_minutes") or 0)
    except (TypeError, ValueError):
        override = 0
    if override > 0:
        return max(1, min(10080, override))
    return max(1, min(10080, int(settings.get("auto_delete_minutes", 30))))


async def _send_delivery_caption(chat_id: int, minutes: int, session_id: str):
    settings = _get_app_settings()
    if not settings.get("delivery_caption_enabled"):
        return None
    text = (settings.get("delivery_caption") or "").replace("{minutes}", str(minutes))
    if not text.strip():
        return None
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                f"https://api.telegram.org/bot{DELIVERY_BOT_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
            )
            data = response.json()
            if data.get("ok"):
                return int(data["result"]["message_id"])
            print("DELIVERY CAPTION ERROR:", data)
    except Exception as exc:
        print("DELIVERY CAPTION ERROR:", repr(exc))
    return None


def _schedule_deletion_notice(chat_id: int, delete_at: int, now: int, session_id: str, message_ids: list):
    settings = _get_app_settings()
    if settings.get("deletion_notice_enabled") and settings.get("deletion_notice", "").strip():
        db.collection("scheduled_deletions").add({
            "chat_id": chat_id, "delete_at": delete_at, "status": "pending",
            "created_at": now, "session_id": session_id, "job_type": "notice",
            "notice_text": settings["deletion_notice"], "video_message_ids": [int(x) for x in message_ids],
        })


@app.post("/deliver")
async def deliver_video(payload: AdStatusRequest):
    user, _ = verify_telegram_init_data(payload.init_data)
    _require_channel_membership(str(user["id"]))
    if not DELIVERY_BOT_TOKEN:
        raise HTTPException(status_code=503, detail="Delivery bot is not configured")
    session_ref = db.collection("ad_sessions").document(payload.session_id)
    session_snap = session_ref.get()
    if not session_snap.exists:
        raise HTTPException(status_code=404, detail="Ad session not found")
    session = session_snap.to_dict() or {}
    if str(session.get("telegram_id")) != str(user["id"]):
        raise HTTPException(status_code=403, detail="This ad session belongs to another user")
    if int(session.get("expires_at", 0)) < int(time.time()):
        raise HTTPException(status_code=410, detail="Ad session expired")
    if session.get("status") == "delivered":
        return {"success": True, "message": "Video already delivered"}
    event_times = []
    for key in ("ymid1", "ymid2"):
        event = db.collection("monetag_events").document(session[key]).get()
        if not event.exists:
            raise HTTPException(status_code=403, detail="Both Monetag ads must be verified before delivery")
        event_times.append(int((event.to_dict() or {}).get("received_at", 0) or 0))
    # Ad 1 is the popup (10 seconds on its page), then ~5 seconds later ad 2 starts. Too small a gap means the popup was skipped.
    required_gap = max(1, int(session.get("min_ad_gap_seconds", AD_MIN_GAP_SECONDS)))
    if event_times[1] - event_times[0] < required_gap:
        required_seconds = required_gap + 1
        raise HTTPException(status_code=403, detail=f"Stay at least {required_seconds} seconds on the ad page, then watch the ads again")

    video_snap = db.collection("videos").document(session["video_id"]).get()
    if not video_snap.exists:
        raise HTTPException(status_code=404, detail="Video not found")
    video = video_snap.to_dict() or {}
    if video.get("status", "active") != "active":
        raise HTTPException(status_code=403, detail="This video is not active")
    sent_ids = await _send_media_items(int(user["id"]), video)
    if not sent_ids:
        raise HTTPException(status_code=502, detail="Telegram could not send the video. Make sure the user has started the delivery bot.")
    settings_snap = db.collection("settings").document("app").get()
    settings = settings_snap.to_dict() if settings_snap.exists else {}
    delete_minutes = _video_delete_minutes(video, settings)
    now = int(time.time())
    delete_at = now + delete_minutes * 60
    caption_id = await _send_delivery_caption(int(user["id"]), delete_minutes, payload.session_id)
    # Delete the accompanying delivery message at exactly the same time as the video.
    _schedule_deletions(int(user["id"]), sent_ids + ([caption_id] if caption_id else []), payload.session_id, delete_at, now)
    _schedule_deletion_notice(int(user["id"]), delete_at, now, payload.session_id, sent_ids)
    session_ref.set({"status": "delivered", "delivered_at": now, "sent_message_id": sent_ids[0], "sent_message_ids": sent_ids, "delivery_caption_message_id": caption_id}, merge=True)

    # Only count as unlocked after Telegram confirms the video was delivered.
    progress_ref = db.collection("user_video_progress").document(
        f"{user['id']}_{session['video_id']}"
    )
    progress_ref.set({
        "telegram_id": str(user["id"]),
        "video_id": session["video_id"],
        "status": "unlocked",
        "unlocked_at": now,
        "updated_at": now,
    }, merge=True)

    _count_weekly_view(session["video_id"])
    try:
        if _get_app_settings()["video_share_enabled"]:
            reward_sharer_for_view(str(user["id"]), session["video_id"])
    except Exception as exc:
        print("SHARE REWARD ERROR:", repr(exc))

    # Referral reward: the referrer gets coins when this user gets their first video.
    try:
        if _get_app_settings()["referral_enabled"]:
            reward_referrer_for_first_video(str(user["id"]))
    except Exception as exc:
        print("REFERRAL REWARD ERROR:", repr(exc))

    return {"success": True, "message": "Video sent", "auto_delete_minutes": delete_minutes, "item_count": len(sent_ids)}


@app.get("/trending")
def get_trending():
    """Most watched videos this week (Sunday to Saturday), cached briefly."""
    cached = _cache_get("trending")
    if cached is not None:
        return cached
    week = _week_key()
    rows = []
    for doc in db.collection("video_weekly_stats").where("week", "==", week).stream():
        data = doc.to_dict() or {}
        if data.get("video_id"):
            rows.append({"video_id": data["video_id"], "count": int(data.get("count", 0) or 0)})
    rows.sort(key=lambda row: row["count"], reverse=True)
    pins = (db.collection("settings").document("trending").get().to_dict() or {}).get("pinned", [])
    rows = [{"video_id": p, "count": 0, "pinned": True} for p in pins] + [r for r in rows if r["video_id"] not in pins]
    return _cache_set("trending", {"success": True, "week_start": week, "trending": rows[:40]}, 20)


# =========================
# DAILY CHECK-IN AND VIDEO SHARE REWARDS
# =========================

@gcf.transactional
def _checkin_tx(tx, user_ref, today):
    data = user_ref.get(transaction=tx).to_dict() or {}
    coins = int(data.get("coins", 0) or 0)
    if data.get("last_checkin") == today:
        return False, coins
    tx.set(user_ref, {"last_checkin": today, "coins": gcf.Increment(CHECKIN_REWARD_COINS)}, merge=True)
    return True, coins + CHECKIN_REWARD_COINS


@app.post("/checkin")
def daily_checkin(payload: VideoProgressRequest):
    """One check-in per day (day changes at local midnight). Gives CHECKIN_REWARD_COINS."""
    if not _get_app_settings()["checkin_enabled"]:
        raise HTTPException(status_code=403, detail="Daily check-in is currently disabled")
    user, _ = verify_telegram_init_data(payload.init_data)
    telegram_id = str(user["id"])
    done, coins = _checkin_tx(db.transaction(), db.collection("users").document(telegram_id), _today_key())
    if done:
        db.collection("coin_logs").add({
            "telegram_id": telegram_id, "type": "earn", "amount": CHECKIN_REWARD_COINS,
            "reason": "daily_checkin", "created_at": int(time.time()),
        })
    return {"success": True, "already": not done, "coins": coins, "checked_in_today": True}


@gcf.transactional
def _reward_sharer_tx(tx, visit_ref, sharer_ref):
    snap = visit_ref.get(transaction=tx)
    visit = snap.to_dict() or {}
    if not snap.exists or visit.get("status") != "pending":
        return False
    now = int(time.time())
    tx.set(sharer_ref, {"coins": gcf.Increment(SHARE_VIDEO_REWARD_COINS)}, merge=True)
    tx.update(visit_ref, {"status": "rewarded", "rewarded_at": now})
    tx.set(db.collection("coin_logs").document(), {
        "telegram_id": sharer_ref.id, "type": "earn", "amount": SHARE_VIDEO_REWARD_COINS,
        "reason": "video_share", "friend_id": visit.get("viewer_id"), "video_id": visit.get("video_id"),
        "created_at": now,
    })
    return True


def reward_sharer_for_view(viewer_id: str, video_id: str) -> bool:
    """Give the sharer coins when someone who opened their video link gets that video. Once per viewer and video."""
    visit_ref = db.collection("share_visits").document(f"{viewer_id}_{video_id}")
    snap = visit_ref.get()
    data = snap.to_dict() or {}
    if not snap.exists or data.get("status") != "pending" or not data.get("sharer_id"):
        return False
    return _reward_sharer_tx(db.transaction(), visit_ref, db.collection("users").document(str(data["sharer_id"])))


# Ad timing rules (client shows the 10 second rule; the server double-checks using Monetag postback times)
AD_MIN_GAP_SECONDS = 9     # video unlock: 2nd ad must be seen at least this long after the popup (10s on the ad page + 5s wait, minus slack)
AD_MIN_POPUP_SECONDS = 8   # coin ad: coin is given only this long after the popup postback (10s on the ad page, minus slack)


def _save_ad_event(ymid: str, fields: dict):
    """Store the FIRST postback of a ymid only. Later retries or click events must not change the time."""
    ref = db.collection("monetag_events").document(ymid)
    if ref.get().exists:
        return
    ref.set({**fields, "received_at": int(time.time())})


@app.post("/coin-ad/start")
def coin_ad_start(payload: VideoProgressRequest):
    """Start a 'watch one ad, earn one coin' session (max DAILY_AD_COIN_LIMIT per day)."""
    user, _ = verify_telegram_init_data(payload.init_data)
    telegram_id = str(user["id"])
    if _ads_today(telegram_id) >= DAILY_AD_COIN_LIMIT:
        raise HTTPException(status_code=429, detail="Daily limit reached. Come back tomorrow.")
    session_id = uuid.uuid4().hex
    now = int(time.time())
    db.collection("coin_ad_sessions").document(session_id).set({
        "telegram_id": telegram_id,
        "ymid": f"{session_id}_c1",
        "created_at": now,
        "expires_at": now + 900,
        "status": "waiting_ad",
    })
    return {"success": True, "session_id": session_id, "ymid": f"{session_id}_c1"}


@app.post("/coin-ad/claim")
def coin_ad_claim(payload: AdStatusRequest):
    """Give 1 coin once Monetag has confirmed the ad. Safe to call repeatedly (poll)."""
    user, _ = verify_telegram_init_data(payload.init_data)
    telegram_id = str(user["id"])
    session_ref = db.collection("coin_ad_sessions").document(payload.session_id)
    snap = session_ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Ad session not found")
    data = snap.to_dict() or {}
    if str(data.get("telegram_id")) != telegram_id:
        raise HTTPException(status_code=403, detail="This ad session belongs to another user")
    if data.get("status") != "claimed":
        if int(data.get("expires_at", 0)) < int(time.time()):
            raise HTTPException(status_code=410, detail="Ad session expired. Please try again")
        event = db.collection("monetag_events").document(data["ymid"]).get()
        min_popup_seconds = max(1, _get_app_settings()["popup_min_seconds"] - 2)
        if not event.exists or int(time.time()) - int((event.to_dict() or {}).get("received_at", 0) or 0) < min_popup_seconds:
            return {"success": True, "pending": True}
        daily_ref = db.collection("coin_ad_daily").document(f"{telegram_id}_{_today_key()}")
        user_ref = db.collection("users").document(telegram_id)
        result = _claim_ad_coin_tx(db.transaction(), session_ref, daily_ref, user_ref, telegram_id)
        if result == "limit":
            raise HTTPException(status_code=429, detail="Daily limit reached. Come back tomorrow.")
    user_data = db.collection("users").document(telegram_id).get().to_dict() or {}
    return {
        "success": True,
        "pending": False,
        "coins": int(user_data.get("coins", 0) or 0),
        "ads_today": _ads_today(telegram_id),
        "ads_limit": DAILY_AD_COIN_LIMIT,
        "video_cost": VIDEO_COIN_COST,
        "ad_reward": AD_REWARD_COINS,
        "referral_reward": REFERRAL_REWARD_COINS,
    }


@app.post("/referral/info")
def referral_info(payload: VideoProgressRequest):
    user, _ = verify_telegram_init_data(payload.init_data)
    telegram_id = str(user["id"])
    data = db.collection("users").document(telegram_id).get().to_dict() or {}
    return {
        "success": True,
        "coins": int(data.get("coins", 0) or 0),
        "referral_count": int(data.get("referral_count", 0) or 0) if _get_app_settings()["referral_enabled"] else 0,
        "checkin_reward": CHECKIN_REWARD_COINS,
        "share_reward": SHARE_VIDEO_REWARD_COINS,
        "checked_in_today": data.get("last_checkin") == _today_key(),
        "referral_link": _build_referral_link(telegram_id) if _get_app_settings()["referral_enabled"] else "",
        "ads_today": _ads_today(telegram_id),
        "ads_limit": DAILY_AD_COIN_LIMIT,
        "video_cost": VIDEO_COIN_COST,
        "ad_reward": AD_REWARD_COINS,
        "referral_reward": REFERRAL_REWARD_COINS,
        "features": {k: _get_app_settings()[k] for k in ("checkin_enabled", "video_share_enabled", "referral_enabled")},
    }


@app.post("/use-coin")
async def use_coin_delivery(payload: UseCoinRequest):
    """Spend 1 Reward Coin to receive a video without watching ads."""
    user, _ = verify_telegram_init_data(payload.init_data)
    _require_channel_membership(str(user["id"]))
    if not DELIVERY_BOT_TOKEN:
        raise HTTPException(status_code=503, detail="Delivery bot is not configured")
    telegram_id = str(user["id"])

    video_snap = db.collection("videos").document(payload.video_id).get()
    if not video_snap.exists:
        raise HTTPException(status_code=404, detail="Video not found")
    video = video_snap.to_dict() or {}
    if video.get("status", "active") != "active":
        raise HTTPException(status_code=403, detail="This video is not active")
    if not _video_media_items(video):
        raise HTTPException(status_code=409, detail="Video source message is missing")

    # Deduct first (atomic) so a coin can never be spent twice; refund if Telegram fails.
    user_ref = db.collection("users").document(telegram_id)
    remaining = await asyncio.to_thread(_spend_coin_tx, db.transaction(), user_ref)
    if remaining < 0:
        raise HTTPException(status_code=402, detail=f"You need {VIDEO_COIN_COST} Reward Coins to watch a video without ads")

    try:
        sent_ids = await _send_media_items(int(user["id"]), video)
    except Exception as exc:
        print("COIN DELIVERY ERROR:", repr(exc))
        sent_ids = []
    if not sent_ids:
        user_ref.set({"coins": gcf.Increment(VIDEO_COIN_COST)}, merge=True)  # refund
        print("VIDEO DELIVERY ERROR (coin)")
        raise HTTPException(status_code=502, detail="Telegram could not send the video. Make sure you have started the delivery bot. Your coin was not used.")

    settings_snap = db.collection("settings").document("app").get()
    settings = settings_snap.to_dict() if settings_snap.exists else {}
    delete_minutes = _video_delete_minutes(video, settings)
    now = int(time.time())
    delete_at = now + delete_minutes * 60
    deletion_session_id = "coin_" + uuid.uuid4().hex
    caption_id = await _send_delivery_caption(int(user["id"]), delete_minutes, deletion_session_id)
    _schedule_deletions(int(user["id"]), sent_ids + ([caption_id] if caption_id else []), deletion_session_id, delete_at, now)
    _schedule_deletion_notice(int(user["id"]), delete_at, now, deletion_session_id, sent_ids)
    db.collection("user_video_progress").document(f"{telegram_id}_{payload.video_id}").set({
        "telegram_id": telegram_id,
        "video_id": payload.video_id,
        "status": "unlocked",
        "unlocked_at": now,
        "updated_at": now,
    }, merge=True)
    db.collection("coin_logs").add({
        "telegram_id": telegram_id, "type": "spend", "amount": VIDEO_COIN_COST,
        "video_id": payload.video_id, "created_at": now,
    })
    _count_weekly_view(payload.video_id)
    try:
        reward_referrer_for_first_video(telegram_id)
    except Exception as exc:
        print("REFERRAL REWARD ERROR:", repr(exc))

    return {"success": True, "message": "Video sent", "auto_delete_minutes": delete_minutes, "coins": remaining, "item_count": len(sent_ids)}


@app.get("/")
def home():
    return {
        "status": "success",
        "message": "Telegram Mini App Backend is running!"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/videos")
def get_videos(limit: int = 20, cursor: str = "", ids: str = ""):
    """Return a small page, or fetch a bounded set of explicit video IDs for deep links/trending."""
    requested_ids = list(dict.fromkeys(x.strip() for x in (ids or "").split(",") if x.strip()))[:40]
    if requested_ids:
        result = []
        for video_id in requested_ids:
            snap = db.collection("videos").document(video_id).get()
            if snap.exists:
                data = snap.to_dict() or {}
                data.pop("country", None)
                data["item_count"] = len(_video_media_items(data))
                data.pop("media_items", None)
                data["id"] = snap.id
                result.append(data)
        return {"success": True, "videos": result, "next_cursor": None, "has_more": False, "page_size": len(result)}
    limit = max(1, min(int(limit or 20), 50))
    query = db.collection("videos").order_by(FieldPath.document_id()).limit(limit + 1)
    if cursor:
        cursor_doc = db.collection("videos").document(cursor).get()
        if cursor_doc.exists:
            query = db.collection("videos").order_by(FieldPath.document_id()).start_after(cursor_doc).limit(limit + 1)
    docs = list(query.stream())
    has_more = len(docs) > limit
    docs = docs[:limit]
    result = []
    for video in docs:
        data = video.to_dict() or {}
        data.pop("country", None)
        data["item_count"] = len(_video_media_items(data))
        data.pop("media_items", None)
        data["id"] = video.id
        result.append(data)
    return {"success": True, "videos": result, "next_cursor": docs[-1].id if has_more and docs else None, "has_more": has_more, "page_size": limit}


def _video_payload(video: Video):
    payload = video.model_dump(exclude_none=True)
    chosen = payload.get("categories") or ([payload.get("category")] if payload.get("category") else [])
    chosen = list(dict.fromkeys(str(name).strip() for name in chosen if str(name).strip()))
    payload["categories"] = chosen
    payload["category"] = ", ".join(chosen)
    return payload


@app.post("/videos")
def add_video(video: Video, request: Request):
    require_admin(request, "editor")
    doc_ref = db.collection("videos").document()
    doc_ref.set(_video_payload(video))
    _cache_clear("categories", "admin_stats", "admin_videos")
    return {
        "success": True,
        "video_id": doc_ref.id,
        "message": "Video added successfully!"
    }


@app.put("/videos/{video_id}")
def update_video(video_id: str, video: Video, request: Request):
    require_admin(request, "editor")
    doc_ref = db.collection("videos").document(video_id)

    if not doc_ref.get().exists:
        raise HTTPException(status_code=404, detail="Video not found")

    # Exclude omitted optional Telegram fields so editing metadata does not erase file_id.
    # Remove the legacy field when an existing video is edited.
    doc_ref.update({"country": gcf.DELETE_FIELD, **_video_payload(video)})
    _cache_clear("categories", "admin_stats", "admin_videos")
    return {
        "success": True,
        "video_id": video_id,
        "message": "Video updated successfully!"
    }


@app.delete("/videos/{video_id}")
def delete_video(video_id: str, request: Request):
    require_admin(request, "editor")
    doc_ref = db.collection("videos").document(video_id)

    if not doc_ref.get().exists:
        raise HTTPException(status_code=404, detail="Video not found")

    doc_ref.delete()
    _cache_clear("categories", "admin_stats", "admin_videos")
    return {
        "success": True,
        "video_id": video_id,
        "message": "Video deleted successfully!"
    }


# =========================
# CATEGORY MANAGEMENT
# =========================

def _clean_category_name(value: str) -> str:
    name = (value or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Category name is required")
    if len(name) > 40:
        raise HTTPException(status_code=400, detail="Category name must be 40 characters or less")
    return name


_legacy_categories_migrated = False

@app.get("/categories")
def get_categories():
    """Return cached managed categories; migrate legacy video category names once per process."""
    global _legacy_categories_migrated
    cached = _cache_get("categories")
    if cached is not None:
        return {"success": True, "categories": cached}
    category_collection = db.collection("categories")
    categories_by_name = {}
    for item in category_collection.stream():
        data = item.to_dict() or {}
        name = (data.get("name") or "").strip()
        if name:
            categories_by_name[name.casefold()] = {"id": item.id, "name": name}
    if not _legacy_categories_migrated:
        for video in db.collection("videos").stream():
            data = video.to_dict() or {}
            names = data.get("categories") or ([data.get("category")] if data.get("category") else [])
            for raw_name in names:
                name = str(raw_name or "").strip()
                if not name or name.casefold() in categories_by_name:
                    continue
                doc_ref = category_collection.document()
                doc_ref.set({"name": name, "created_at": int(time.time())})
                categories_by_name[name.casefold()] = {"id": doc_ref.id, "name": name}
        _legacy_categories_migrated = True
    result = sorted(categories_by_name.values(), key=lambda item: item["name"].casefold())
    _cache_set("categories", result, _CATEGORY_CACHE_TTL)
    return {"success": True, "categories": result}


@app.post("/categories")
def create_category(category: Category, request: Request):
    require_admin(request, "editor")
    name = _clean_category_name(category.name)

    for item in db.collection("categories").stream():
        data = item.to_dict() or {}
        if (data.get("name") or "").strip().casefold() == name.casefold():
            raise HTTPException(status_code=409, detail="This category already exists")

    doc_ref = db.collection("categories").document()
    doc_ref.set({"name": name, "created_at": int(time.time())})
    _cache_clear("categories")
    return {
        "success": True,
        "category": {"id": doc_ref.id, "name": name},
        "message": "Category created successfully"
    }


@app.put("/categories/{category_id}")
def rename_category(category_id: str, category: Category, request: Request):
    require_admin(request, "editor")
    name = _clean_category_name(category.name)
    category_ref = db.collection("categories").document(category_id)
    snapshot = category_ref.get()

    if not snapshot.exists:
        raise HTTPException(status_code=404, detail="Category not found")

    old_name = (snapshot.to_dict() or {}).get("name", "")

    for item in db.collection("categories").stream():
        data = item.to_dict() or {}
        if item.id != category_id and (data.get("name") or "").strip().casefold() == name.casefold():
            raise HTTPException(status_code=409, detail="This category already exists")

    # Rename category in both legacy single-category and new multi-category video records.
    category_ref.set({"name": name, "updated_at": int(time.time())}, merge=True)
    batch = db.batch()
    pending_writes = 0
    for video in db.collection("videos").stream():
        data = video.to_dict() or {}
        old_categories = data.get("categories") or ([data.get("category")] if data.get("category") else [])
        if old_name not in old_categories and data.get("category") != old_name:
            continue
        updated = [name if item == old_name else item for item in old_categories]
        updated = list(dict.fromkeys(updated))
        batch.update(video.reference, {"categories": updated, "category": ", ".join(updated)})
        pending_writes += 1
        if pending_writes >= 450:
            batch.commit(); batch = db.batch(); pending_writes = 0
    if pending_writes:
        batch.commit()
    _cache_clear("categories")

    return {"success": True, "message": "Category renamed successfully"}


@app.delete("/categories/{category_id}")
def delete_category(category_id: str, request: Request):
    require_admin(request, "editor")
    category_ref = db.collection("categories").document(category_id)
    snapshot = category_ref.get()

    if not snapshot.exists:
        raise HTTPException(status_code=404, detail="Category not found")

    name = (snapshot.to_dict() or {}).get("name", "")
    for video in db.collection("videos").stream():
        data = video.to_dict() or {}
        assigned = data.get("categories") or ([data.get("category")] if data.get("category") else [])
        if name in assigned:
            raise HTTPException(
                status_code=409,
                detail="এই Category-তে ভিডিও আছে। আগে ভিডিওগুলো অন্য Category-তে সরান।"
            )

    category_ref.delete()
    _cache_clear("categories")
    return {"success": True, "message": "Category deleted successfully"}



# =========================
# ADMIN: AUTH, ROLES, COIN SETTINGS, USERS, STATS, PINS, SCHEDULING, BROADCAST
# Roles: viewer (read only) < editor (users, coins, pins, schedule, broadcast) < super (coin settings, admins)
# =========================
import base64

ROLE_ORDER = {"viewer": 1, "editor": 2, "super": 3}
ADMIN_TOKEN_TTL = 12 * 3600
# Set ADMIN_TOKEN_SECRET on Render (any long random string). Falls back to a value derived from existing secrets.
ADMIN_TOKEN_SECRET = (os.getenv("ADMIN_TOKEN_SECRET") or "").strip() or hashlib.sha256(
    f"{ADMIN_PASSWORD or ''}|{BOT_TOKEN}".encode()
).hexdigest()
_login_failures = {}

_COIN_DEFAULTS = {
    "referral_reward": REFERRAL_REWARD_COINS, "video_cost": VIDEO_COIN_COST, "ad_reward": AD_REWARD_COINS,
    "join_bonus": JOIN_BONUS_COINS, "daily_ad_limit": DAILY_AD_COIN_LIMIT,
    "checkin_reward": CHECKIN_REWARD_COINS, "share_reward": SHARE_VIDEO_REWARD_COINS,
}
_COIN_LIMITS = {
    "referral_reward": (0, 1000), "video_cost": (1, 1000), "ad_reward": (0, 1000),
    "join_bonus": (0, 1000), "daily_ad_limit": (0, 100),
    "checkin_reward": (0, 1000), "share_reward": (0, 1000),
}
_coin_loaded_at = 0.0


def _coin_values():
    return {
        "referral_reward": REFERRAL_REWARD_COINS, "video_cost": VIDEO_COIN_COST, "ad_reward": AD_REWARD_COINS,
        "join_bonus": JOIN_BONUS_COINS, "daily_ad_limit": DAILY_AD_COIN_LIMIT,
        "checkin_reward": CHECKIN_REWARD_COINS, "share_reward": SHARE_VIDEO_REWARD_COINS,
    }


def _refresh_coin_settings(force: bool = False):
    """Load coin amounts saved by the admin (settings/coins). Refreshed at most once a minute."""
    global REFERRAL_REWARD_COINS, VIDEO_COIN_COST, AD_REWARD_COINS, JOIN_BONUS_COINS, DAILY_AD_COIN_LIMIT, CHECKIN_REWARD_COINS, SHARE_VIDEO_REWARD_COINS, _coin_loaded_at
    if not force and time.time() - _coin_loaded_at < 60:
        return
    _coin_loaded_at = time.time()
    try:
        data = db.collection("settings").document("coins").get().to_dict() or {}
    except Exception as exc:
        print("COIN SETTINGS ERROR:", repr(exc))
        return

    def pick(key):
        try:
            value = int(data.get(key))
            low, high = _COIN_LIMITS[key]
            return value if low <= value <= high else _COIN_DEFAULTS[key]
        except (TypeError, ValueError):
            return _COIN_DEFAULTS[key]

    REFERRAL_REWARD_COINS = pick("referral_reward")
    VIDEO_COIN_COST = pick("video_cost")
    AD_REWARD_COINS = pick("ad_reward")
    JOIN_BONUS_COINS = pick("join_bonus")
    DAILY_AD_COIN_LIMIT = pick("daily_ad_limit")
    CHECKIN_REWARD_COINS = pick("checkin_reward")
    SHARE_VIDEO_REWARD_COINS = pick("share_reward")


@app.middleware("http")
async def coin_settings_middleware(request: Request, call_next):
    if time.time() - _coin_loaded_at >= 60:
        await asyncio.to_thread(_refresh_coin_settings)
    return await call_next(request)


_banned = {"ids": set(), "at": 0.0}


def _is_banned(telegram_id: str) -> bool:
    if time.time() - _banned["at"] > 60:
        _banned["at"] = time.time()
        try:
            _banned["ids"] = {d.id for d in db.collection("users").where("banned", "==", True).select([]).stream()}
        except Exception as exc:
            print("BANNED LIST ERROR:", repr(exc))
    return telegram_id in _banned["ids"]


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _make_admin_token(username: str, role: str) -> str:
    payload = _b64e(json.dumps({"u": username, "r": role, "e": int(time.time()) + ADMIN_TOKEN_TTL}).encode())
    sig = hmac.new(ADMIN_TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _hash_password(password: str, salt: str = ""):
    salt = salt or os.urandom(16).hex()
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()


def require_admin(request: Request, min_role: str = "viewer") -> dict:
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    try:
        payload, sig = token.split(".", 1)
        expected = hmac.new(ADMIN_TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("bad signature")
        data = json.loads(_b64d(payload))
        if int(data["e"]) < time.time():
            raise ValueError("expired")
        username, role = str(data["u"]), str(data["r"])
    except Exception:
        raise HTTPException(status_code=401, detail="Please log in again")
    if not (ADMIN_USERNAME and username == ADMIN_USERNAME and role == "super"):
        doc = db.collection("admins").document(username.lower()).get()
        info = doc.to_dict() or {}
        if not doc.exists or info.get("disabled"):
            raise HTTPException(status_code=401, detail="Please log in again")
        role = info.get("role", "viewer")
    if ROLE_ORDER.get(role, 0) < ROLE_ORDER[min_role]:
        raise HTTPException(status_code=403, detail="You do not have permission for this action")
    return {"username": username, "role": role}


@app.post("/admin/login")
def admin_login(login: AdminLogin, request: Request):
    key = f"{request.client.host if request.client else '?'}|{login.username.lower()}"
    now = time.time()
    fails = [t for t in _login_failures.get(key, []) if now - t < 600]
    if len(fails) >= 8:
        raise HTTPException(status_code=429, detail="Too many attempts. Try again in 10 minutes")
    role, name = None, ""
    if (
        ADMIN_USERNAME and ADMIN_PASSWORD
        and hmac.compare_digest(login.username.encode(), ADMIN_USERNAME.encode())
        and hmac.compare_digest(login.password.encode(), ADMIN_PASSWORD.encode())
    ):
        role, name = "super", ADMIN_USERNAME
    else:
        info = db.collection("admins").document(login.username.strip().lower()).get().to_dict() or {}
        if info and not info.get("disabled") and hmac.compare_digest(
            _hash_password(login.password, info.get("salt", "00"))[1], info.get("password_hash", "")
        ):
            role, name = info.get("role", "viewer"), info.get("username", login.username)
    if not role:
        fails.append(now)
        _login_failures[key] = fails
        raise HTTPException(status_code=401, detail="Invalid username or password")
    _login_failures.pop(key, None)
    return {
        "success": True, "message": "Admin login successful!",
        "token": _make_admin_token(name, role), "role": role, "username": name,
    }


@app.get("/admin/coin-settings")
def admin_get_coin_settings(request: Request):
    require_admin(request, "viewer")
    _refresh_coin_settings(force=True)
    return {"success": True, "settings": _coin_values()}


@app.put("/admin/coin-settings")
def admin_put_coin_settings(request: Request, payload: dict):
    require_admin(request, "super")
    clean = {}
    for key, (low, high) in _COIN_LIMITS.items():
        try:
            value = int(payload.get(key))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f"{key} must be a number")
        if not low <= value <= high:
            raise HTTPException(status_code=400, detail=f"{key} must be between {low} and {high}")
        clean[key] = value
    db.collection("settings").document("coins").set({**clean, "updated_at": int(time.time())}, merge=True)
    _refresh_coin_settings(force=True)
    return {"success": True, "settings": _coin_values()}


def _day_start_ts() -> int:
    local = datetime.now(timezone.utc) + timedelta(hours=DAY_RESET_UTC_OFFSET_HOURS)
    start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    return int((start - timedelta(hours=DAY_RESET_UTC_OFFSET_HOURS)).timestamp())


def _count(query):
    try:
        return int(query.count().get()[0][0].value)
    except Exception:
        return sum(1 for _ in query.select([]).stream())


def _sum_price(query):
    total, n = 0.0, 0
    for doc in query.select(["estimated_price"]).stream():
        n += 1
        try:
            total += float((doc.to_dict() or {}).get("estimated_price") or 0)
        except (TypeError, ValueError):
            pass
    return n, round(total, 4)


@app.get("/admin/stats")
def admin_stats(request: Request):
    require_admin(request, "viewer")
    cached = _cache_get("admin_stats")
    if cached is not None:
        return cached
    today, week_ago = _day_start_ts(), int(time.time()) - 7 * 86400
    users = db.collection("users")
    deliveries = db.collection("scheduled_deletions")
    events = db.collection("monetag_events")
    circulating = None
    try:
        circulating = int(users.sum("coins").get()[0][0].value or 0)
    except Exception:
        pass
    earned, spent, adjusted = {}, 0, 0
    for doc in db.collection("coin_logs").where("created_at", ">=", today).stream():
        log = doc.to_dict() or {}
        amount = int(log.get("amount", 0) or 0)
        if log.get("type") == "spend":
            spent += amount
        elif log.get("type") == "adjust":
            adjusted += amount
        else:
            earned[log.get("reason", "other")] = earned.get(log.get("reason", "other"), 0) + amount
    coin_ads_today = sum(
        int((d.to_dict() or {}).get("count", 0) or 0)
        for d in db.collection("coin_ad_daily").where("updated_at", ">=", today).stream()
    )
    ev_today, usd_today = _sum_price(events.where("received_at", ">=", today))
    ev_week, usd_week = _sum_price(events.where("received_at", ">=", week_ago))
    top = []
    rows = [d.to_dict() or {} for d in db.collection("video_weekly_stats").where("week", "==", _week_key()).stream()]
    for row in sorted(rows, key=lambda r: int(r.get("count", 0) or 0), reverse=True)[:5]:
        title = (db.collection("videos").document(str(row.get("video_id"))).get().to_dict() or {}).get("title", "(deleted)")
        top.append({"video_id": row.get("video_id"), "title": title, "count": int(row.get("count", 0) or 0)})
    result = {
        "success": True,
        "users": {
            "total": _count(users), "new_today": _count(users.where("created_at", ">=", today)),
            "active_today": _count(users.where("last_seen", ">=", today)),
            "banned": _count(users.where("banned", "==", True)),
        },
        "videos": {
            "total": _count(db.collection("videos")),
            "delivered_today": _count(deliveries.where("created_at", ">=", today)),
            "delivered_7d": _count(deliveries.where("created_at", ">=", week_ago)),
        },
        "coins": {
            "circulating": circulating, "earned_today": earned, "spent_today": spent,
            "adjusted_today": adjusted, "coin_ads_today": coin_ads_today,
        },
        "earnings": {"ads_today": ev_today, "ads_7d": ev_week, "usd_today": usd_today, "usd_7d": usd_week},
        "top_videos": top,
    }
    return _cache_set("admin_stats", result, _STATS_CACHE_TTL)


def _user_row(doc):
    d = doc.to_dict() or {}
    return {
        "id": doc.id, "name": f"{d.get('first_name', '')} {d.get('last_name', '')}".strip(),
        "username": d.get("username", ""), "coins": int(d.get("coins", 0) or 0),
        "referrals": int(d.get("referral_count", 0) or 0), "referred_by": d.get("referred_by", ""),
        "banned": bool(d.get("banned")), "created_at": d.get("created_at"), "last_seen": d.get("last_seen"),
    }


@app.get("/admin/users")
def admin_users(request: Request, q: str = "", limit: int = 30):
    require_admin(request, "viewer")
    q, limit = q.strip().lstrip("@"), max(1, min(limit, 100))
    users = db.collection("users")
    if q.isdigit():
        doc = users.document(q).get()
        docs = [doc] if doc.exists else []
    elif q:
        found = {}
        for field in ("username", "first_name"):
            for doc in users.where(field, ">=", q).where(field, "<=", q + "\uf8ff").limit(limit).stream():
                found[doc.id] = doc
        docs = list(found.values())[:limit]
    else:
        docs = list(users.order_by("created_at", direction=gcf.Query.DESCENDING).limit(limit).stream())
    return {"success": True, "users": [_user_row(d) for d in docs]}


@gcf.transactional
def _adjust_coins_tx(tx, user_ref, amount):
    snap = user_ref.get(transaction=tx)
    if not snap.exists:
        return None
    new_total = int((snap.to_dict() or {}).get("coins", 0) or 0) + amount
    if new_total < 0:
        return -1
    tx.update(user_ref, {"coins": new_total})
    return new_total


@app.post("/admin/users/{telegram_id}/coins")
def admin_adjust_coins(telegram_id: str, request: Request, payload: dict):
    admin = require_admin(request, "editor")
    try:
        amount = int(payload.get("amount"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Amount must be a number")
    if amount == 0 or abs(amount) > 100000:
        raise HTTPException(status_code=400, detail="Amount must be between 1 and 100000 (use minus to remove)")
    result = _adjust_coins_tx(db.transaction(), db.collection("users").document(telegram_id), amount)
    if result is None:
        raise HTTPException(status_code=404, detail="User not found")
    if result < 0:
        raise HTTPException(status_code=400, detail="User does not have that many coins")
    db.collection("coin_logs").add({
        "telegram_id": telegram_id, "type": "adjust", "amount": amount, "reason": "admin_adjust",
        "note": str(payload.get("reason", ""))[:200], "admin": admin["username"], "created_at": int(time.time()),
    })
    return {"success": True, "coins": result}


@app.post("/admin/users/{telegram_id}/ban")
def admin_ban_user(telegram_id: str, request: Request, payload: dict):
    admin = require_admin(request, "editor")
    ref = db.collection("users").document(telegram_id)
    if not ref.get().exists:
        raise HTTPException(status_code=404, detail="User not found")
    banned = bool(payload.get("banned"))
    ref.update({
        "banned": banned, "ban_reason": str(payload.get("reason", ""))[:200],
        "banned_by": admin["username"], "banned_at": int(time.time()),
    })
    (_banned["ids"].add if banned else _banned["ids"].discard)(telegram_id)
    return {"success": True, "banned": banned}


@app.get("/admin/coin-logs")
def admin_coin_logs(request: Request, telegram_id: str = ""):
    require_admin(request, "viewer")
    logs = db.collection("coin_logs")
    if telegram_id:
        logs = logs.where("telegram_id", "==", telegram_id)
    rows = sorted((d.to_dict() or {} for d in logs.stream()), key=lambda r: r.get("created_at", 0), reverse=True)
    return {"success": True, "logs": rows[:100]}


@app.get("/admin/videos")
def admin_videos(request: Request):
    require_admin(request, "viewer")
    cached = _cache_get("admin_videos")
    if cached is not None:
        return cached
    rows = []
    for doc in db.collection("videos").stream():
        d = doc.to_dict() or {}
        rows.append({"id": doc.id, "title": d.get("title", ""), "status": d.get("status", "active"), "publish_at": d.get("publish_at"), "auto_delete_minutes": int(d.get("auto_delete_minutes") or 0)})
    rows.sort(key=lambda r: r["title"].lower())
    return _cache_set("admin_videos", {"success": True, "videos": rows}, 60)


@app.put("/admin/videos/{video_id}/delete-time")
def admin_video_delete_time(video_id: str, request: Request, payload: dict):
    require_admin(request, "editor")
    ref = db.collection("videos").document(video_id)
    if not ref.get().exists:
        raise HTTPException(status_code=404, detail="Video not found")
    try:
        minutes = int(payload.get("auto_delete_minutes", 0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="auto_delete_minutes must be a number")
    if minutes < 0 or minutes > 10080:
        raise HTTPException(status_code=400, detail="auto_delete_minutes must be between 0 and 10080")
    ref.update({"auto_delete_minutes": minutes, "updated_at": int(time.time())})
    _cache_clear("admin_videos", "admin_stats")
    return {"success": True, "auto_delete_minutes": minutes, "message": "Video auto-delete time saved"}


@app.get("/admin/videos/{video_id}/media")
def admin_video_media(video_id: str, request: Request):
    require_admin(request, "viewer")
    snap = db.collection("videos").document(video_id).get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Video not found")
    candidates = []
    for doc in db.collection("videos").where("status", "==", "pending").stream():
        if doc.id != video_id:
            d = doc.to_dict() or {}
            candidates.append({"id": doc.id, "title": d.get("title", ""), "item_count": len(_video_media_items(d))})
    return {"success": True, "items": _video_media_items(snap.to_dict() or {}), "candidates": candidates}


@app.post("/admin/videos/{video_id}/media/add")
def admin_video_media_add(video_id: str, request: Request, payload: dict):
    """Add channel photos (by thumbnail id) and/or whole pending channel videos to this entry."""
    require_admin(request, "editor")
    ref = db.collection("videos").document(video_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Video not found")
    items = _video_media_items(snap.to_dict() or {})
    have = {(str(i["chat_id"]), int(i["message_id"])) for i in items}
    added, merged = 0, []
    for photo_id in payload.get("photo_ids") or []:
        thumb = db.collection("thumbnails").document(str(photo_id)).get().to_dict() or {}
        if thumb.get("channel_chat_id") and thumb.get("channel_message_id"):
            key = (str(thumb["channel_chat_id"]), int(thumb["channel_message_id"]))
            if key not in have:
                items.append({"chat_id": key[0], "message_id": key[1], "type": "photo"})
                have.add(key)
                added += 1
    for other_id in payload.get("video_ids") or []:
        if str(other_id) == video_id:
            continue
        other = db.collection("videos").document(str(other_id))
        other_snap = other.get()
        if not other_snap.exists:
            continue
        for item in _video_media_items(other_snap.to_dict() or {}):
            key = (str(item["chat_id"]), int(item["message_id"]))
            if key not in have:
                items.append(item)
                have.add(key)
                added += 1
        merged.append(other)
    items.sort(key=lambda i: int(i["message_id"]))
    ref.update({"media_items": items, "updated_at": int(time.time())})
    for other in merged:
        other.delete()
    return {"success": True, "added": added, "item_count": len(items)}


@app.post("/admin/videos/{video_id}/media/remove")
def admin_video_media_remove(video_id: str, request: Request, payload: dict):
    require_admin(request, "editor")
    ref = db.collection("videos").document(video_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Video not found")
    try:
        target = int(payload.get("message_id"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="message_id is required")
    items = [i for i in _video_media_items(snap.to_dict() or {}) if int(i["message_id"]) != target]
    if not items:
        raise HTTPException(status_code=400, detail="An entry needs at least one item")
    ref.update({
        "media_items": items, "channel_chat_id": str(items[0]["chat_id"]),
        "channel_message_id": int(items[0]["message_id"]), "updated_at": int(time.time()),
    })
    return {"success": True, "item_count": len(items)}


@app.get("/admin/trending-pins")
def admin_get_pins(request: Request):
    require_admin(request, "viewer")
    return {"success": True, "pinned": (db.collection("settings").document("trending").get().to_dict() or {}).get("pinned", [])}


@app.put("/admin/trending-pins")
def admin_put_pins(request: Request, payload: dict):
    require_admin(request, "editor")
    pinned = list(dict.fromkeys(str(v) for v in (payload.get("pinned") or [])))[:15]
    db.collection("settings").document("trending").set({"pinned": pinned}, merge=True)
    _cache_clear("trending")
    return {"success": True, "pinned": pinned}


@app.put("/admin/videos/{video_id}/schedule")
def admin_schedule_video(video_id: str, request: Request, payload: dict):
    require_admin(request, "editor")
    ref = db.collection("videos").document(video_id)
    if not ref.get().exists:
        raise HTTPException(status_code=404, detail="Video not found")
    if payload.get("publish_now"):
        ref.update({"status": "active", "published_at": int(time.time()), "publish_at": gcf.DELETE_FIELD})
    elif payload.get("publish_at"):
        try:
            when = int(payload["publish_at"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid time")
        if when <= int(time.time()):
            raise HTTPException(status_code=400, detail="Choose a future time")
        ref.update({"status": "pending", "publish_at": when})
    else:
        ref.update({"publish_at": gcf.DELETE_FIELD})
    _cache_clear("admin_videos", "admin_stats")
    return {"success": True}


def _publish_due_videos():
    now = int(time.time())
    for doc in db.collection("videos").where("publish_at", "<=", now).stream():
        if (doc.to_dict() or {}).get("status") == "pending":
            doc.reference.update({"status": "active", "published_at": now, "publish_at": gcf.DELETE_FIELD})
            _cache_clear("admin_videos", "admin_stats")


async def publish_worker():
    """Every 30 seconds, activate scheduled videos whose time has come."""
    while True:
        try:
            await asyncio.to_thread(_publish_due_videos)
        except Exception as exc:
            print("PUBLISH WORKER ERROR:", repr(exc))
        await asyncio.sleep(30)


_broadcast_state = {"running": False}
_media_store = {}  # media_id -> uploaded photo/video waiting to be broadcast (kept in memory for 30 minutes)
MAX_MEDIA_BYTES = {"photo": 10 * 1024 * 1024, "video": 40 * 1024 * 1024}
_bot_name_cache = {}


def _broadcast_bots():
    options = (("delivery", DELIVERY_BOT_TOKEN, "Delivery bot"), ("miniapp", BOT_TOKEN, "Mini App bot"))
    return {key: {"token": token, "label": label} for key, token, label in options if token}


def _bot_username(token: str) -> str:
    if token not in _bot_name_cache:
        try:
            result = httpx.get(f"https://api.telegram.org/bot{token}/getMe", timeout=10).json()
            if result.get("ok"):
                _bot_name_cache[token] = (result.get("result") or {}).get("username", "")
        except Exception as exc:
            print("BOT NAME ERROR:", repr(exc))
    return _bot_name_cache.get(token, "")


@app.get("/admin/broadcast-bots")
def admin_broadcast_bots(request: Request):
    require_admin(request, "viewer")
    return {"success": True, "bots": [
        {"key": key, "label": info["label"], "username": _bot_username(info["token"])}
        for key, info in _broadcast_bots().items()
    ]}


@app.post("/admin/broadcast-media")
async def admin_broadcast_media(request: Request, kind: str = "photo", filename: str = "file"):
    """Upload one photo or video (raw request body) to attach to the next broadcast."""
    require_admin(request, "editor")
    if kind not in MAX_MEDIA_BYTES:
        raise HTTPException(status_code=400, detail="kind must be photo or video")
    limit = MAX_MEDIA_BYTES[kind]
    if int(request.headers.get("content-length") or 0) > limit:
        raise HTTPException(status_code=413, detail=f"{kind.title()} is too large (max {limit // (1024 * 1024)} MB)")
    data = await request.body()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"{kind.title()} is too large (max {limit // (1024 * 1024)} MB)")
    now = time.time()
    for key in [k for k, v in _media_store.items() if now - v["at"] > 1800]:
        _media_store.pop(key, None)
    media_id = uuid.uuid4().hex
    _media_store[media_id] = {
        "type": kind, "filename": filename[:100] or "file", "data": data, "at": now,
        "content_type": request.headers.get("content-type") or "application/octet-stream",
    }
    return {"success": True, "media_id": media_id, "size": len(data)}


async def _send_one(client, token, chat_id, text, media, file_id, reply_markup=None):
    base = f"https://api.telegram.org/bot{token}"
    markup = {"reply_markup": reply_markup} if reply_markup else {}
    message_ids = []
    if not media:
        response = await client.post(f"{base}/sendMessage", json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True, **markup})
        data = response.json()
        if data.get("ok") and (data.get("result") or {}).get("message_id"):
            message_ids.append(int(data["result"]["message_id"]))
        return response, message_ids

    method, field = ("sendPhoto", "photo") if media["type"] == "photo" else ("sendVideo", "video")
    caption = text if text and len(text) <= 1024 else ""
    params = {"chat_id": chat_id, **markup}
    if caption:
        params["caption"] = caption
    if file_id:
        response = await client.post(f"{base}/{method}", json={**params, field: file_id})
    else:
        form_params = dict(params)
        if reply_markup:
            form_params["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        response = await client.post(f"{base}/{method}", data=form_params, files={field: (media["filename"], media["data"], media["content_type"])})
    data = response.json()
    if data.get("ok") and (data.get("result") or {}).get("message_id"):
        message_ids.append(int(data["result"]["message_id"]))
    if text and not caption and response.status_code == 200:
        extra = await client.post(f"{base}/sendMessage", json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True})
        extra_data = extra.json()
        if extra_data.get("ok") and (extra_data.get("result") or {}).get("message_id"):
            message_ids.append(int(extra_data["result"]["message_id"]))
    return response, message_ids


async def _delete_delivery_messages(client, delivery):
    bot_info = _broadcast_bots().get(str(delivery.get("bot") or "delivery")) or {}
    token = str(bot_info.get("token") or "")
    chat_id = delivery.get("chat_id")
    if not token:
        return False
    base = f"https://api.telegram.org/bot{token}"
    all_ok = True
    for message_id in delivery.get("message_ids", []):
        try:
            response = await client.post(f"{base}/deleteMessage", json={"chat_id": chat_id, "message_id": int(message_id)})
            result = response.json()
            if not result.get("ok") and "message to delete not found" not in str(result).lower():
                all_ok = False
        except Exception:
            all_ok = False
    return all_ok


async def _run_broadcast(ref, text, token, bot_key, media, media_id, audience, reply_markup, auto_delete_seconds):
    sent = failed = unreachable = 0
    file_id = None
    try:
        await asyncio.to_thread(_is_banned, "0")  # Refresh the cached banned-user list.
        users = await asyncio.to_thread(lambda: [(d.id, d.to_dict() or {}) for d in db.collection("users").stream()])
        cutoff = int(time.time()) - 7 * 86400
        if audience == "active":
            users = [(uid, u) for uid, u in users if int(u.get("last_seen", 0) or 0) >= cutoff]
        elif audience == "inactive":
            users = [(uid, u) for uid, u in users if int(u.get("last_seen", 0) or 0) < cutoff]
        users = [(uid, u) for uid, u in users if uid not in _banned["ids"] and not u.get("banned")]
        ref.update({"total": len(users)})
        async with httpx.AsyncClient(timeout=120) as client:
            for n, (uid, user_data) in enumerate(users, 1):
                try:
                    response, message_ids = await _send_one(client, token, int(uid), text, media, file_id, reply_markup)
                    data = response.json()
                    if data.get("ok"):
                        sent += 1
                        if media and not file_id:
                            result = data.get("result") or {}
                            media_obj = result.get("photo", [])[-1] if media["type"] == "photo" else result.get("video", {})
                            file_id = media_obj.get("file_id") if media_obj else None
                        if message_ids:
                            delivery = {"broadcast_id": ref.id, "chat_id": int(uid), "message_ids": message_ids, "bot": bot_key, "status": "pending" if auto_delete_seconds else "sent", "created_at": int(time.time())}
                            if auto_delete_seconds:
                                delivery["delete_at"] = int(time.time()) + auto_delete_seconds
                            db.collection("broadcast_deliveries").document(f"{ref.id}_{uid}").set(delivery)
                    elif response.status_code == 429:
                        retry = int((data.get("parameters") or {}).get("retry_after", 1)) + 1
                        await asyncio.sleep(retry)
                        retry_response, retry_ids = await _send_one(client, token, int(uid), text, media, file_id, reply_markup)
                        retry_data = retry_response.json()
                        if retry_data.get("ok"):
                            sent += 1
                            if media and not file_id:
                                retry_result = retry_data.get("result") or {}
                                retry_media = retry_result.get("photo", [])[-1] if media["type"] == "photo" else retry_result.get("video", {})
                                file_id = retry_media.get("file_id") if retry_media else None
                            if retry_ids:
                                delivery = {"broadcast_id": ref.id, "chat_id": int(uid), "message_ids": retry_ids, "bot": bot_key, "status": "pending" if auto_delete_seconds else "sent", "created_at": int(time.time())}
                                if auto_delete_seconds: delivery["delete_at"] = int(time.time()) + auto_delete_seconds
                                db.collection("broadcast_deliveries").document(f"{ref.id}_{uid}").set(delivery)
                        else:
                            failed += 1
                    elif response.status_code in (400, 403):
                        unreachable += 1
                    else:
                        failed += 1
                except Exception as exc:
                    print("BROADCAST USER ERROR:", uid, repr(exc))
                    failed += 1
                await asyncio.sleep(0.05)
                if n % 25 == 0:
                    ref.update({"sent": sent, "failed": failed, "unreachable": unreachable})
        ref.update({"sent": sent, "failed": failed, "unreachable": unreachable, "status": "done", "finished_at": int(time.time())})
    except Exception as exc:
        print("BROADCAST ERROR:", repr(exc))
        ref.update({"sent": sent, "failed": failed, "unreachable": unreachable, "status": "error"})
    finally:
        _media_store.pop(media_id, None)
        _broadcast_state["running"] = False


@app.get("/admin/broadcast-audience")
def admin_broadcast_audience(request: Request):
    require_admin(request, "viewer")
    cutoff = int(time.time()) - 7 * 86400
    all_users = [d.to_dict() or {} for d in db.collection("users").stream()]
    eligible = [u for u in all_users if not u.get("banned")]
    active = sum(1 for u in eligible if int(u.get("last_seen", 0) or 0) >= cutoff)
    return {"success": True, "all": len(eligible), "active": active, "inactive": len(eligible) - active, "active_days": 7}


@app.post("/admin/broadcast")
async def admin_broadcast(request: Request, payload: dict):
    admin = require_admin(request, "editor")
    text = str(payload.get("text", "")).strip()
    bots = _broadcast_bots()
    bot_key = str(payload.get("bot") or "delivery")
    if bot_key not in bots:
        raise HTTPException(status_code=400, detail="Choose a bot that is configured")
    media_id = str(payload.get("media_id") or "")
    media = _media_store.get(media_id) if media_id else None
    if media_id and not media:
        raise HTTPException(status_code=400, detail="Uploaded file expired. Please attach it again")
    if not text and not media:
        raise HTTPException(status_code=400, detail="Write a message or attach a photo or video")
    if len(text) > 4000:
        raise HTTPException(status_code=400, detail="Message must be 4000 characters or fewer")
    audience = str(payload.get("audience") or "all")
    if audience not in ("all", "active", "inactive"):
        raise HTTPException(status_code=400, detail="Invalid audience")
    try:
        auto_delete_seconds = int(payload.get("auto_delete_seconds") or 0)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid auto-delete duration")
    if auto_delete_seconds < 0 or auto_delete_seconds > 2592000:
        raise HTTPException(status_code=400, detail="Auto-delete must be 0 to 30 days")
    raw_buttons = payload.get("buttons") or []
    if not isinstance(raw_buttons, list) or len(raw_buttons) > 5:
        raise HTTPException(status_code=400, detail="Use up to 5 inline buttons")
    keyboard = []
    for item in raw_buttons:
        label = str((item or {}).get("text") or "").strip()[:64]
        url = str((item or {}).get("url") or "").strip()
        if not label and not url: continue
        if not label or not (url.startswith("https://") or url.startswith("http://") or url.startswith("tg://")):
            raise HTTPException(status_code=400, detail="Each button needs a label and valid http(s) or tg:// URL")
        keyboard.append([{"text": label, "url": url}])
    if _broadcast_state["running"]:
        raise HTTPException(status_code=409, detail="Another broadcast is still running")
    ref = db.collection("broadcasts").document()
    ref.set({
        "text": text, "bot": bot_key, "media": media["type"] if media else None,
        "audience": audience, "auto_delete_seconds": auto_delete_seconds, "buttons": keyboard,
        "created_by": admin["username"], "created_at": int(time.time()),
        "status": "running", "total": 0, "sent": 0, "failed": 0, "unreachable": 0, "deleted": 0, "delivery_tracking": True,
    })
    _broadcast_state["running"] = True
    markup = {"inline_keyboard": keyboard} if keyboard else None
    asyncio.create_task(_run_broadcast(ref, text, bots[bot_key]["token"], bot_key, media, media_id, audience, markup, auto_delete_seconds))
    return {"success": True, "broadcast_id": ref.id}


async def _delete_broadcast(ref):
    docs = list(db.collection("broadcast_deliveries").where("broadcast_id", "==", ref.id).stream())
    deleted = failed = 0
    async with httpx.AsyncClient(timeout=30) as client:
        for doc in docs:
            data = doc.to_dict() or {}
            if data.get("status") == "deleted":
                continue
            ok = await _delete_delivery_messages(client, data)
            if ok:
                deleted += len(data.get("message_ids", []))
                doc.reference.set({"status": "deleted", "deleted_at": int(time.time())}, merge=True)
            else:
                failed += 1
            await asyncio.sleep(0.03)
    ref.update({"delete_status": "done" if not failed else "partial", "deleted": deleted, "delete_failed": failed, "delete_finished_at": int(time.time())})


@app.post("/admin/broadcasts/{broadcast_id}/delete")
async def admin_delete_broadcast(request: Request, broadcast_id: str):
    require_admin(request, "editor")
    ref = db.collection("broadcasts").document(broadcast_id)
    if not ref.get().exists:
        raise HTTPException(status_code=404, detail="Broadcast not found")
    ref.update({"delete_status": "deleting"})
    asyncio.create_task(_delete_broadcast(ref))
    return {"success": True, "message": "Deletion started"}


@app.get("/admin/broadcasts")
def admin_broadcasts(request: Request):
    require_admin(request, "viewer")
    query = db.collection("broadcasts").order_by("created_at", direction=gcf.Query.DESCENDING).limit(20)
    return {"success": True, "broadcasts": [{**(d.to_dict() or {}), "id": d.id} for d in query.stream()]}


def _admin_row(info):
    row = {k: info.get(k) for k in ("username", "role", "created_by", "created_at")}
    row["disabled"] = bool(info.get("disabled"))
    return row


@app.get("/admin/admins")
def admin_list_admins(request: Request):
    require_admin(request, "super")
    return {"success": True, "owner": ADMIN_USERNAME, "admins": [_admin_row(d.to_dict() or {}) for d in db.collection("admins").stream()]}


@app.post("/admin/admins")
def admin_create_admin(request: Request, payload: dict):
    me = require_admin(request, "super")
    name, role, password = str(payload.get("username", "")).strip(), payload.get("role"), str(payload.get("password", ""))
    if not 3 <= len(name) <= 30 or not name.replace("_", "").replace("-", "").replace(".", "").isalnum():
        raise HTTPException(status_code=400, detail="Username: 3-30 letters, numbers, _ - .")
    if role not in ROLE_ORDER:
        raise HTTPException(status_code=400, detail="Invalid role")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    ref = db.collection("admins").document(name.lower())
    if ref.get().exists or name.lower() == (ADMIN_USERNAME or "").lower():
        raise HTTPException(status_code=409, detail="This username already exists")
    salt, hashed = _hash_password(password)
    ref.set({"username": name, "role": role, "salt": salt, "password_hash": hashed,
             "created_by": me["username"], "created_at": int(time.time()), "disabled": False})
    return {"success": True}


@app.put("/admin/admins/{username}")
def admin_update_admin(username: str, request: Request, payload: dict):
    me = require_admin(request, "super")
    if username.lower() == me["username"].lower():
        raise HTTPException(status_code=400, detail="You cannot modify your own account here")
    ref = db.collection("admins").document(username.lower())
    if not ref.get().exists:
        raise HTTPException(status_code=404, detail="Admin not found")
    changes = {}
    if "role" in payload:
        if payload["role"] not in ROLE_ORDER:
            raise HTTPException(status_code=400, detail="Invalid role")
        changes["role"] = payload["role"]
    if "disabled" in payload:
        changes["disabled"] = bool(payload["disabled"])
    if payload.get("password"):
        if len(str(payload["password"])) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        changes["salt"], changes["password_hash"] = _hash_password(str(payload["password"]))
    if changes:
        ref.update(changes)
    return {"success": True}


@app.delete("/admin/admins/{username}")
def admin_delete_admin(username: str, request: Request):
    me = require_admin(request, "super")
    if username.lower() == me["username"].lower():
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    db.collection("admins").document(username.lower()).delete()
    return {"success": True}


APP_SETTING_DEFAULTS = {
    "auto_delete_minutes": 30,
    "deletion_notice_auto_delete_minutes": 720,
    "join_verification_enabled": True,
    "join_channel": "@ViralDuniyaaBD",
    "delivery_caption_enabled": True,
    "delivery_caption": "⏳ এই ভিডিওটি {minutes} মিনিট পর স্বয়ংক্রিয়ভাবে মুছে যাবে।",
    "deletion_notice_enabled": True,
    "deletion_notice": "🗑️ নির্ধারিত সময় শেষে ভিডিওটি মুছে ফেলা হয়েছে।",
    "in_app_ads_enabled": False,
    "popup_min_seconds": 10,
    "second_ad_delay_seconds": 5,
    "checkin_enabled": True,
    "video_share_enabled": True,
    "referral_enabled": True,
    "maintenance_enabled": False,
    "maintenance_message": {"bn": "সাইটটি সাময়িক রক্ষণাবেক্ষণে আছে। অনুগ্রহ করে পরে আবার আসুন।", "hi": "साइट रखरखाव में है। कृपया बाद में आएं।", "en": "We are under maintenance. Please come back later."},
    "announcement_enabled": False,
    "announcement_message": {"bn": "", "hi": "", "en": ""},
}


def _get_app_settings():
    """Read normalized app settings with a short process-local TTL cache."""
    cached = _cache_get("app_settings")
    if cached is not None:
        return cached
    try:
        saved = db.collection("settings").document("app").get().to_dict() or {}
    except Exception as exc:
        print("APP SETTINGS READ ERROR:", repr(exc))
        saved = {}
    result = dict(APP_SETTING_DEFAULTS)
    result.update({k: v for k, v in saved.items() if k in APP_SETTING_DEFAULTS})
    for key in ("maintenance_message", "announcement_message"):
        value = result.get(key)
        result[key] = {lang: str((value or {}).get(lang, "") or "")[:1000] for lang in ("bn", "hi", "en")} if isinstance(value, dict) else dict(APP_SETTING_DEFAULTS[key])
    for key in ("in_app_ads_enabled", "checkin_enabled", "video_share_enabled", "referral_enabled", "maintenance_enabled", "announcement_enabled", "join_verification_enabled", "delivery_caption_enabled", "deletion_notice_enabled"):
        result[key] = bool(result.get(key))
    for key, low, high in (("popup_min_seconds", 1, 120), ("second_ad_delay_seconds", 0, 60), ("auto_delete_minutes", 1, 10080), ("deletion_notice_auto_delete_minutes", 1, 10080)):
        try:
            result[key] = max(low, min(high, int(result.get(key, APP_SETTING_DEFAULTS[key]))))
        except (TypeError, ValueError):
            result[key] = APP_SETTING_DEFAULTS[key]
    result["join_channel"] = str(result.get("join_channel") or "@ViralDuniyaaBD").strip()[:100]
    result["delivery_caption"] = str(result.get("delivery_caption") or "")[:1000]
    result["deletion_notice"] = str(result.get("deletion_notice") or "")[:1000]
    return _cache_set("app_settings", result, _SETTINGS_CACHE_TTL)


def _channel_membership(telegram_id: str):
    """Check membership using the delivery bot; that bot must be an admin in the channel."""
    settings = _get_app_settings()
    channel = settings.get("join_channel") or "@ViralDuniyaaBD"
    if not settings.get("join_verification_enabled"):
        return True
    if not DELIVERY_BOT_TOKEN:
        raise HTTPException(status_code=503, detail="Delivery bot is not configured for channel verification")
    try:
        result = httpx.get(
            f"https://api.telegram.org/bot{DELIVERY_BOT_TOKEN}/getChatMember",
            params={"chat_id": channel, "user_id": telegram_id}, timeout=12
        ).json()
    except Exception as exc:
        print("CHANNEL MEMBERSHIP CHECK ERROR:", repr(exc))
        raise HTTPException(status_code=502, detail="Could not verify channel membership. Please try again.")
    if not result.get("ok"):
        print("CHANNEL MEMBERSHIP TELEGRAM ERROR:", result)
        raise HTTPException(status_code=502, detail="Channel verification is unavailable. Check the delivery bot admin permission.")
    status = (result.get("result") or {}).get("status")
    return status in ("creator", "administrator", "member") or (
        status == "restricted" and bool((result.get("result") or {}).get("is_member"))
    )


def _require_channel_membership(telegram_id: str):
    settings = _get_app_settings()
    if settings.get("join_verification_enabled") and not _channel_membership(telegram_id):
        channel = settings.get("join_channel") or "@ViralDuniyaaBD"
        raise HTTPException(status_code=403, detail=f"Please join {channel}, then verify your membership before receiving videos.")


@app.post("/channel/join-status")
def channel_join_status(payload: VideoProgressRequest):
    user, _ = verify_telegram_init_data(payload.init_data)
    settings = _get_app_settings()
    joined = _channel_membership(str(user["id"])) if settings.get("join_verification_enabled") else True
    channel = settings.get("join_channel") or "@ViralDuniyaaBD"
    return {"success": True, "enabled": settings.get("join_verification_enabled"), "joined": joined,
            "channel": channel, "join_url": "https://t.me/" + channel.lstrip("@")}


@app.get("/app-settings")
def public_app_settings():
    settings = _get_app_settings()
    # Cache the bot's public URL so each Mini App open does not call Telegram getMe.
    delivery_bot_url = _cache_get("delivery_bot_url") or ""
    if DELIVERY_BOT_TOKEN and not delivery_bot_url:
        try:
            me = httpx.get(
                f"https://api.telegram.org/bot{DELIVERY_BOT_TOKEN}/getMe", timeout=6
            ).json()
            username = (me.get("result") or {}).get("username") if me.get("ok") else None
            if username:
                delivery_bot_url = _cache_set("delivery_bot_url", f"https://t.me/{username}", 3600)
        except Exception as exc:
            print("DELIVERY BOT USERNAME LOOKUP ERROR:", repr(exc))
    return {"success": True, **{k: settings[k] for k in APP_SETTING_DEFAULTS},
            "delivery_bot_url": delivery_bot_url}


@app.get("/admin/settings")
def get_admin_settings(request: Request):
    require_admin(request, "viewer")
    return {"success": True, **_get_app_settings()}


@app.put("/admin/settings")
def update_admin_settings(payload: dict, request: Request):
    require_admin(request, "editor")
    clean = {}
    for key, low, high in (("auto_delete_minutes", 1, 10080), ("deletion_notice_auto_delete_minutes", 1, 10080), ("popup_min_seconds", 1, 120), ("second_ad_delay_seconds", 0, 60)):
        if key in payload:
            try:
                value = int(payload[key])
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{key} must be a number")
            if not low <= value <= high:
                raise HTTPException(status_code=400, detail=f"{key} must be between {low} and {high}")
            clean[key] = value
    for key in ("in_app_ads_enabled", "checkin_enabled", "video_share_enabled", "referral_enabled", "maintenance_enabled", "announcement_enabled", "join_verification_enabled", "delivery_caption_enabled", "deletion_notice_enabled"):
        if key in payload:
            clean[key] = bool(payload[key])
    for key in ("join_channel", "delivery_caption", "deletion_notice"):
        if key in payload:
            clean[key] = str(payload[key] or "").strip()[:1000 if key != "join_channel" else 100]
    for key in ("maintenance_message", "announcement_message"):
        if key in payload:
            value = payload[key]
            if not isinstance(value, dict):
                raise HTTPException(status_code=400, detail=f"{key} must contain bn, hi and en text")
            clean[key] = {lang: str(value.get(lang, "") or "")[:1000] for lang in ("bn", "hi", "en")}
    if clean:
        settings_ref = db.collection("settings").document("app")
        current = settings_ref.get().to_dict() or {}
        changed = {key: value for key, value in clean.items() if current.get(key) != value}
        if changed:
            changed["updated_at"] = int(time.time())
            settings_ref.set(changed, merge=True)
            _cache_clear("app_settings", "admin_stats")
    return {"success": True, **_get_app_settings(), "message": "Settings saved"}


@app.post("/thumbnails")
def save_thumbnail(thumbnail: Thumbnail, request: Request):
    require_admin(request, "editor")
    doc_ref = db.collection("thumbnails").document()
    doc_ref.set({"file_id": thumbnail.file_id, "created_at": int(time.time())})
    return {
        "success": True,
        "thumbnail_id": doc_ref.id,
        "message": "Thumbnail saved successfully!"
    }


@app.get("/thumbnails")
def get_thumbnails(limit: int = 20, cursor: str = ""):
    """Return a page of Telegram channel thumbnails (newest first)."""
    limit = max(1, min(int(limit or 20), 50))
    query = db.collection("thumbnails").order_by(FieldPath.document_id()).limit(limit + 1)
    if cursor:
        cursor_doc = db.collection("thumbnails").document(cursor).get()
        if cursor_doc.exists:
            query = db.collection("thumbnails").order_by(FieldPath.document_id()).start_after(cursor_doc).limit(limit + 1)
    docs = list(query.stream())
    has_more = len(docs) > limit
    docs = docs[:limit]
    result = []
    for thumbnail in docs:
        data = thumbnail.to_dict() or {}
        data["id"] = thumbnail.id
        result.append(data)
    return {"success": True, "thumbnails": result, "next_cursor": docs[-1].id if has_more and docs else None, "has_more": has_more, "page_size": limit}


@app.get("/thumbnails/{thumbnail_id}/image")
async def get_thumbnail_image(thumbnail_id: str):
    cache_key = "thumbnail_file:" + thumbnail_id
    file_id = _cache_get(cache_key)
    if not file_id:
        doc = db.collection("thumbnails").document(thumbnail_id).get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Thumbnail not found")
        file_id = (doc.to_dict() or {}).get("file_id")
        if file_id:
            _cache_set(cache_key, file_id, 3600)
    if not file_id:
        raise HTTPException(status_code=404, detail="Telegram file ID not found")

    if not BOT_TOKEN:
        raise HTTPException(status_code=500, detail="Telegram bot token missing")

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            telegram_response = await client.get(
                f"https://api.telegram.org/bot{BOT_TOKEN}/getFile",
                params={"file_id": file_id}
            )
            telegram_response.raise_for_status()
            telegram_data = telegram_response.json()

            if not telegram_data.get("ok"):
                raise HTTPException(
                    status_code=502,
                    detail="Could not retrieve Telegram file"
                )

            file_path = telegram_data["result"]["file_path"]
            image_response = await client.get(
                f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_path}"
            )
            image_response.raise_for_status()

            return Response(
                content=image_response.content,
                media_type=image_response.headers.get("content-type", "image/jpeg"),
                headers={"Cache-Control": "public, max-age=3600"}
            )

    except HTTPException:
        raise
    except Exception as exc:
        print("THUMBNAIL ERROR:", repr(exc))
        raise HTTPException(status_code=500, detail="Thumbnail error")
