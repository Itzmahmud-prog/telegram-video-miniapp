import os
import httpx
import hmac
import hashlib
import json
import time
from urllib.parse import parse_qsl
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from firebase_db import db

load_dotenv()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
BOT_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()

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
    country: str
    category: str
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


class TelegramAuthRequest(BaseModel):
    init_data: str


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
        return user, auth_date

    except (ValueError, TypeError, json.JSONDecodeError):
        raise HTTPException(
            status_code=401, detail="Invalid or expired Telegram initData"
        )


@app.on_event("startup")
async def register_telegram_webhook():
    """Register this Render URL as the bot webhook when the app starts."""
    if not BOT_TOKEN or not TELEGRAM_WEBHOOK_SECRET or not WEBHOOK_URL:
        print("Telegram webhook setup skipped: required environment variable missing.")
        return

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/setWebhook",
                json={
                    "url": WEBHOOK_URL,
                    "secret_token": TELEGRAM_WEBHOOK_SECRET,
                    "allowed_updates": ["channel_post", "edited_channel_post"],
                },
            )
            response.raise_for_status()
            result = response.json()
            if result.get("ok"):
                print("Telegram webhook registered successfully.")
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
    message = update.get("channel_post") or update.get("edited_channel_post")
    if not message:
        return {"success": True, "message": "Update ignored"}

    video = message.get("video")
    if not video or not video.get("file_id"):
        return {"success": True, "message": "This channel post is not a video"}

    chat = message.get("chat") or {}
    chat_id = str(chat.get("id", ""))
    message_id = message.get("message_id")
    if not chat_id or not message_id:
        return {"success": True, "message": "Channel message information missing"}

    # One Firestore document per channel message prevents duplicate records.
    document_id = f"{chat_id}_{message_id}"
    video_ref = db.collection("videos").document(document_id)
    existing = video_ref.get()
    old_data = existing.to_dict() if existing.exists else {}

    caption = (message.get("caption") or "").strip()
    file_name = (video.get("file_name") or "").strip()
    title = old_data.get("title") or caption or file_name or "New Telegram Video"

    video_data = {
        "title": title,
        "country": old_data.get("country", ""),
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


@app.post("/auth/telegram")
def telegram_login(payload: TelegramAuthRequest):
    user, auth_date = verify_telegram_init_data(payload.init_data)
    telegram_id = str(user["id"])
    user_ref = db.collection("users").document(telegram_id)
    existing = user_ref.get()
    now = int(time.time())

    profile = {
        "telegram_id": telegram_id,
        "first_name": user.get("first_name", ""),
        "last_name": user.get("last_name", ""),
        "username": user.get("username", ""),
        "language_code": user.get("language_code", ""),
        "photo_url": user.get("photo_url", ""),
        "last_seen": now,
        "telegram_auth_date": auth_date,
    }
    if not existing.exists:
        profile["created_at"] = now
    user_ref.set(profile, merge=True)

    return {
        "success": True,
        "message": "Telegram authentication successful",
        "user": profile,
    }


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
def get_videos():
    videos = db.collection("videos").stream()
    result = []

    for video in videos:
        data = video.to_dict()
        data["id"] = video.id
        result.append(data)

    return {"success": True, "videos": result}


@app.post("/videos")
def add_video(video: Video):
    doc_ref = db.collection("videos").document()
    doc_ref.set(video.model_dump(exclude_none=True))
    return {
        "success": True,
        "video_id": doc_ref.id,
        "message": "Video added successfully!"
    }


@app.put("/videos/{video_id}")
def update_video(video_id: str, video: Video):
    doc_ref = db.collection("videos").document(video_id)

    if not doc_ref.get().exists:
        raise HTTPException(status_code=404, detail="Video not found")

    # Exclude omitted optional Telegram fields so editing metadata does not erase file_id.
    doc_ref.update(video.model_dump(exclude_none=True))
    return {
        "success": True,
        "video_id": video_id,
        "message": "Video updated successfully!"
    }


@app.delete("/videos/{video_id}")
def delete_video(video_id: str):
    doc_ref = db.collection("videos").document(video_id)

    if not doc_ref.get().exists:
        raise HTTPException(status_code=404, detail="Video not found")

    doc_ref.delete()
    return {
        "success": True,
        "video_id": video_id,
        "message": "Video deleted successfully!"
    }


@app.post("/admin/login")
def admin_login(login: AdminLogin):
    if login.username == ADMIN_USERNAME and login.password == ADMIN_PASSWORD:
        return {"success": True, "message": "Admin login successful!"}

    raise HTTPException(status_code=401, detail="Invalid username or password")


@app.post("/thumbnails")
def save_thumbnail(thumbnail: Thumbnail):
    doc_ref = db.collection("thumbnails").document()
    doc_ref.set({"file_id": thumbnail.file_id})
    return {
        "success": True,
        "thumbnail_id": doc_ref.id,
        "message": "Thumbnail saved successfully!"
    }


@app.get("/thumbnails")
def get_thumbnails():
    thumbnails = db.collection("thumbnails").stream()
    result = []

    for thumbnail in thumbnails:
        data = thumbnail.to_dict()
        data["id"] = thumbnail.id
        result.append(data)

    return {"success": True, "thumbnails": result}


@app.get("/thumbnails/{thumbnail_id}/image")
async def get_thumbnail_image(thumbnail_id: str):
    doc = db.collection("thumbnails").document(thumbnail_id).get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Thumbnail not found")

    file_id = doc.to_dict().get("file_id")
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
                media_type=image_response.headers.get("content-type", "image/jpeg")
            )

    except HTTPException:
        raise
    except Exception as exc:
        print("THUMBNAIL ERROR:", repr(exc))
        raise HTTPException(status_code=500, detail="Thumbnail error")
