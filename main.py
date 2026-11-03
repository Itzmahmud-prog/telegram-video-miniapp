
import os
import httpx
import hmac
import hashlib
import json
import time

from urllib.parse import parse_qsl
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from firebase_db import db


# ==========================================
# ENVIRONMENT VARIABLES
# ==========================================

load_dotenv()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")


# ==========================================
# FASTAPI APP
# ==========================================

app = FastAPI(
    title="Telegram Video Mini App API",
    description="Backend API for Telegram Video Mini App"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# DATA MODELS
# ==========================================

class Video(BaseModel):
    title: str
    country: str
    category: str
    status: str = "active"
    thumbnail: str = ""


class AdminLogin(BaseModel):
    username: str
    password: str


class Thumbnail(BaseModel):
    file_id: str


class TelegramAuthRequest(BaseModel):
    init_data: str


# ==========================================
# TELEGRAM LOGIN VERIFICATION
# ==========================================

def verify_telegram_init_data(init_data: str):
    """Verify Telegram Mini App initData using the bot token."""

    if not BOT_TOKEN:
        print("TELEGRAM AUTH ERROR: Bot token missing")
        raise HTTPException(
            status_code=500,
            detail="Telegram bot token missing"
        )

    if not init_data or not init_data.strip():
        print("TELEGRAM AUTH ERROR: Empty initData")
        raise HTTPException(
            status_code=401,
            detail="Telegram initData is empty"
        )

    try:
        pairs = parse_qsl(
            init_data,
            keep_blank_values=True,
            strict_parsing=True
        )

        values = dict(pairs)

        if len(values) != len(pairs):
            raise ValueError("Duplicate initData fields")

        received_hash = values.pop("hash", None)

        # Remove signature field if present
        values.pop("signature", None)

        if not received_hash:
            raise ValueError("Missing hash")

        data_check_string = "\n".join(
            f"{key}={value}"
            for key, value in sorted(values.items())
        )

        secret_key = hmac.new(
            b"WebAppData",
            BOT_TOKEN.encode("utf-8"),
            hashlib.sha256
        ).digest()

        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            calculated_hash,
            received_hash
        ):
            print("TELEGRAM AUTH ERROR: Invalid signature")
            raise ValueError("Invalid Telegram signature")

        auth_date = int(values.get("auth_date", "0"))
        now = int(time.time())

        print("TELEGRAM AUTH: Signature verified")
        print("TELEGRAM AUTH: Auth date:", auth_date)

        if (
            auth_date <= 0
            or auth_date > now + 60
            or now - auth_date > 86400
        ):
            print("TELEGRAM AUTH ERROR: Invalid or expired auth_date")
            raise ValueError("Expired or invalid auth_date")

        user = json.loads(values.get("user", ""))

        if not isinstance(user, dict) or not user.get("id"):
            raise ValueError("Telegram user data missing")

        print("TELEGRAM AUTH: User verified successfully")

        return user, auth_date

    except HTTPException:
        raise

    except Exception as e:
        print(
            "TELEGRAM AUTH ERROR:",
            type(e).__name__,
            str(e)
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired Telegram initData"
        )


# ==========================================
# TELEGRAM LOGIN API
# ==========================================

@app.post("/auth/telegram")
def telegram_login(payload: TelegramAuthRequest):

    user, auth_date = verify_telegram_init_data(
        payload.init_data
    )

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
        "user": profile
    }


# ==========================================
# HOME API
# ==========================================

@app.get("/")
def home():

    return {
        "status": "success",
        "message": "Telegram Mini App Backend is running!"
    }


# ==========================================
# HEALTH CHECK API
# ==========================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ==========================================
# VIDEO APIs
# ==========================================

@app.get("/videos")
def get_videos():

    videos = db.collection("videos").stream()

    result = []

    for video in videos:

        data = video.to_dict()

        data["id"] = video.id

        result.append(data)

    return {
        "success": True,
        "videos": result
    }


@app.post("/videos")
def add_video(video: Video):

    doc_ref = db.collection("videos").document()

    doc_ref.set(video.model_dump())

    return {
        "success": True,
        "video_id": doc_ref.id,
        "message": "Video added successfully!"
    }


@app.put("/videos/{video_id}")
def update_video(video_id: str, video: Video):

    doc_ref = db.collection("videos").document(video_id)

    if not doc_ref.get().exists:
        raise HTTPException(
            status_code=404,
            detail="Video not found"
        )

    doc_ref.update(video.model_dump())

    return {
        "success": True,
        "video_id": video_id,
        "message": "Video updated successfully!"
    }


@app.delete("/videos/{video_id}")
def delete_video(video_id: str):

    doc_ref = db.collection("videos").document(video_id)

    if not doc_ref.get().exists:
        raise HTTPException(
            status_code=404,
            detail="Video not found"
        )

    doc_ref.delete()

    return {
        "success": True,
        "video_id": video_id,
        "message": "Video deleted successfully!"
    }


# ==========================================
# ADMIN LOGIN API
# ==========================================

@app.post("/admin/login")
def admin_login(login: AdminLogin):

    if (
        login.username == ADMIN_USERNAME
        and login.password == ADMIN_PASSWORD
    ):
        return {
            "success": True,
            "message": "Admin login successful!"
        }

    raise HTTPException(
        status_code=401,
        detail="Invalid username or password"
    )


# ==========================================
# THUMBNAIL APIs
# ==========================================

@app.post("/thumbnails")
def save_thumbnail(thumbnail: Thumbnail):

    doc_ref = db.collection("thumbnails").document()

    doc_ref.set({
        "file_id": thumbnail.file_id
    })

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

    return {
        "success": True,
        "thumbnails": result
    }


# ==========================================
# TELEGRAM THUMBNAIL IMAGE API
# ==========================================

@app.get("/thumbnails/{thumbnail_id}/image")
async def get_thumbnail_image(thumbnail_id: str):

    doc = (
        db.collection("thumbnails")
        .document(thumbnail_id)
        .get()
    )

    if not doc.exists:
        raise HTTPException(
            status_code=404,
            detail="Thumbnail not found"
        )

    file_id = doc.to_dict().get("file_id")

    if not file_id:
        raise HTTPException(
            status_code=404,
            detail="Telegram file ID not found"
        )

    if not BOT_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="Telegram bot token missing"
        )

    try:

        async with httpx.AsyncClient(timeout=30) as client:

            telegram_response = await client.get(
                f"https://api.telegram.org/bot{BOT_TOKEN}/getFile",
                params={
                    "file_id": file_id
                }
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
                media_type=image_response.headers.get(
                    "content-type",
                    "image/jpeg"
                )
            )

    except HTTPException:
        raise

    except Exception as e:

        print(
            "THUMBNAIL ERROR:",
            repr(e)
        )

        raise HTTPException(
            status_code=500,
            detail="Thumbnail error"
        )
