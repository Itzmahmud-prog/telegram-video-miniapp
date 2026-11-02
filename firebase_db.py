import json
import os

import firebase_admin
from firebase_admin import credentials, firestore


if not firebase_admin._apps:
    firebase_credentials_json = os.environ.get("FIREBASE_CREDENTIALS_JSON")

    if not firebase_credentials_json:
        raise RuntimeError(
            "FIREBASE_CREDENTIALS_JSON environment variable is missing. "
            "Add the contents of your Firebase service-account JSON in Render."
        )

    try:
        service_account_info = json.loads(firebase_credentials_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "FIREBASE_CREDENTIALS_JSON is not valid JSON. "
            "Paste the complete Firebase service-account JSON."
        ) from exc

    cred = credentials.Certificate(service_account_info)
    firebase_admin.initialize_app(cred)

db = firestore.client()
