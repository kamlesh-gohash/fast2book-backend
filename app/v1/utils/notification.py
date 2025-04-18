import json
import os

from datetime import datetime, timedelta
from typing import Any, Dict, List

import bcrypt
import firebase_admin

from fastapi import HTTPException, status
from firebase_admin import credentials, messaging


# Get the absolute path to the firebase-adminsdk.json file
# BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Points to /app/v1/utils/
# FIREBASE_CRED_PATH = os.path.join(BASE_DIR, "firebase-adminsdk.json")
# print(FIREBASE_CRED_PATH, 'FIREBASE_CRED_PATH')
# Initialize Firebase Admin SDK (do this once in your app's initialization, not in the function)
if not firebase_admin._apps:
    try:
        # with open(FIREBASE_CRED_PATH, 'r') as f:
        #     cred_data = json.load(f)
        #     print("Credential content:", cred_data)
        required_env_vars = [
            "TYPE",
            "PROJECT_ID",
            "PRIVATE_KEY_ID",
            "PRIVATE_KEY",
            "CLIENT_EMAIL",
            "CLIENT_ID",
            "AUTH_URI",
            "TOKEN_URI",
            "AUTH_PROVIDER_X509_CERT_URL",
            "CLIENT_X509_CERT_URL",
        ]

        missing_or_empty_vars = [var for var in required_env_vars if not os.environ.get(var)]
        if missing_or_empty_vars:
            raise ValueError(f"Missing or empty environment variables: {', '.join(missing_or_empty_vars)}")

        private_key = os.environ.get("PRIVATE_KEY")
        if not private_key:
            raise ValueError("PRIVATE_KEY is empty")

        private_key = private_key.replace("\\n", "\n")

        if not private_key.startswith("-----BEGIN PRIVATE KEY-----") or not private_key.endswith(
            "-----END PRIVATE KEY-----\n"
        ):
            key_preview = private_key[:50] + "..." if len(private_key) > 50 else private_key
            raise ValueError(
                f"Invalid PRIVATE_KEY format. Must be a valid PEM-encoded RSA private key. "
                f"Current value starts with: '{key_preview}'"
            )

        FIREBASE_CRED_PATH = {
            "type": os.environ.get("TYPE"),
            "project_id": os.environ.get("PROJECT_ID"),
            "private_key_id": os.environ.get("PRIVATE_KEY_ID"),
            "private_key": private_key,
            "client_email": os.environ.get("CLIENT_EMAIL"),
            "client_id": os.environ.get("CLIENT_ID"),
            "auth_uri": os.environ.get("AUTH_URI"),
            "token_uri": os.environ.get("TOKEN_URI"),
            "auth_provider_x509_cert_url": os.environ.get("AUTH_PROVIDER_X509_CERT_URL"),
            "client_x509_cert_url": os.environ.get("CLIENT_X509_CERT_URL"),
        }

        cred = credentials.Certificate(FIREBASE_CRED_PATH)
        firebase_admin.initialize_app(cred)
    except FileNotFoundError:
        raise Exception("Firebase service account key file not found at: {}".format(FIREBASE_CRED_PATH))
    except json.JSONDecodeError as e:
        raise Exception("Invalid JSON in service account file: {}".format(str(e)))
    except Exception as e:
        raise Exception("Failed to initialize Firebase Admin SDK: {}".format(str(e)))


async def send_push_notification(
    subscriptions: List[Any], title: str, body: str, data: Dict[str, Any] = None
) -> Dict[str, str]:
    """
    Sends a push notification to multiple web and mobile clients using Firebase Admin SDK.

    Args:
        subscriptions (List[Any]): List of subscriptions. Can include web push subscription dictionaries
                                  ({"endpoint": str, "keys": {"p256dh": str, "auth": str}}) or mobile tokens (str).
        title (str): Notification title
        body (str): Notification body
        data (Dict[str, Any], optional): Additional data to send with the notification

    Returns:
        Dict[str, str]: Response message
    """
    try:
        responses = []
        for sub in subscriptions:
            if isinstance(sub, dict) and "endpoint" in sub and "keys" in sub:

                message = messaging.Message(
                    notification=messaging.Notification(
                        title=title,
                        body=body,
                    ),
                    data=data or {},
                    webpush=messaging.WebpushConfig(
                        notification=messaging.WebpushNotification(
                            title=title,
                            body=body,
                            data=data or {},
                        ),
                        fcm_options=messaging.WebpushFCMOptions(link="https://fast2book.com"),  # Optional: URL to open
                    ),
                )
                response = messaging.send(message, subscription_info=sub)
            else:
                message = messaging.Message(
                    notification=messaging.Notification(
                        title=title,
                        body=body,
                    ),
                    data=data or {},
                    token=sub,
                )
                response = messaging.send(message)

            responses.append(response)
        return {"message": f"Notifications sent successfully: {', '.join(responses)}"}
    except Exception as e:
        raise Exception(f"Failed to send notification: {str(e)}")
