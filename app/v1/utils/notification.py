# import firebase_admin
# from firebase_admin import credentials, messaging
# from fastapi import HTTPException, status
# from datetime import datetime, timedelta
# from typing import Optional
# import bcrypt

# # Initialize Firebase Admin SDK (do this once in your app's initialization, not in the function)
# if not firebase_admin._apps:
#     cred = credentials.Certificate("path/to/firebase-adminsdk.json")  # Replace with your service account key path
#     firebase_admin.initialize_app(cred)

# async def send_push_notification(device_token: str, title: str, body: str, data: dict = None) -> dict:
#     """
#     Sends a push notification to a single device using Firebase Admin SDK.
#     """
#     try:
#         message = messaging.Message(
#             notification=messaging.Notification(
#                 title=title,
#                 body=body,
#             ),
#             data=data or {},
#             token=device_token,
#         )
#         response = messaging.send(message)
#         return {"message": f"Notification sent successfully: {response}"}
#     except Exception as e:
#         raise Exception(f"Failed to send notification: {str(e)}")
