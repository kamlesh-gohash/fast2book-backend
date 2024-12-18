# app/v1/utils/email.py

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os


def send_email(to_email: str, otp: str):
    """Send OTP to user's email."""
    from_email = os.getenv('EMAIL_USER')
    from_password = os.getenv('EMAIL_PASSWORD')

    # Set up the email content
    subject = "Your OTP Code"
    body = f"Your OTP code is {otp}. Please use it within the next 10 minutes."

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Send the email
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(from_email, from_password)
            server.sendmail(from_email, to_email, msg.as_string())
        print(f"OTP sent to {to_email}")
    except Exception as e:
        print(f"Failed to send OTP email: {str(e)}")
