# app/v1/utils/email.py
import os
import random
import smtplib

from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from string import Template
from typing import Optional

import boto3
import requests

from bs4 import BeautifulSoup
from fastapi import HTTPException

from app.v1.models import email_monitor_collection
from app.v1.models.email_monitor import EmailMonitor, EmailStatus


def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"


def strip_tags(html_content: str) -> str:
    """Remove HTML tags from the given content."""
    soup = BeautifulSoup(html_content, "lxml")
    return soup.get_text()


def validate_image_urls(html_content: str) -> list:
    """Check if image URLs are accessible."""
    soup = BeautifulSoup(html_content, "lxml")
    img_tags = soup.find_all("img")
    inaccessible_urls = []
    for img in img_tags:
        src = img.get("src", "")
        if src.startswith("http"):
            try:
                response = requests.head(src, timeout=5)
                if response.status_code != 200:
                    inaccessible_urls.append(src)
            except requests.RequestException:
                inaccessible_urls.append(src)
    return inaccessible_urls


async def send_email(to_email: str, source: str, context: dict = None, cc_email: Optional[str] = None):
    """Send email based on the source and context provided with different sender emails."""
    # Define email categories and their corresponding sender addresses
    auth_emails = {
        "Resend OTP",
        "Forgot Password",
        "Signup Successful",
        "Verification Email",
        "Activation_code",
        "sign_in",
        "Forgot_Password",
        "validate_otp",
        "Account created",
        "Login With Otp",
        "APP Link",
        "Vednor Create",
    }
    payment_emails = {
        "Order Placed",
        "Payment Success",
        "Booking Confirmation",
        "Booking Notification",
        "Booking Cancelled",
        "Booking Cancelled Vendor",
    }
    support_emails = {
        "Support Ticket Reply",
        "Support Request",
        "New Support Request",
    }
    contact_emails = {
        "Ticket Created",
        "Ticket Reply",
        "Vendor Query Created",
        "Vendor Query Reply",
        "New Ticket Created",
        "New Vendor Query",
    }

    # Determine the sender email based on the source
    if source in auth_emails:
        from_email = "no-reply@fast2book.com"
        from_password = os.getenv("EMAIL_PASSWORD")
    elif source in payment_emails:
        from_email = "billing@fast2book.com"
        from_password = os.getenv("EMAIL_PASSWORD")
    elif source in support_emails:
        from_email = "support@fast2book.com"
        from_password = os.getenv("EMAIL_PASSWORD")
    elif source in contact_emails:
        from_email = "contact@fast2book.com"
        from_password = os.getenv("EMAIL_PASSWORD")
    else:
        from_email = os.getenv("EMAIL_USER")  # Default fallback
        from_password = os.getenv("EMAIL_PASSWORD")

    if not from_email or not from_password:
        raise ValueError(f"Email credentials for {source} are not set in environment variables.")

    # Define the project root and template paths
    project_root = Path(__file__).resolve().parent.parent.parent

    templates = {
        "Resend OTP": project_root / "templates/email/resend_otp.html",
        "Forgot Password": project_root / "templates/email/forgot_password.html",
        "Signup Successful": project_root / "templates/email/signup_successful.html",
        "Verification Email": project_root / "templates/email/verification_email.html",
        "Order Placed": project_root / "templates/email/order_place.html",
        "Payment Success": project_root / "templates/email/payment_successfully.html",
        "Activation_code": project_root / "templates/email/activation_code.html",
        "sign_in": project_root / "templates/email/welcome.html",
        "Forgot_Password": project_root / "templates/email/forgot_password.html",
        "validate_otp": project_root / "templates/email/accountapproval.html",
        "Account created": project_root / "templates/email/account_create.html",
        "Login With Otp": project_root / "templates/email/login_with_otp.html",
        "Vednor Create": project_root / "templates/email/vendor_create_email.html",
        "APP Link": project_root / "templates/email/app_link.html",
        "Booking Confirmation": project_root / "templates/email/booking_confirm.html",
        "Ticket Created": project_root / "templates/email/ticket.html",
        "Ticket Reply": project_root / "templates/email/ticket_reply.html",
        "Vendor Query Created": project_root / "templates/email/vendor_query.html",
        "Vendor Query Reply": project_root / "templates/email/vendor_query_reply.html",
        "Support Ticket Reply": project_root / "templates/email/support_ticket_reply.html",
        "Support Request": project_root / "templates/email/support_request.html",
        "New Support Request": project_root / "templates/email/new_support_request.html",
        "New Ticket Created": project_root / "templates/email/new_ticket.html",
        "New Vendor Query": project_root / "templates/email/new_vendor_query.html",
        "Booking Notification": project_root / "templates/email/booking_notification.html",
        "Booking Cancelled": project_root / "templates/email/booking_cancel.html",
        "Booking Cancelled Vendor": project_root / "templates/email/booking_cancel_email_to_vendor.html",
    }

    # Get the template path based on the source
    template_path = templates.get(source)
    if not template_path:
        raise ValueError(f"No template defined for source: {source}")

    # Verify if the template exists
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found at: {template_path}")

    # Read the HTML template
    try:
        with open(template_path, "r", encoding="utf-8") as file:
            html_template = file.read()
    except Exception as e:
        raise

    # Replace placeholders with actual values
    try:
        template = Template(html_template)
        html_content = template.substitute(**context)
    except KeyError as e:
        raise
    except Exception as e:
        raise

    # Validate image URLs
    inaccessible_urls = validate_image_urls(html_content)
    if inaccessible_urls:
        raise ValueError(f"Inaccessible image URLs: {', '.join(inaccessible_urls)}")

    # Create plain text version by stripping HTML tags
    plain_text_content = strip_tags(html_content)

    # Set up the email
    msg = MIMEMultipart("alternative")
    msg["From"] = from_email
    msg["To"] = to_email
    if cc_email:
        msg["Cc"] = cc_email
    subject_map = {
        "Activation_code": "Your Activation Code",
        "Forgot Password": "Forgot Password",
        "Resend OTP": "Resend OTP",
        "Account created": "Account created",
        "Login With Otp": "Login With Otp",
        "Vednor Create": "Vednor Create",
        "APP Link": "Download Our App",
        "Payment Success": "Payment Success",
        "Booking Confirmation": "Booking Confirm",
        "Ticket Created": "Ticket Created",
        "Ticket Reply": "Ticket Reply",
        "Vendor Query Created": "Vendor Query Created",
        "Vendor Query Reply": "Vendor Query Reply",
        "Support Ticket Reply": "Support Ticket Reply",
        "Support Request": "Support Request",
        "New Support Request": "New Support Request",
        "New Ticket Created": "New Ticket Created",
        "New Vendor Query": "New Vendor Query",
        "Booking Notification": "New Booking",
        "Booking Cancelled": "Booking Cancelled",
        "Booking Cancelled Vendor": "Booking Cancelled Vendor",
    }
    msg["Subject"] = subject_map.get(source, "Welcome")  # Default subject

    # Attach both plain text and HTML versions
    text_part = MIMEText(plain_text_content, "plain", "utf-8")
    html_part = MIMEText(html_content, "html", "utf-8")
    msg.attach(text_part)
    msg.attach(html_part)

    email_log = {
        "to_email": to_email,
        "subject": msg["Subject"],
        "source": source,
        "status": EmailStatus.FAILURE.value,
        "message": "Pending send",
        "context": context,
        "html_content": html_content,
        "sent_at": datetime.utcnow(),
        "inaccessible_urls": inaccessible_urls if inaccessible_urls else None,
    }

    # Skip logging if to_email is support@fast2book.com
    log_id = None
    if to_email != "support@fast2book.com":
        try:
            result = await email_monitor_collection.insert_one(email_log)
            log_id = result.inserted_id
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to log email: {str(e)}")

    try:
        server = smtplib.SMTP_SSL("smtp.zeptomail.com", 465)
        server.login(from_email, from_password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()

        success_message = "Email sent successfully."
        if inaccessible_urls:
            success_message += " Note: Some images may not display due to inaccessible URLs."

        if log_id:
            await email_monitor_collection.update_one(
                {"_id": log_id}, {"$set": {"status": "SUCCESS", "message": success_message}}
            )
        return {"status": "SUCCESS", "message": success_message}
    except Exception as e:
        error_message = f"Failed to send email: {str(e)}"
        if inaccessible_urls:
            error_message += f" Inaccessible image URLs: {', '.join(inaccessible_urls)}"
        if log_id:
            await email_monitor_collection.update_one(
                {"_id": log_id}, {"$set": {"status": "FAILURE", "message": error_message}}
            )
        return {"status": "FAILURE", "message": error_message}


# AWS SNS Configuration (Set your credentials in environment variables or AWS config)
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID", "your-access-key")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "your-secret-key")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
# Initialize SNS client
sns_client = boto3.client(
    "sns", aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY, region_name=AWS_REGION
)


async def send_sms_on_phone(to_phone: str, otp: str, expiry_minutes: int = 10):
    try:
        formatted_phone = f"+91{to_phone}"
        message = f"Your OTP for login to Fast2Book is {otp}. This OTP is valid for {expiry_minutes} minutes. Do not share this with anyone. - Fast2Book"

        # Send SMS
        response = sns_client.publish(PhoneNumber=formatted_phone, Message=message)
        return {"message": "OTP sent successfully", "otp": otp, "sns_response": response}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def send_app_link(to_phone: str, app_link: str):
    try:
        formatted_phone = f"+{to_phone}"
        message = f"Your Fast2Book App Link is {app_link}. Do not share this with anyone. - Fast2Book"
        # Send SMS
        response = sns_client.publish(PhoneNumber=formatted_phone, Message=message)
        return {"message": "OTP sent successfully", "otp": app_link, "sns_response": response}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
