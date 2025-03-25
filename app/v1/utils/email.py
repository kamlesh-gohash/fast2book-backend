# app/v1/utils/email.py

import os
import random
import smtplib

from datetime import datetime
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from string import Template

import boto3

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


# Define the image directory


async def send_email(to_email: str, source: str, context: dict = None):
    """Send email based on the source and context provided."""
    from_email = os.getenv("EMAIL_USER")
    from_password = os.getenv("EMAIL_PASSWORD")
    if not from_email or not from_password:
        raise ValueError("Email credentials (EMAIL_USER and EMAIL_PASSWORD) are not set in environment variables.")

    # Define the project root and template paths
    project_root = Path(__file__).resolve().parent.parent.parent

    IMAGE_DIR = Path(project_root / "templates/email/images")
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

    # Parse the HTML to find all image tags
    soup = BeautifulSoup(html_content, "lxml")
    img_tags = soup.find_all("img")

    # Dictionary to keep track of embedded images (to avoid duplicates)
    embedded_images = {}

    # Embed images and update the src attributes
    for idx, img in enumerate(img_tags):
        src = img.get("src", "")
        if not src:
            continue

        # Assume src is the filename (e.g., "fast2 book logo-05 2 1.png")
        image_filename = src
        image_path = IMAGE_DIR / image_filename

        if not image_path.exists():
            raise FileNotFoundError(f"Image not found: {image_path}")

        # Generate a unique cid for each image
        cid = f"image_{idx}"
        img["src"] = f"cid:{cid}"

        # Embed the image if not already embedded
        if image_filename not in embedded_images:
            try:
                with open(image_path, "rb") as img_file:
                    mime_image = MIMEImage(img_file.read())
                    mime_image.add_header("Content-ID", f"<{cid}>")
                    mime_image.add_header("Content-Disposition", "inline", filename=image_filename)
                    embedded_images[image_filename] = mime_image
            except Exception as e:
                raise

    # Update the HTML content with the modified image tags
    html_content = str(soup)

    # Create plain text version by stripping HTML tags
    plain_text_content = strip_tags(html_content)

    # Set up the email
    msg = MIMEMultipart("related")  # Use "related" for embedding images
    msg["From"] = from_email
    msg["To"] = to_email
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
    }
    msg["Subject"] = subject_map.get(source, "Welcome")  # Default subject

    # Create a multipart/alternative for text and HTML
    msg_alternative = MIMEMultipart("alternative")
    msg.attach(msg_alternative)

    # Attach both plain text and HTML versions
    text_part = MIMEText(plain_text_content, "plain")
    html_part = MIMEText(html_content, "html")
    msg_alternative.attach(text_part)
    msg_alternative.attach(html_part)

    # Attach all embedded images
    for mime_image in embedded_images.values():
        msg.attach(mime_image)
    email_log = {
        "to_email": to_email,
        "subject": msg["Subject"],
        "source": source,
        "status": EmailStatus.FAILURE.value,  # Use .value to get the string
        "message": "Pending send",
        "context": context,
        "html_content": html_content,  # Add the final HTML content here
        "sent_at": datetime.utcnow(),
    }

    # Skip logging if to_email is fast2book@yopmail.com
    log_id = None
    if to_email != "fast2book@yopmail.com":
        try:
            result = await email_monitor_collection.insert_one(email_log)
            log_id = result.inserted_id
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to log email: {str(e)}")
    # Send the email
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(from_email, from_password)

        text = msg.as_string()
        server.sendmail(from_email, to_email, text)

        server.quit()
        if log_id:
            await email_monitor_collection.update_one(
                {"_id": email_log["_id"]}, {"$set": {"status": "SUCCESS", "message": "Email sent successfully."}}
            )

        return {"status": "SUCCESS", "message": "Email sent successfully."}
    except Exception as e:
        if log_id:
            await email_monitor_collection.update_one(
                {"_id": email_log["_id"]}, {"$set": {"status": "FAILURE", "message": str(e)}}
            )

        return {"status": "FAILURE", "message": str(e)}


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
