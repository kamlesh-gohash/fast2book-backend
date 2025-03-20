# app/v1/utils/email.py

import os
import random
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from string import Template

import boto3

from fastapi import HTTPException


def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"


# async def send_email(to_email: str, otp: str):
#     """Send OTP to user's email."""
#     from_email = os.getenv('EMAIL_USER')
#     from_password = os.getenv('EMAIL_PASSWORD')

#     # Set up the email content
#     subject = "Your OTP Code"
#     body = f"Your OTP code is {otp}. Please use it within the next 10 minutes."

#     msg = MIMEMultipart()
#     msg['From'] = from_email
#     msg['To'] = to_email
#     msg['Subject'] = subject
#     msg.attach(MIMEText(body, 'plain'))

#     # Send the email
#     try:
#         # Connect to the SMTP server
#         server = smtplib.SMTP('smtp.gmail.com', 587)
#         server.starttls()
#         server.login(from_email, from_password)

#         # Send the email
#         text = msg.as_string()
#         server.sendmail(from_email, to_email, text)

#         # Close the connection to the server
#         server.quit()
#     except Exception as e:
#         print(f"Failed to send OTP to {to_email}: {e}")


# async def send_email(to_email: str, otp: str):
#     """Send OTP to user's email using HTML template."""
#     from_email = os.getenv("EMAIL_USER")
#     from_password = os.getenv("EMAIL_PASSWORD")

#     project_root = Path(__file__).resolve().parent.parent.parent
#     template_path = project_root / "templates" / "email" / "forgot_password.html"

#     # Verify if template exists
#     if not template_path.exists():
#         raise FileNotFoundError(f"Template not found at: {template_path}")
#     with open(template_path, "r", encoding="utf-8") as file:
#         html_template = file.read()

#     # Replace placeholder with actual OTP
#     html_content = html_template.format(otp=otp)

#     # Set up the email
#     msg = MIMEMultipart("alternative")
#     msg["From"] = from_email
#     msg["To"] = to_email
#     msg["Subject"] = "Your OTP Code"

#     # Attach both plain text and HTML versions
#     text_part = MIMEText(f"Your OTP code is {otp}. Please use it within the next 10 minutes.", "plain")
#     html_part = MIMEText(html_content, "html")

#     msg.attach(text_part)
#     msg.attach(html_part)

#     # Send the email
#     try:
#         server = smtplib.SMTP("smtp.gmail.com", 587)
#         server.starttls()
#         server.login(from_email, from_password)

#         text = msg.as_string()
#         server.sendmail(from_email, to_email, text)

#         server.quit()
#         return True
#     except Exception as e:
#         return False


async def send_vendor_email(to_email, password, login_link):
    from_email = os.getenv("EMAIL_USER")
    from_password = os.getenv("EMAIL_PASSWORD")

    # Path to the email template
    project_root = Path(__file__).resolve().parent.parent.parent
    template_path = project_root / "templates" / "email" / "vendor_create_email.html"

    # Verify if the template exists
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found at: {template_path}")

    # Read the HTML template
    with open(template_path, "r", encoding="utf-8") as file:
        html_template = file.read()
    # Replace placeholders with actual values
    template = Template(html_template)
    html_content = template.substitute(password=password, login_link=login_link)

    # Set up the email
    msg = MIMEMultipart("alternative")
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = "Vendor Account Activation"

    # Attach both plain text and HTML versions
    text_part = MIMEText(
        f"Your login link is {login_link}. Please use this password to login: {password}.",
        "plain",
    )
    html_part = MIMEText(html_content, "html")

    msg.attach(text_part)
    msg.attach(html_part)

    # Send the email
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(from_email, from_password)

        text = msg.as_string()
        server.sendmail(from_email, to_email, text)

        server.quit()
        return {"status": "SUCCESS", "message": "Email sent successfully."}
    except Exception as e:
        return {"status": "FAILURE", "message": str(e)}


import logging
import os
import random
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from string import Template

from bs4 import BeautifulSoup


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def strip_tags(html_content: str) -> str:
    """Remove HTML tags from the given content."""
    soup = BeautifulSoup(html_content, "lxml")
    return soup.get_text()


async def send_email(to_email: str, source: str, context: dict = None):
    """Send email based on the source and context provided."""
    from_email = os.getenv("EMAIL_USER")
    from_password = os.getenv("EMAIL_PASSWORD")
    if not from_email or not from_password:
        raise ValueError("Email credentials (EMAIL_USER and EMAIL_PASSWORD) are not set in environment variables.")

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
        logger.error(f"Failed to read template file: {e}")
        raise

    # Replace placeholders with actual values
    try:
        template = Template(html_template)
        html_content = template.substitute(**context)
    except KeyError as e:
        logger.error(f"Missing placeholder in template: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to substitute placeholders: {e}")
        raise

    # Create plain text version by stripping HTML tags
    plain_text_content = strip_tags(html_content)
    # Set up the email
    msg = MIMEMultipart("alternative")
    msg["From"] = from_email
    msg["To"] = to_email
    subject_map = {
        "Activation_code": "Your Activation Code",
        "Forgot Password": "Forgot Password",
        "Resend OTP": "Resend OTP",
        "Account created": "Account created",
        "Login With Otp": "Login With Otp",
        "Vednor Create": "Vednor Create",
        "APP Link": "APP Link",
        "Payment Success": "Payment Success",
        "Booking Confirmation": "Booking Confirm",
        "Ticket Created": "Ticket Created",
        "Ticket Reply": "Ticket Reply",
        "Vendor Query Created": "Vendor Query Created",
        "Vendor Query Reply": "Vendor Query Reply",
        # Add other sources and subjects here
    }
    msg["Subject"] = subject_map.get(source, "Welcome")  # Default subject

    # Attach both plain text and HTML versions
    text_part = MIMEText(plain_text_content, "plain")
    html_part = MIMEText(html_content, "html")
    msg.attach(text_part)
    msg.attach(html_part)

    # Send the email
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(from_email, from_password)

        text = msg.as_string()
        server.sendmail(from_email, to_email, text)

        server.quit()
        logger.info(f"Email sent successfully to {to_email}.")
        return {"status": "SUCCESS", "message": "Email sent successfully."}
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
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
