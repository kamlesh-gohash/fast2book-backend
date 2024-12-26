# app/v1/utils/email.py

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import random
from pathlib import Path


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

async def send_email(to_email: str, otp: str):
    """Send OTP to user's email using HTML template."""
    from_email = os.getenv('EMAIL_USER')
    from_password = os.getenv('EMAIL_PASSWORD')

    project_root = Path(__file__).resolve().parent.parent.parent
    template_path = project_root / 'templates' / 'email' / 'forgot_password.html'
    
    # Verify if template exists
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found at: {template_path}")
    with open(template_path, 'r', encoding='utf-8') as file:
        html_template = file.read()
    
    # Replace placeholder with actual OTP
    html_content = html_template.format(otp=otp)

    # Set up the email
    msg = MIMEMultipart('alternative')
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = "Your OTP Code"

    # Attach both plain text and HTML versions
    text_part = MIMEText(f"Your OTP code is {otp}. Please use it within the next 10 minutes.", 'plain')
    html_part = MIMEText(html_content, 'html')
    
    msg.attach(text_part)
    msg.attach(html_part)

    # Send the email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, from_password)
        
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send OTP to {to_email}: {e}")
        return False