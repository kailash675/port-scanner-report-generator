import os
import smtplib

from email.message import EmailMessage
from dotenv import load_dotenv


# Load .env file
load_dotenv()


def send_report_email(receiver_email, pdf_path):

    # Sender Gmail
    sender_email = os.getenv("REPORT_EMAIL")

    # Gmail App Password
    sender_password = os.getenv("REPORT_EMAIL_PASSWORD")

    # SMTP settings
    smtp_server = os.getenv(
        "SMTP_SERVER",
        "smtp.gmail.com"
    )

    smtp_port = int(
        os.getenv(
            "SMTP_PORT",
            "587"
        )
    )


    # Check sender email
    if not sender_email:

        raise ValueError(
            "Sender Gmail is not configured. "
            "Please set REPORT_EMAIL in .env"
        )


    # Check app password
    if not sender_password:

        raise ValueError(
            "Gmail App Password is not configured. "
            "Please set REPORT_EMAIL_PASSWORD in .env"
        )


    # Check receiver
    if not receiver_email:

        raise ValueError(
            "Receiver email address is required"
        )


    # Check PDF
    if not os.path.exists(pdf_path):

        raise FileNotFoundError(
            f"PDF report not found: {pdf_path}"
        )


    # Create email
    message = EmailMessage()


    message["Subject"] = (
        "SecureScan - Network Security Report"
    )

    message["From"] = sender_email

    message["To"] = receiver_email


    # Email body
    message.set_content(
        """Hello,

Please find the SecureScan Network Security Report attached.

This report contains:

- Network scan results
- Open ports
- Detected services
- CVE information
- Security recommendations
- Scan duration

Regards,
SecureScan
Network Security Assessment Tool
"""
    )


    # Attach PDF
    with open(
        pdf_path,
        "rb"
    ) as pdf_file:

        pdf_data = pdf_file.read()


    message.add_attachment(
        pdf_data,
        maintype="application",
        subtype="pdf",
        filename=os.path.basename(
            pdf_path
        )
    )


    # Connect to Gmail SMTP
    try:

        with smtplib.SMTP(
            smtp_server,
            smtp_port
        ) as server:

            server.ehlo()

            server.starttls()

            server.ehlo()

            server.login(
                sender_email,
                sender_password
            )

            server.send_message(
                message
            )


    except smtplib.SMTPAuthenticationError:

        raise ValueError(
            "Gmail authentication failed. "
            "Check REPORT_EMAIL and use a Gmail App Password."
        )


    except smtplib.SMTPException as error:

        raise RuntimeError(
            f"Email sending failed: {error}"
        )


    return True