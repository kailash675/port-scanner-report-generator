import os
import smtplib

from email.message import EmailMessage


def send_report_email(
    receiver_email,
    pdf_path
):

    sender_email = os.getenv(
        "REPORT_EMAIL"
    )

    sender_password = os.getenv(
        "REPORT_EMAIL_PASSWORD"
    )

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


    if not sender_email:
        raise ValueError(
            "REPORT_EMAIL is not configured"
        )


    if not sender_password:
        raise ValueError(
            "REPORT_EMAIL_PASSWORD is not configured"
        )


    if not os.path.exists(pdf_path):
        raise FileNotFoundError(
            "PDF report not found"
        )


    message = EmailMessage()

    message["Subject"] = (
        "Port Scanner Security Report"
    )

    message["From"] = sender_email

    message["To"] = receiver_email

    message.set_content(
        """
Hello,

Please find the Port Scanner Security Report attached.

This report contains the scan results,
open ports, detected services,
CVE information and security recommendations.

Regards,
Port Scanner Report Generator
"""
    )


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


    with smtplib.SMTP(
        smtp_server,
        smtp_port
    ) as server:

        server.starttls()

        server.login(
            sender_email,
            sender_password
        )

        server.send_message(
            message
        )


    return True