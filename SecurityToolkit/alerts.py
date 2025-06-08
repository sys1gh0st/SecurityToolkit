import smtplib
from dotenv import load_dotenv
import os 
from email.mime.text import MIMEText # Create a simple plain-text email
import time
from datetime import datetime

class alerts:
    def __init__(self):
        # Configure email credentials
        load_dotenv()
        self.__email_address = os.getenv("GMAIL_ADDRESS") #Sender's email address
        self.__email_password = os.getenv("GMAIL_APP_PASSWORD")  # App password
        self.__recipients = [os.getenv("ALERT_RECIPIENT")]  # Recipient list
        
        # Test connection on initialization
        # Attempts to establish SMTP connection when alert system is initialized
        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=5) as test_smtp:
                test_smtp.login(self.__email_address, self.__email_password.replace(" ", ""))
            print("Alert system connected to Gmail SMTP")
        except Exception as e:
            print(f"SMTP connection test failed: {str(e)}")
            raise RuntimeError("Failed to initialize alert system")

    def generate_alert(self, subject, message):
        """Send security alerts via email
        
        Args:
            subject: Brief description of the alert
            message: Detailed alert content
            
        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        try:
            # Create email message
            # Formats the message with proper headers for SMTP
            msg = MIMEText(message)
            msg['Subject'] = f"SECURITY ALERT: {subject}"  # Prepends standard prefix
            msg['From'] = self.__email_address
            msg['To'] = ", ".join(self.__recipients)  # Converts list to comma-separated string
            
            # Send email
            # Establishes secure connection and sends the message
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as smtp:
                smtp.login(self.__email_address, self.__email_password.replace(" ", ""))
                smtp.send_message(msg)
                print(f"Alert sent: {subject}")
                return True
                
        except smtplib.SMTPAuthenticationError:
            # Handles authentication failures specifically
            print("Failed to authenticate with Gmail. Check your app password.")
            return False
        except Exception as e:
            # General error handling for other SMTP issues
            print(f"Error sending alert: {str(e)}")
            return False

# References: [21], [22], [23]