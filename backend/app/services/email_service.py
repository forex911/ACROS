import os
import resend
from app.core.logger import get_logger
logger = get_logger(__name__)

# Initialize resend with API key from environment
resend.api_key = os.environ.get("RESEND_API_KEY", "")

def send_otp_email(to_email: str, otp_code: str) -> bool:
    """Send a 6-digit OTP email using Resend."""
    
    # If no API key is configured, log and skip (for local dev without key)
    if not resend.api_key:
        logger.warning(f"RESEND_API_KEY not set. Would have sent OTP {otp_code} to {to_email}")
        return False
        
    from_email = os.environ.get("RESEND_FROM_EMAIL", "onboarding@resend.dev")
    from_name = os.environ.get("RESEND_FROM_NAME", "ACROS")
    
    html_content = f"""
    <div style="background-color:#000000;color:#ffffff;font-family:'Courier New',Courier,monospace;max-width:600px;margin:0 auto;border:1px solid #333333;padding:40px;">
      <div style="text-align:center;border-bottom:1px solid #222222;padding-bottom:20px;margin-bottom:30px;">
        <h1 style="margin:0;font-size:28px;font-weight:900;letter-spacing:4px;">{from_name}</h1>
        <p style="margin:8px 0 0 0;font-size:11px;color:#888888;letter-spacing:2px;">AUTHORIZATION PROTOCOL</p>
      </div>
      <p style="font-size:14px;color:#cccccc;">OPERATOR,</p>
      <p style="font-size:14px;color:#cccccc;">Use the following verification code to confirm your account:</p>
      <div style="background-color:#111111;border:1px solid #ffffff;padding:25px;text-align:center;margin:35px 0;">
        <h2 style="margin:0;font-size:42px;font-weight:bold;letter-spacing:12px;color:#ffffff;">{otp_code}</h2>
      </div>
      <div style="border-left:2px solid #ff4444;padding-left:15px;margin-top:35px;">
        <p style="font-size:12px;color:#888888;margin:0 0 5px 0;text-transform:uppercase;font-weight:bold;">Security Notice</p>
        <p style="font-size:12px;color:#666666;margin:0;">This code expires in 5 minutes. If you did not request this, ignore it.</p>
      </div>
      <div style="margin-top:40px;padding-top:20px;border-top:1px solid #222222;text-align:center;">
        <p style="font-size:10px;color:#444444;letter-spacing:1px;">SECURE TRANSMISSION &mdash; {from_name} AUTOMATED SYSTEM</p>
      </div>
    </div>
    """
    
    try:
        response = resend.Emails.send({
            "from": f"{from_name} <{from_email}>",
            "to": to_email,
            "subject": f"[{from_name}] Security Clearance Verification Code",
            "html": html_content
        })
        logger.info(f"OTP email sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email: {str(e)}")
        return False
