import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os

def send_alert_email(filename, detected_info):
    sender_email = os.getenv("your_email@gmail.com") # 발신자 이메일
    sender_password = os.getenv("your_password") # 발신자 이메일 비밀번호
    recipient_email = "admin@example.com"  # 담당자 이메일
    
    smtp_name = "smtp.naver.com" 
    smtp_port = 587   
    
    subject = f"민감정보 포함 파일 업로드됨: {filename}"
    body = f"파일 '{filename}'에서 다음과 같은 민감정보가 탐지되었습니다:\n\n"
    for label, matches in detected_info.items():
        body += f"{label}: {', '.join(matches)}\n"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email
    
    try:
        server = smtplib.SMTP(smtp_name, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        print("이메일 전송 성공!")
    except Exception as e:
        print("이메일 전송 실패:", e)