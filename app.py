import os
import re
import olefile
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, render_template, redirect, url_for
from flask_pymongo import PyMongo
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import struct
import zlib

load_dotenv()  # 환경변수 로드

app = Flask(__name__)

# 파일 업로드 설정
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'hwp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 데이터베이스 설정
app.config['MONGO_URI'] = 'mongodb://localhost:27017/mydatabase'  # MongoDB URI
mongo = PyMongo(app)  # PyMongo 객체 초기화

# 민감정보 정규식 패턴
SENSITIVE_PATTERNS = {
    '주민등록번호': r'\b\d{6}-\d{7}\b',
    '전화번호': r'\b01[0-9]-\d{3,4}-\d{4}\b',
    '이메일': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
}

# 허용 확장자 확인
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# HWP 파일 텍스트 추출
def get_hwp_text(filename):
    try:
        f = olefile.OleFileIO(filename)
        dirs = f.listdir()

        # HWP 파일 검증
        if ["FileHeader"] not in dirs or ["\x05HwpSummaryInformation"] not in dirs:
            raise Exception("Not Valid HWP.")

        # 문서 포맷 압축 여부 확인
        header = f.openstream("FileHeader")
        header_data = header.read()
        is_compressed = (header_data[36] & 1) == 1

        # BodyText 섹션 경로 수집
        nums = [int(d[1][len("Section"):]) for d in dirs if d[0] == "BodyText"]
        sections = ["BodyText/Section" + str(x) for x in sorted(nums)]

        # 전체 텍스트 추출
        text = ""

        for section in sections:
            bodytext = f.openstream(section)
            data = bodytext.read()
            if is_compressed:
                try:
                    unpacked_data = zlib.decompress(data, -15)
                except Exception as e:
                    print(f"[압축 해제 오류] {e}")
                    continue
            else:
                unpacked_data = data

            section_text = ""
            i = 0
            size = len(unpacked_data)

            while i < size:
                try:
                    header = struct.unpack_from("<I", unpacked_data, i)[0]
                    rec_type = header & 0x3ff
                    rec_len = (header >> 20) & 0xfff
                except:
                    break  # 데이터 끝에 도달하거나 깨졌을 경우

                if rec_type == 67:  # 문단 텍스트
                    rec_data = unpacked_data[i+4:i+4+rec_len]
                    try:
                        section_text += rec_data.decode('utf-16')
                    except:
                        pass
                    section_text += "\n"

                i += 4 + rec_len

            text += section_text
            text += "\n"

        return text

    except Exception as e:
        print("Error extracting text:", e)
        return ""

# 민감정보 검사
def detect_sensitive_info(text):
    detected = {}
    for label, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            detected[label] = matches
    return detected

# 이메일 전송 함수
def send_alert_email(filename, detected_info):
    sender_email = os.getenv("sender_email")  # 발신자 이메일
    sender_password = os.getenv("sender_password")  # 발신자 이메일 비밀번호
    recipient_email = "dksguddn15@gmail.com"  # 담당자 이메일
    
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

# 업로드 및 분석 처리
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "파일이 없습니다", 400

        file = request.files['file']
        if file.filename == '':
            return "파일을 선택하세요", 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            print(f"File saved to {filepath}")

            # 텍스트 추출 및 분석
            extracted_text = get_hwp_text(filepath)
            detected_info = detect_sensitive_info(extracted_text)

            # 결과 저장 (MongoDB에 저장)
            detected_info_str = str(detected_info) if detected_info else "민감정보 없음"
            scan_result = {
                "filename": filename,
                "detected_info": detected_info_str
            }
            mongo.db.sensitive_results.insert_one(scan_result)  # MongoDB에 결과 저장
            print("데이터 저장 완료")

            # 민감정보 포함 시 이메일 전송
            if detected_info:
                send_alert_email(filename, detected_info)

            return redirect(url_for('result'))

    return render_template('upload.html')

# 검사 결과 페이지
@app.route('/result')
def result():
    results = list(mongo.db.sensitive_results.find())  # MongoDB에서 데이터 가져오기
    print("Results:", results)  # 데이터를 확인하는 로그
    return render_template('result.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
