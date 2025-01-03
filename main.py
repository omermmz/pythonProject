from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
import random
import redis
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import uvicorn
import os
from fastapi.middleware.cors import CORSMiddleware
# .env dosyasını yükleme
load_dotenv()

# FastAPI uygulaması
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # İzin verilen kaynaklar
    allow_credentials=True,
    allow_methods=["*"],  # İzin verilen HTTP yöntemleri
    allow_headers=["*"],  # İzin verilen başlıklar
)

# Redis bağlantısı
redis_client = redis.StrictRedis(
    host=os.getenv("REDIS_HOST"),
    port=os.getenv("REDIS_PORT"),
    db=int(os.getenv("REDIS_DB"))
)

# E-posta Ayarları
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT"))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# OTP Geçerlilik Süresi
OTP_VALIDITY_PERIOD = int(os.getenv("OTP_VALIDITY_PERIOD"))

PASSWORD_FILE = "email_passwords.txt"

# Pydantic Modeller
class EmailRequest(BaseModel):
    email: EmailStr
    password: str


class OTPValidationRequest(BaseModel):
    email: EmailStr
    otp: str
    password: str


# OTP oluşturma
def generate_otp():
    return str(random.randint(100000, 999999))


# E-posta ile OTP gönderme
def send_email(email: str, otp: str):
    try:
        validity_minutes = OTP_VALIDITY_PERIOD // 60

        with open("otp_email_template.html", "r", encoding="utf-8") as file:
            html_template = file.read()

        email_content = html_template.replace("{{otp}}", otp).replace("{{validity}}", str(validity_minutes))

        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

        msg = MIMEText(email_content, "html")
        msg["Subject"] = "Your OTP Code"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = email

        server.sendmail(EMAIL_ADDRESS, email, msg.as_string())
        server.quit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

# E-posta ve şifreyi dosyaya kaydetme
def save_email_password_to_file(email: str, password: str):
    # Eğer aynı e-posta varsa, şifreyi güncelle
    lines = []
    found = False
    with open(PASSWORD_FILE, "r") as file:
        lines = file.readlines()

    with open(PASSWORD_FILE, "w") as file:
        for line in lines:
            stored_email, stored_password = line.strip().split(":")
            if stored_email == email:
                # E-posta bulundu, şifreyi güncelle
                file.write(f"{email}:{password}\n")
                found = True
            else:
                file.write(line)

        if not found:
            # Eğer e-posta bulunamazsa yeni bir satır ekle
            file.write(f"{email}:{password}\n")

def check_email_password_in_file(email: str, password: str):
    with open(PASSWORD_FILE, "r") as file:
        for line in file:
            stored_email, stored_password = line.strip().split(":")
            if stored_email == email and stored_password == password:
                return True
    return False


# OTP Generate Endpoint
@app.post("/generate-otp")
def generate_otp_endpoint(request: EmailRequest):
    print(request)
    otp = generate_otp()
    redis_key = f"otp:{request.email}"
    redis_client.setex(redis_key, OTP_VALIDITY_PERIOD, otp)

    save_email_password_to_file(request.email, request.password)

    try:
        send_email(request.email, otp)
        return {"message": "OTP has been sent to your email."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# OTP Validation Endpoint
@app.post("/validate-otp/")
def validate_otp_endpoint(request: OTPValidationRequest):
    redis_key = f"otp:{request.email}"
    stored_otp = redis_client.get(redis_key)

    if not check_email_password_in_file(request.email, request.password):
        raise HTTPException(status_code=400, detail="Invalid password or email.")

    if not stored_otp:
        raise HTTPException(status_code=404, detail="OTP not found or expired.")

    if stored_otp.decode("utf-8") == request.otp:
        redis_client.delete(redis_key)  # OTP doğrulandıktan sonra silinir
        return {"message": "OTP validated successfully."}
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP.")


if __name__ == "_main_":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)