import os
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec  
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import random
import smtplib
from email.message import EmailMessage
from twilio.rest import Client
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive

# Load or Generate ECDSA Keys
def load_or_generate_keys():
    if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    return private_key, public_key

private_key, public_key = load_or_generate_keys()

# ECDSA Digital Signature
def sign_data(data):
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(data, signature):
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"❌ Signature verification failed: {e}")
        return False

def authenticate_google_drive():
    gauth = GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)
    print("✅ Google Drive Authentication Successful.")
    return drive

# AES-GCM Encryption
def encrypt_file(file_path, key):
    iv = os.urandom(12)
    key = hashlib.sha256(key).digest()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    
    with open(file_path, "rb") as f:
        plaintext = f.read()
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

# AES-GCM Decryption
def decrypt_file(encrypted_data, key):
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    
    key = hashlib.sha256(key).digest()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        print("❌ Decryption failed! Invalid key or corrupted file.")
        exit()

# Generate OTP for 2FA
def generate_otp():
    return str(random.randint(100000, 999999))

# Send OTP via Twilio SMS
def send_otp_via_sms(phone_number, otp):
    twilio_account_sid = 'AC85b59a7a104d0d7dc7afdd680020cc85'
    twilio_auth_token = '4161f2f6aa7b6608f423b6f93062130a'
    twilio_phone_number = '+19788988972'

    client = Client(twilio_account_sid, twilio_auth_token)
    message = client.messages.create(
        body=f"Your OTP for file decryption is: {otp}",
        from_=twilio_phone_number,
        to=phone_number
    )
    print(f"✅ OTP sent to {phone_number}")

# Upload File to Google Drive
def upload_to_drive(drive, file_path):
    file_drive = drive.CreateFile({"title": os.path.basename(file_path)})
    file_drive.SetContentFile(file_path)
    file_drive.Upload()
    print(f"✅ Uploaded {file_path} to Google Drive")
    return file_drive["id"]

# Send Email with Encrypted File Links and Access Key
def send_email(sender_email, sender_password, receiver_emails, file_ids, access_key):
    msg = EmailMessage()
    msg["Subject"] = "Secure File Transfer"
    msg["From"] = sender_email
    msg["To"] = ", ".join(receiver_emails)
    msg.set_content(f"Your encrypted files have been uploaded to Google Drive.\n"
                    f"Download links: {', '.join([f'https://drive.google.com/file/d/{fid}/view' for fid in file_ids])}\n"
                    f"Access Key: {access_key.decode()}")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
            print(f"✅ Email sent to {', '.join(receiver_emails)}")
    except Exception as e:
        print(f"❌ Error sending email: {e}")

# Secure Upload
def upload_secure_file(drive, file_path):
    sender_email = input("Enter your Gmail address (used for Drive and email): ").strip()
    sender_password = input("Enter your Gmail App Password (not your regular password): ").strip()

    additional_emails = input("Enter recipient emails (comma-separated): ").split(",")
    additional_phone_numbers = input("Enter recipient phone numbers (comma-separated): ").split(",")
    access_key = input("Enter a 4-digit secure key: ").encode()
    
    encrypted_data = encrypt_file(file_path, access_key)
    signature = sign_data(encrypted_data)
    
    enc_file_path = file_path + ".enc"
    sig_file_path = file_path + ".sig"
    with open(enc_file_path, "wb") as f:
        f.write(encrypted_data)
    with open(sig_file_path, "wb") as f:
        f.write(signature)
    
    file_ids = [upload_to_drive(drive, enc_file_path), upload_to_drive(drive, sig_file_path)]
    otp = generate_otp()
    
    for phone_number in additional_phone_numbers:
        send_otp_via_sms(phone_number.strip(), otp)
    
    send_email(sender_email, sender_password, additional_emails, file_ids, access_key)
    
    print(f"✅ File '{file_path}' encrypted and uploaded!")

# Secure Decryption
def decrypt_secure_file():
    file_path = input("Enter the encrypted file path: ").strip()
    access_key = input("Enter the access key: ").encode()
    otp = input("Enter the OTP sent to your phone: ")
    
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    
    with open(file_path.replace(".enc", ".sig"), "rb") as f:
        signature = f.read()
    
    if verify_signature(encrypted_data, signature):
        print("✅ File integrity verified.")
        decrypted_data = decrypt_file(encrypted_data, access_key)
        with open(file_path.replace(".enc", ""), "wb") as f:
            f.write(decrypted_data)
        print(f"✅ File decrypted successfully: {file_path.replace('.enc', '')}")
    else:
        print("❌ File integrity verification failed!")

# Main
if __name__ == "__main__":
    print("Select an option:")
    print("1. Upload a file")
    print("2. Decrypt a file")
    choice = input("Enter your choice (1/2): ")
    
    if choice == "1":
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(title="Select a file to upload").strip('"')
        if not os.path.isfile(file_path):
            print("❌ Error: File not found! Please enter a valid file path.")
            exit()
        drive = authenticate_google_drive()
        upload_secure_file(drive, file_path)
    elif choice == "2":
        decrypt_secure_file()
