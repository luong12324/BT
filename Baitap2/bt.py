import os
from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from werkzeug.utils import secure_filename
import io

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def pad_key(key):
    key = key.encode('utf-8')
    if len(key) < 32:
        key += b'0' * (32 - len(key))  # Bổ sung ký tự 0 nếu khoá ngắn hơn 32 byte
    return key[:32]  # Cắt nếu dài hơn

def pad_data(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad_data(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_file(file_data, key):
    key = pad_key(key)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(pad_data(file_data))
    return encrypted_data

def decrypt_file(file_data, key):
    key = pad_key(key)
    iv = file_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(file_data[16:])
    return unpad_data(decrypted)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_file():
    uploaded_file = request.files['file']
    key = request.form['key']
    action = request.form['action']

    if uploaded_file.filename == '':
        return "Vui lòng chọn file."

    filename = secure_filename(uploaded_file.filename)
    file_data = uploaded_file.read()

    try:
        if action == 'encrypt':
            result = encrypt_file(file_data, key)
            out_filename = filename + '.enc'
        elif action == 'decrypt':
            result = decrypt_file(file_data, key)
            out_filename = filename.replace('.enc', '.dec')
        else:
            return "Hành động không hợp lệ."
    except Exception as e:
        return f"Lỗi xử lý: {str(e)}"

    return send_file(
        io.BytesIO(result),
        download_name=out_filename,
        as_attachment=True
    )

if __name__ == '__main__':
    app.run(debug=True)
