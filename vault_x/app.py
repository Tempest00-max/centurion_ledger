from flask import Flask, request, send_file
from flask_cors import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import io

app = Flask(__name__)
# Enable CORS so your GitHub-hosted frontend can talk to your local WSL server
CORS(app) 

def derive_key(password: str):
    """
    Standardizes any password into a secure 32-byte key for Fernet.
    The salt must remain constant for decryption to work.
    """
    salt = b'vault_x2_production_salt_2026' 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    try:
        file = request.files['file']
        password = request.form['key']
        
        # 1. Derive key from password
        secret_key = derive_key(password)
        f = Fernet(secret_key)
        
        # 2. Encrypt the file stream
        encrypted_data = f.encrypt(file.read())
        
        # 3. Return as a downloadable .vault file
        return send_file(
            io.BytesIO(encrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f"{file.filename}.vault"
        )
    except Exception as e:
        return f"ENCRYPTION_ERROR: {str(e)}", 400

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    try:
        file = request.files['file']
        password = request.form['key']
        
        # 1. Derive the exact same key
        secret_key = derive_key(password)
        f = Fernet(secret_key)
        
        # 2. Decrypt the binary stream
        decrypted_data = f.decrypt(file.read())
        
        # 3. Restore original filename (remove .vault)
        original_name = file.filename.replace('.vault', '')
        
        return send_file(
            io.BytesIO(decrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=original_name
        )
    except Exception:
        # Triggered if password is wrong or data is tampered with
        return "DECRYPTION_FAILED: Invalid Key or Corrupt Data", 400

if __name__ == '__main__':
    # Server runs on localhost:5000
    app.run(port=5000, debug=True)