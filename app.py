from flask import Flask, request, send_file
from flask_cors import CORS
from cryptography.fernet import Fernet
import io

app = Flask(__name__)
CORS(app) # Allows your GitHub page to talk to your local computer

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    file = request.files['file']
    key = request.form['key'] # You'll need to derive a 32-byte key here
    
    # Simple encryption logic for testing
    f = Fernet(Fernet.generate_key()) 
    encrypted_data = f.encrypt(file.read())
    
    return send_file(
        io.BytesIO(encrypted_data),
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=f"{file.filename}.vault"
    )

if __name__ == '__main__':
    app.run(port=5000)