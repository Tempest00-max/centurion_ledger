import os
import io
import time
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import encrypt_file, decrypt_file

app = FastAPI()

# --- CORS CONFIGURATION ---
# Open for all origins to ensure stable connection with GitHub Pages
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"],
)

# Text Request Model for JSON processing
class TextRequest(BaseModel):
    text: str
    password: str
    mode: str  # 'encrypt' or 'decrypt'

# --- FILE PROCESSING ENDPOINT ---
@app.post("/process-file")
async def process_file(
    file: UploadFile = File(...), 
    password: str = Form(...), 
    action: str = Form(...) # Form field expected by frontend
):
    try:
        content = await file.read()
        if action == "encrypt":
            result = encrypt_file(content, password)
            out_name = f"{file.filename}.vx2"
        else:
            result = decrypt_file(content, password)
            out_name = file.filename.replace(".vx2", "")

        return StreamingResponse(
            io.BytesIO(result),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={out_name}"}
        )
    except Exception:
        raise HTTPException(status_code=401, detail="AUTHENTICATION_FAILED")

# --- TEXT PROCESSING ENDPOINT ---
@app.post("/process-text")
async def process_text(request: TextRequest):
    try:
        data = request.text.encode()
        if request.mode == "encrypt":
            # Encrypt and return as hex string for easy sharing
            result = encrypt_file(data, request.password)
            return {"result": result.hex()}
        else:
            # Decrypt from hex string back to original text
            encrypted_data = bytes.fromhex(request.text)
            result = decrypt_file(encrypted_data, request.password)
            return {"result": result.decode()}
    except Exception:
        raise HTTPException(status_code=401, detail="INVALID_KEY_OR_DATA")

if __name__ == "__main__":
    import uvicorn
    # Bind to the PORT environment variable provided by Render
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))