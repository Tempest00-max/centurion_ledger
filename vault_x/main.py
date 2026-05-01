# Force Sync Update: v2.2 (Security Hardened)
import os
import io
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import encrypt_file, decrypt_file

# --- RATE LIMITING IMPORTS ---
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Initialize Limiter
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TextRequest(BaseModel):
    text: str
    password: str
    mode: str 

@app.get("/")
async def root():
    return {"status": "VAULT-X2 ONLINE", "mode": "HYBRID_GATEWAY_ACTIVE", "protection": "RATE_LIMIT_ENABLED"}

@app.post("/process-file")
@limiter.limit("5/minute")
async def process_file(request: Request, file: UploadFile = File(...), password: str = Form(...), action: str = Form(...)):
    try:
        content = await file.read()
        if action == "encrypt":
            result = encrypt_file(content, password)
            out_name = f"{file.filename}.vx2"
        else:
            result = decrypt_file(content, password)
            out_name = file.filename.replace(".vx2", "")
        return StreamingResponse(io.BytesIO(result), media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename={out_name}"})
    except Exception:
        raise HTTPException(status_code=401, detail="AUTHENTICATION_FAILED")

@app.post("/process-text")
@limiter.limit("5/minute")
async def process_text(request: Request, text_req: TextRequest):
    try:
        data = text_req.text.encode()
        if text_req.mode == "encrypt":
            result = encrypt_file(data, text_req.password)
            return {"result": result.hex()}
        else:
            encrypted_data = bytes.fromhex(text_req.text)
            result = decrypt_file(encrypted_data, text_req.password)
            return {"result": result.decode()}
    except Exception:
        raise HTTPException(status_code=400, detail="TRANSCODE_ERROR")