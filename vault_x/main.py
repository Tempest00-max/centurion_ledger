# Vault-X2 Hybrid Engine v2.3 - Security Hardened
# Location: vault_x/main.py

import os
import io
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import encrypt_file, decrypt_file

# Rate Limiting Components
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Initialize Limiter using the remote IP address as the key
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter

# Custom Exception Handler to prevent server crashes on rate limit triggers
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Security Alert: Too many requests. Gateway throttled."}
    )

# Security: Permissive CORS for GitHub Pages frontend
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
    return {
        "status": "VAULT-X2 ONLINE", 
        "mode": "HYBRID_GATEWAY_ACTIVE",
        "protection": "RATE_LIMIT_ENABLED_V2.3"
    }

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
        
        return StreamingResponse(
            io.BytesIO(result), 
            media_type="application/octet-stream", 
            headers={"Content-Disposition": f"attachment; filename={out_name}"}
        )
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
            # Decrypting from hex string back to readable text
            encrypted_data = bytes.fromhex(text_req.text)
            result = decrypt_file(encrypted_data, text_req.password)
            return {"result": result.decode()}
    except Exception:
        raise HTTPException(status_code=400, detail="TRANSCODE_ERROR")

if __name__ == "__main__":
    import uvicorn
    # Port configuration for Render deployment
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))