# Force Sync Update: 2026-05-01 (Hybrid Gateway v2.1)
import os
import io
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import encrypt_file, decrypt_file

app = FastAPI()

# Permissive CORS for GitHub Pages
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
    # This message confirms the backend is ready for text encryption
    return {"status": "VAULT-X2 ONLINE", "mode": "HYBRID_GATEWAY_ACTIVE"}

@app.post("/process-file")
async def process_file(file: UploadFile = File(...), password: str = Form(...), action: str = Form(...)):
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
async def process_text(request: TextRequest):
    try:
        data = request.text.encode()
        if request.mode == "encrypt":
            result = encrypt_file(data, request.password)
            return {"result": result.hex()}
        else:
            # Decrypting from hex string back to readable text
            encrypted_data = bytes.fromhex(request.text)
            result = decrypt_file(encrypted_data, request.password)
            return {"result": result.decode()}
    except Exception:
        raise HTTPException(status_code=400, detail="TRANSCODE_ERROR: Verify hex format or key")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))