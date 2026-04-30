import os
import io
import time
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from security import encrypt_file, decrypt_file

app = FastAPI()

# --- CORS CONFIGURATION ---
# allow_origins=["*"] ensures your GitHub Pages site isn't blocked by the browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"],
)

# Basic Rate Limiting Logic
request_history = {}

@app.post("/process-file")
async def process_file(
    file: UploadFile = File(...), 
    password: str = Form(...), 
    mode: str = Form(...)
):
    # Rate Limiting: 1 request every 2 seconds per global instance
    client_ip = "global_user" 
    now = time.time()
    if client_ip in request_history and now - request_history[client_ip] < 2:
        raise HTTPException(status_code=429, detail="RATE_LIMIT_EXCEEDED")
    request_history[client_ip] = now

    try:
        content = await file.read()
        
        if mode == "encrypt":
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
        # Generic error to prevent side-channel leaks
        raise HTTPException(status_code=401, detail="AUTHENTICATION_FAILED")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))