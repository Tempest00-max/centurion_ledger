import uuid, os, io, re, logging, traceback, asyncio, threading
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, Query, Request, Header
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import Response, JSONResponse
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from sqlalchemy.orm import Session
from sqlalchemy import or_, cast, String
from sqlalchemy.orm import joinedload
from jose import jwt, JWTError
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from . import models, schemas, database, auth

load_dotenv()

# ============================================
# LOGGING - Sanitize sensitive data
# ============================================

class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        if isinstance(record.msg, str):
            record.msg = re.sub(r'pin=[^&\s]+', 'pin=***', record.msg, flags=re.IGNORECASE)
            record.msg = re.sub(r'password=[^&\s]+', 'password=***', record.msg, flags=re.IGNORECASE)
            record.msg = re.sub(r'token=[^&\s]+', 'token=***', record.msg, flags=re.IGNORECASE)
        return True

logging.getLogger("uvicorn.access").addFilter(SensitiveDataFilter())

# ============================================
# FASTAPI APP CONFIGURATION
# ============================================

app = FastAPI(title="CENTURION Tactical Ledger", version="2.0.0")

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers middleware
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'"
    )
    return response

# Email configuration
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME", ""),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD", ""),
    MAIL_FROM=os.getenv("MAIL_FROM", ""),
    MAIL_PORT=int(os.getenv("MAIL_PORT", "587")),
    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_FROM_NAME="CENTURION Vault",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

mailer = FastMail(conf)

# CORS - Production domains should be configured
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS],
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
    allow_credentials=True,
    max_age=3600
)

# OAuth2 scheme - auto_error=False to allow cookie fallback
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# ============================================
# DATABASE DEPENDENCY
# ============================================

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============================================
# AUTHENTICATION - FIXED UUID HANDLING
# ============================================

async def get_current_user(
    request: Request, 
    token: Optional[str] = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
):
    """
    Unified auth: checks Bearer header first, falls back to httpOnly cookie.
    ALL user IDs are handled as strings to prevent UUID type mismatches.
    """
    # Priority 1: Bearer token from header
    if not token:
        # Priority 2: Cookie fallback
        token = request.cookies.get("access_token")
    
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        payload = jwt.decode(
            token, 
            auth.SECRET_KEY, 
            algorithms=[auth.ALGORITHM],
            options={"leeway": 60}
        )
        user_id = str(payload.get("sub")) if payload.get("sub") else None
        
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        # CRITICAL FIX: Query using cast to String to handle UUID columns
        user = db.query(models.Account).filter(
            cast(models.Account.id, String) == user_id
        ).first()
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return user
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication failed")

# ============================================
# VALIDATION HELPERS
# ============================================

def validate_target(t: str):
    """Validate transfer target is email or UUID. Returns normalized string."""
    if not t or not isinstance(t, str):
        raise HTTPException(status_code=400, detail="Target is required")
    
    t = t.strip()
    
    # Email check
    if re.match(r'^[\w.-]+@[\w.-]+\.\w+$', t):
        return "email", t.lower()
    
    # UUID check
    try:
        uuid.UUID(t)
        return "uuid", str(uuid.UUID(t))  # Normalize format
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid target format. Use email or Vault ID.")

def log_audit(db: Session, user_id, action: str, details: dict, request: Request):
    """Log all financial actions for compliance. Safe against null values."""
    try:
        audit = models.AuditLog(
            user_id=user_id,
            action=action,
            details=details or {},
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", "unknown")
        )
        db.add(audit)
        db.commit()
    except Exception as e:
        # Audit failure should not break the main transaction
        db.rollback()
        logging.error(f"Audit log failed: {e}")

# ============================================
# EMAIL HELPERS - FIXED: Run async email in background thread with new event loop
# ============================================

def _run_email_async(coro):
    """
    Run an async coroutine in a background thread by creating a new event loop.
    This is the ONLY reliable way to use fastapi-mail (async-only) inside FastAPI BackgroundTasks (sync-only).
    """
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(coro)
        loop.close()
    except Exception as e:
        logging.error(f"Email sending failed: {e}")
    finally:
        try:
            loop.close()
        except:
            pass


def send_credit_email_sync(receiver_email: str, amount: float, currency: str, sender_name: str):
    """Synchronous wrapper for sending credit email."""
    async def _send():
        try:
            await mailer.send_message(MessageSchema(
                subject="CENTURION: Vault Credit",
                recipients=[receiver_email],
                body=f"Tactical Notice: {amount} {currency} has been moved to your vault by {sender_name}.",
                subtype=MessageType.plain
            ))
            logging.info(f"Credit email sent to {receiver_email}")
        except Exception as e:
            logging.error(f"Credit email failed: {e}")
    
    _run_email_async(_send())


def send_debit_email_sync(sender_email: str, amount: float, currency: str, receiver_name: str, receiver_email: str, tx_id: str):
    """Synchronous wrapper for sending debit email."""
    async def _send():
        try:
            await mailer.send_message(MessageSchema(
                subject="CENTURION: Vault Debit",
                recipients=[sender_email],
                body=f"Tactical Notice: You sent {amount} {currency} to {receiver_name} ({receiver_email}). TX ID: {tx_id[:8]}.",
                subtype=MessageType.plain
            ))
            logging.info(f"Debit email sent to {sender_email}")
        except Exception as e:
            logging.error(f"Debit email failed: {e}")
    
    _run_email_async(_send())


def schedule_emails(bg: BackgroundTasks, receiver_email: str, sender_email: str, sender_name: str, 
                   receiver_name: str, amount: float, currency: str, tx_id: str):
    """
    Schedule email notifications using FastAPI BackgroundTasks.
    BackgroundTasks runs sync functions in a thread pool, so we use sync wrappers
    that each create their own event loop to run the async fastapi-mail coroutines.
    """
    bg.add_task(send_credit_email_sync, receiver_email, amount, currency, sender_name)
    bg.add_task(send_debit_email_sync, sender_email, amount, currency, receiver_name, receiver_email, tx_id)

# ============================================
# HEALTH CHECK
# ============================================

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }

# ============================================
# AUTH ENDPOINTS
# ============================================

@app.post("/signup")
@limiter.limit("5/minute")
async def signup(
    request: Request, 
    request_data: schemas.AccountBase, 
    password: str = Query(...), 
    pin: str = Query(...), 
    db: Session = Depends(get_db)
):
    """Create new account with validation."""
    # PIN validation
    if not pin or len(pin) != 6 or not pin.isdigit():
        raise HTTPException(status_code=400, detail="PIN must be exactly 6 digits")
    
    # Password validation
    if not password or len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    
    # Check existing credentials
    existing = db.query(models.Account).filter(
        or_(
            models.Account.username == request_data.username,
            models.Account.email == request_data.email
        )
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    # Create account with default balance in NGN (base currency)
    new_user = models.Account(
        owner_name=request_data.owner_name,
        username=request_data.username,
        email=request_data.email.lower(),
        hashed_password=auth.get_password_hash(password),
        pin_hash=auth.get_pin_hash(pin),
        balance=Decimal('1562500000.00'),  # ~1M EUR in NGN
        currency='NGN'
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {
        "status": "SUCCESS", 
        "id": str(new_user.id),
        "message": "Account created successfully"
    }

@app.post("/token")
@limiter.limit("10/minute")
async def login(
    request: Request, 
    response: Response, 
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db)
):
    """Authenticate user and set httpOnly cookie."""
    # Clear any existing cookie first
    response.delete_cookie("access_token")
    
    # Find user by email (username field in OAuth2 form)
    user = db.query(models.Account).filter(
        models.Account.email == form_data.username.lower()
    ).first()
    
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Generate token
    token = auth.create_access_token(data={"sub": str(user.id)})
    
    # Set httpOnly cookie (secure=True for HTTPS production)
    is_production = os.getenv("ENVIRONMENT", "development") == "production"
    
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=is_production,
        samesite="lax",
        max_age=3600,  # 60 minutes
        path="/"
    )
    
    return {
        "access_token": token, 
        "token_type": "bearer",
        "expires_in": 3600
    }

@app.post("/logout")
@limiter.limit("20/minute")
async def logout(request: Request, response: Response):
    """Clear auth cookie."""
    response.delete_cookie("access_token", path="/")
    return {"status": "LOGGED_OUT"}

# ============================================
# TRANSFER - FIXED RACE CONDITIONS & UUID BUGS
# ============================================

@app.post("/transfer/")
@limiter.limit("10/minute")
async def transfer(
    request: Request,
    target: str = Query(...),
    amount: float = Query(..., gt=0, le=100_000_000),
    currency: str = Query("EUR"),
    pin: str = Header(..., alias="X-Pin"),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    bg: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
    user: models.Account = Depends(get_current_user)
):
    """
    Execute transfer with:
    - Idempotency protection
    - PIN lockout
    - Database row locking
    - Proper transaction rollback
    - Email notifications
    """
    
    # Validate amount precision (max 2 decimal places)
    if round(amount, 2) != amount:
        raise HTTPException(status_code=400, detail="Amount must have max 2 decimal places")
    
    # Validate currency
    valid_currencies = {"NGN", "USD", "EUR", "GBP"}
    currency = currency.upper()
    if currency not in valid_currencies:
        raise HTTPException(status_code=400, detail=f"Invalid currency. Use: {', '.join(valid_currencies)}")
    
    # Check idempotency
    if idempotency_key:
        existing = db.query(models.Transaction).filter(
            models.Transaction.idempotency_key == idempotency_key
        ).first()
        if existing:
            return {
                "status": "SUCCESS",
                "transaction_id": str(existing.id),
                "amount_sent": float(existing.amount),
                "currency": existing.currency,
                "message": "Duplicate request - returning existing transaction"
            }
    
    # Validate PIN format
    if not pin or len(pin) != 6 or not pin.isdigit():
        raise HTTPException(status_code=403, detail="PIN must be exactly 6 digits")
    
    # CRITICAL FIX: Re-fetch user WITH row lock in SAME transaction
    # This prevents race conditions and ensures fresh data
    locked_user = db.query(models.Account).filter(
        models.Account.id == user.id
    ).with_for_update().first()
    
    if not locked_user:
        raise HTTPException(status_code=401, detail="Session invalid")
    
    # Check account lockout
    if locked_user.locked_until and locked_user.locked_until > datetime.utcnow():
        raise HTTPException(
            status_code=403, 
            detail=f"Account locked until {locked_user.locked_until.isoformat()}"
        )
    
    # Verify PIN
    if not auth.verify_pin(pin, locked_user.pin_hash):
        # Increment failed attempts
        locked_user.failed_pin_attempts = (locked_user.failed_pin_attempts or 0) + 1
        
        if locked_user.failed_pin_attempts >= 5:
            locked_user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            db.commit()
            raise HTTPException(
                status_code=403, 
                detail="Account locked for 30 minutes due to failed PIN attempts"
            )
        
        db.commit()
        remaining = 5 - locked_user.failed_pin_attempts
        raise HTTPException(
            status_code=403, 
            detail=f"Invalid Security PIN. {remaining} attempts remaining"
        )
    
    # Reset failed attempts on success
    locked_user.failed_pin_attempts = 0
    locked_user.locked_until = None
    
    # Validate target
    target_type, target_value = validate_target(target)
    
    # Find receiver WITH row lock
    receiver = None
    
    if target_type == "uuid":
        receiver = db.query(models.Account).filter(
            cast(models.Account.id, String) == target_value
        ).with_for_update().first()
    else:
        receiver = db.query(models.Account).filter(
            models.Account.email == target_value
        ).with_for_update().first()
    
    if not receiver:
        db.rollback()
        raise HTTPException(status_code=404, detail="Target account not found")
    
    # Prevent self-transfer
    if str(receiver.id) == str(locked_user.id):
        db.rollback()
        raise HTTPException(status_code=400, detail="Cannot transfer to yourself")
    
    # Currency conversion rates (base: NGN)
    rates = {"NGN": Decimal('1'), "USD": Decimal('0.00069'), "EUR": Decimal('0.00064'), "GBP": Decimal('0.00055')}
    rate = rates.get(currency, Decimal('0.00064'))
    
    # Calculate base amount in NGN
    base_deduction = (Decimal(str(amount)) / rate).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    
    # Check balance
    if locked_user.balance < base_deduction:
        db.rollback()
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    # Execute transfer
    locked_user.balance -= base_deduction
    receiver.balance += base_deduction
    
    # Create transaction record
    tx = models.Transaction(
        sender_id=locked_user.id,
        receiver_id=receiver.id,
        amount=Decimal(str(amount)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP),
        currency=currency,
        signature=f"TX-{uuid.uuid4().hex[:8].upper()}",
        idempotency_key=idempotency_key or str(uuid.uuid4())
    )
    
    db.add(tx)
    
    try:
        db.commit()
        db.refresh(tx)
        db.refresh(locked_user)
    except Exception as e:
        db.rollback()
        logging.error(f"Transfer commit failed: {e}")
        raise HTTPException(status_code=500, detail="Transfer failed. Please try again.")
    
    # Audit log (non-blocking, separate try-except)
    try:
        log_audit(db, locked_user.id, "TRANSFER", {
            "amount": float(amount),
            "currency": currency,
            "receiver_id": str(receiver.id),
            "receiver_email": receiver.email,
            "transaction_id": str(tx.id)
        }, request)
    except Exception:
        pass  # Audit failure should not break response
    
    # Schedule email notifications using fixed background tasks
    schedule_emails(
        bg=bg,
        receiver_email=receiver.email,
        sender_email=locked_user.email,
        sender_name=locked_user.owner_name,
        receiver_name=receiver.owner_name,
        amount=float(amount),
        currency=currency,
        tx_id=str(tx.id)
    )
    
    return {
        "status": "SUCCESS",
        "transaction_id": str(tx.id),
        "amount_sent": amount,
        "currency": currency,
        "sender_balance": float(locked_user.balance),
        "receiver_name": receiver.owner_name,
        "receiver_email": receiver.email
    }

# ============================================
# ACCOUNT ENDPOINTS
# ============================================

@app.get("/accounts/me", response_model=schemas.Account)
async def read_me(user: models.Account = Depends(get_current_user)):
    """Get current user profile."""
    return user

@app.patch("/accounts/update")
@limiter.limit("5/minute")
async def update(
    request: Request, 
    data: schemas.UpdateProfile, 
    db: Session = Depends(get_db), 
    user: models.Account = Depends(get_current_user)
):
    """Update user profile with validation."""
    updated = False
    
    if data.owner_name is not None:
        user.owner_name = data.owner_name
        updated = True
    
    if data.email is not None:
        # Check email uniqueness
        existing = db.query(models.Account).filter(
            models.Account.email == data.email.lower(),
            models.Account.id != user.id
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already in use")
        user.email = data.email.lower()
        updated = True
    
    if data.pin is not None:
        if len(data.pin) != 6 or not data.pin.isdigit():
            raise HTTPException(status_code=400, detail="PIN must be exactly 6 digits")
        user.pin_hash = auth.get_pin_hash(data.pin)
        user.failed_pin_attempts = 0
        user.locked_until = None
        updated = True
    
    if data.password is not None:
        if len(data.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        user.hashed_password = auth.get_password_hash(data.password)
        updated = True
    
    if updated:
        db.commit()
    
    return {"status": "UPDATED", "fields_changed": updated}

# ============================================
# TRANSACTION ENDPOINTS
# ============================================

@app.get("/transactions/")
async def get_txs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: models.Account = Depends(get_current_user)
):
    """Get paginated transaction history."""
    user_id_str = str(user.id)
    
    txs = db.query(models.Transaction).options(
        joinedload(models.Transaction.sender),
        joinedload(models.Transaction.receiver)
    ).filter(
        or_(
            cast(models.Transaction.sender_id, String) == user_id_str,
            cast(models.Transaction.receiver_id, String) == user_id_str
        )
    ).order_by(models.Transaction.created_at.desc()).offset(skip).limit(limit).all()
    
    result = []
    for t in txs:
        is_credit = str(t.receiver_id) == user_id_str
        counterparty = t.sender if is_credit else t.receiver
        
        result.append({
            "id": str(t.id),
            "amount": float(t.amount),
            "currency": t.currency or "NGN",
            "status": t.status,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "type": "CREDIT" if is_credit else "DEBIT",
            "counterparty_name": counterparty.owner_name if counterparty else "Unknown",
            "counterparty_email": counterparty.email if counterparty else "Unknown",
            "counterparty_id": str(counterparty.id) if counterparty else "Unknown",
            "signature": t.signature,
            "sender_id": str(t.sender_id),
            "receiver_id": str(t.receiver_id)
        })
    
    return result

@app.get("/transactions/export")
async def export_txs(
    format: str = Query("pdf", pattern="^(pdf|json)$"),
    db: Session = Depends(get_db),
    user: models.Account = Depends(get_current_user)
):
    """Export transactions as PDF or JSON."""
    user_id_str = str(user.id)
    
    txs = db.query(models.Transaction).options(
        joinedload(models.Transaction.sender),
        joinedload(models.Transaction.receiver)
    ).filter(
        or_(
            cast(models.Transaction.sender_id, String) == user_id_str,
            cast(models.Transaction.receiver_id, String) == user_id_str
        )
    ).order_by(models.Transaction.created_at.desc()).all()
    
    if format == "json":
        return [
            {
                "id": str(t.id), 
                "amount": str(t.amount), 
                "status": t.status, 
                "created_at": t.created_at.isoformat() if t.created_at else None
            } 
            for t in txs
        ]
    
    # PDF Generation
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
        from reportlab.lib.units import mm
    except ImportError:
        raise HTTPException(status_code=500, detail="PDF generation not available")
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )
    
    styles = getSampleStyleSheet()
    story = []
    
    story.append(Paragraph("<b>CENTURION TACTICAL LEDGER</b>", styles['Title']))
    story.append(Paragraph(f"Account: {user.owner_name} | {user.email}", styles['Normal']))
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", 
        styles['Normal']
    ))
    story.append(Spacer(1, 10*mm))
    
    story.append(Paragraph(
        f"<b>Current Balance:</b> {user.currency} {float(user.balance):,.2f}", 
        styles['Heading3']
    ))
    story.append(Spacer(1, 5*mm))
    
    if txs:
        table_data = [["Date", "Type", "Amount", "Currency", "Status", "Counterparty", "Email", "TX ID"]]
        
        for t in txs:
            tx_type = "CREDIT" if str(t.receiver_id) == user_id_str else "DEBIT"
            counterparty = t.sender if tx_type == "CREDIT" else t.receiver
            cp_name = counterparty.owner_name if counterparty else "Unknown"
            cp_email = counterparty.email if counterparty else "Unknown"
            date_str = t.created_at.strftime("%Y-%m-%d %H:%M") if t.created_at else "N/A"
            
            table_data.append([
                date_str,
                tx_type,
                f"{float(t.amount):,.2f}",
                t.currency or "NGN",
                t.status,
                cp_name,
                cp_email,
                str(t.id)[:8]
            ])
        
        table = Table(
            table_data, 
            colWidths=[28*mm, 15*mm, 22*mm, 15*mm, 18*mm, 28*mm, 32*mm, 18*mm]
        )
        
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#0a0f1d')),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#3b82f6')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#0f172a'), colors.HexColor('#0a0f1d')]),
        ]))
        
        story.append(table)
    else:
        story.append(Paragraph("No transactions found.", styles['Normal']))
    
    doc.build(story)
    buffer.seek(0)
    
    return Response(
        buffer.getvalue(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=centurion_ledger_{str(user.id)[:8]}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
        }
    )

# ============================================
# AI FORECAST
# ============================================

@app.get("/forecast/")
async def get_forecast(
    db: Session = Depends(get_db), 
    user: models.Account = Depends(get_current_user)
):
    """Generate financial insights based on transaction history."""
    user_id_str = str(user.id)
    
    txs = db.query(models.Transaction).filter(
        or_(
            cast(models.Transaction.sender_id, String) == user_id_str,
            cast(models.Transaction.receiver_id, String) == user_id_str
        )
    ).order_by(models.Transaction.created_at.desc()).all()
    
    if not txs:
        return {
            "message": "No transaction history available for forecasting.",
            "insights": [],
            "prediction": None,
            "recommendations": ["Start making transactions to unlock AI forecasting insights."],
            "daily_activity": {}
        }
    
    # Calculate totals
    total_sent = sum(float(t.amount) for t in txs if str(t.sender_id) == user_id_str)
    total_received = sum(float(t.amount) for t in txs if str(t.receiver_id) == user_id_str)
    tx_count = len(txs)
    
    # Currency breakdown
    currency_stats = {}
    for t in txs:
        curr = t.currency or "NGN"
        if curr not in currency_stats:
            currency_stats[curr] = {"sent": 0, "received": 0, "count": 0}
        currency_stats[curr]["count"] += 1
        if str(t.sender_id) == user_id_str:
            currency_stats[curr]["sent"] += float(t.amount)
        else:
            currency_stats[curr]["received"] += float(t.amount)
    
    # Daily activity
    from collections import defaultdict
    daily_activity = defaultdict(lambda: {"sent": 0, "received": 0, "count": 0})
    
    for t in txs:
        if t.created_at:
            day_key = t.created_at.strftime("%Y-%m-%d")
            daily_activity[day_key]["count"] += 1
            if str(t.sender_id) == user_id_str:
                daily_activity[day_key]["sent"] += float(t.amount)
            else:
                daily_activity[day_key]["received"] += float(t.amount)
    
    # Predictions
    days_with_activity = len(daily_activity)
    avg_daily_sent = total_sent / days_with_activity if days_with_activity > 0 else 0
    predicted_monthly_outflow = avg_daily_sent * 30
    
    # Trend analysis
    if len(daily_activity) >= 2:
        sorted_days = sorted(daily_activity.keys())
        mid = len(sorted_days) // 2
        first_half = sorted_days[:mid]
        second_half = sorted_days[mid:]
        
        first_avg = sum(daily_activity[d]["sent"] for d in first_half) / len(first_half) if first_half else 0
        second_avg = sum(daily_activity[d]["sent"] for d in second_half) / len(second_half) if second_half else 0
        
        if second_avg > first_avg * 1.1:
            trend = "INCREASING"
        elif second_avg < first_avg * 0.9:
            trend = "DECREASING"
        else:
            trend = "STABLE"
    else:
        trend = "INSUFFICIENT_DATA"
    
    net_flow = total_received - total_sent
    
    # Insights
    most_active_currency = max(currency_stats.keys(), key=lambda k: currency_stats[k]['count']) if currency_stats else "NGN"
    
    insights = [
        f"📊 Total Transactions: {tx_count}",
        f"💸 Total Sent: {total_sent:,.2f} across {len(currency_stats)} currencies",
        f"💰 Total Received: {total_received:,.2f}",
        f"📈 Net Flow: {'+' if net_flow >= 0 else ''}{net_flow:,.2f} ({'Surplus' if net_flow >= 0 else 'Deficit'})",
        f"🔥 Most Active Currency: {most_active_currency}",
        f"📅 Active Days: {days_with_activity}",
        f"📉 Spending Trend: {trend}"
    ]
    
    # Recommendations
    recommendations = []
    if net_flow < 0:
        recommendations.append("⚠️ Your outflows exceed inflows. Consider reviewing your spending patterns.")
    if avg_daily_sent > float(user.balance) * 0.01:
        recommendations.append("💡 Your daily spending rate is high relative to your balance. Monitor closely.")
    if days_with_activity < 3:
        recommendations.append("🌱 Build more transaction history for accurate predictions.")
    if trend == "INCREASING":
        recommendations.append("📈 Spending is trending upward. Budget review recommended.")
    elif trend == "DECREASING":
        recommendations.append("✅ Spending is trending downward. Good financial discipline!")
    
    return {
        "message": f"AI Forecast for {user.owner_name}",
        "insights": insights,
        "prediction": {
            "predicted_monthly_outflow": round(predicted_monthly_outflow, 2),
            "trend": trend,
            "confidence": "MEDIUM" if tx_count >= 10 else "LOW",
            "currency_breakdown": currency_stats
        },
        "recommendations": recommendations,
        "daily_activity": dict(daily_activity)
    }

# ============================================
# STATIC FILES - MUST BE LAST
# ============================================

app.mount("/", StaticFiles(directory="static", html=True), name="static")