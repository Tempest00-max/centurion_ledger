#!/usr/bin/env python3
"""
CENTURION LEDGER - DIAGNOSTIC SCRIPT
Run this to identify the exact problem
"""
import os
import sys

sys.path.insert(0, '/home/pandora_admin/dev/portfolio/centurion_ledger')

from dotenv import load_dotenv
load_dotenv()

print("=" * 60)
print("CENTURION LEDGER DIAGNOSTICS")
print("=" * 60)

# 1. Check Python version
print(f"\n[1] Python version: {sys.version}")

# 2. Check key dependencies
print("\n[2] Checking dependencies...")
try:
    import pydantic
    print(f"   ✓ Pydantic: {pydantic.__version__}")
except ImportError as e:
    print(f"   ✗ Pydantic: MISSING - {e}")

try:
    import fastapi
    print(f"   ✓ FastAPI: {fastapi.__version__}")
except ImportError as e:
    print(f"   ✗ FastAPI: MISSING - {e}")

try:
    import sqlalchemy
    print(f"   ✓ SQLAlchemy: {sqlalchemy.__version__}")
except ImportError as e:
    print(f"   ✗ SQLAlchemy: MISSING - {e}")

# 3. Check database connection
print("\n[3] Checking database connection...")
try:
    from app.database import engine
    from sqlalchemy import text
    
    with engine.connect() as conn:
        result = conn.execute(text("SELECT version();"))
        version = result.scalar()
        print(f"   ✓ PostgreSQL connected: {version[:50]}...")
        
        result = conn.execute(text("""
            SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'
        """))
        tables = [row[0] for row in result]
        print(f"   ✓ Tables found: {tables}")
        
        if 'accounts' in tables:
            result = conn.execute(text("""
                SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'accounts'
            """))
            columns = {row[0]: row[1] for row in result}
            print(f"   ✓ Accounts columns: {list(columns.keys())}")
            
            required = ['id', 'owner_name', 'username', 'email', 'hashed_password', 'pin_hash', 'balance']
            missing = [c for c in required if c not in columns]
            if missing:
                print(f"   ✗ MISSING COLUMNS: {missing}")
            else:
                print(f"   ✓ All required columns present")
        else:
            print(f"   ✗ 'accounts' table NOT FOUND")
            
except Exception as e:
    print(f"   ✗ Database error: {e}")

# 4. Test model loading
print("\n[4] Testing SQLAlchemy models...")
try:
    from app.models import Account, Transaction
    print(f"   ✓ Models imported successfully")
except Exception as e:
    print(f"   ✗ Model error: {e}")

# 5. Test schema validation
print("\n[5] Testing Pydantic schemas...")
try:
    from app.schemas import Account
    
    test_data = {
        'id': '6caf2a2b-1353-4eeb-a9d6-4a092d3d495e',
        'owner_name': 'Test User',
        'username': 'testuser',
        'email': 'test@test.com',
        'balance': '1562500000.00',
        'currency': 'USD',
        'version': 1,
        'created_at': None
    }
    
    account = Account(**test_data)
    print(f"   ✓ Schema validation passed")
except Exception as e:
    print(f"   ✗ Schema error: {e}")

# 6. Test UUID serialization
print("\n[6] Testing UUID serialization...")
try:
    from uuid import UUID
    from app.schemas import Account
    
    uid = UUID('6caf2a2b-1353-4eeb-a9d6-4a092d3d495e')
    test_data = {
        'id': uid,
        'owner_name': 'Test',
        'username': 'test',
        'email': 'test@test.com',
        'balance': '100.00',
        'currency': 'USD',
        'version': 1
    }
    account = Account(**test_data)
    print(f"   ✓ UUID accepted by schema")
except Exception as e:
    print(f"   ✗ UUID serialization error: {e}")

# 7. Test actual database serialization
print("\n[7] Testing actual database serialization...")
try:
    from app.database import SessionLocal
    from app.models import Account
    from app.schemas import Account as AccountSchema
    
    db = SessionLocal()
    user = db.query(Account).first()
    if user:
        print(f"   ✓ Found user: {user.email}")
        print(f"   ✓ User ID type: {type(user.id)}")
        print(f"   ✓ User ID value: {user.id}")
        
        try:
            serialized = AccountSchema.model_validate(user)
            print(f"   ✓ Serialization SUCCESS")
            print(f"   ✓ Serialized ID: {serialized.id}")
        except Exception as e:
            print(f"   ✗ Serialization FAILED: {e}")
    else:
        print(f"   ⚠ No users found in database")
    db.close()
except Exception as e:
    print(f"   ✗ Database error: {e}")

print("\n" + "=" * 60)
print("DIAGNOSTICS COMPLETE")
print("=" * 60)