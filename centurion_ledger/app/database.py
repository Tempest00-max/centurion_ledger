import os
from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

# ============================================
# DATABASE CONFIGURATION
# ============================================

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is required")

# ============================================
# ENGINE CONFIGURATION
# ============================================

engine = create_engine(
    DATABASE_URL,
    pool_size=10,              # Base connections
    max_overflow=20,           # Burst connections
    pool_pre_ping=True,        # Verify connection before use
    pool_recycle=3600,         # Recycle connections after 1 hour
    pool_timeout=30,           # Wait 30s for available connection
    echo=False                 # Set to True for SQL debugging
)

# ============================================
# SESSION FACTORY
# ============================================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False     # Prevent detached instance errors
)

# ============================================
# BASE CLASS
# ============================================

Base = declarative_base()

# ============================================
# CONNECTION EVENTS
# ============================================

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """
    Apply database-specific optimizations on connect.
    For PostgreSQL: sets timezone and search path.
    """
    if "postgresql" in DATABASE_URL:
        cursor = dbapi_conn.cursor()
        cursor.execute("SET timezone = 'UTC'")
        cursor.execute("SET search_path = public")
        cursor.close()


@event.listens_for(engine, "checkout")
def ping_connection(dbapi_conn, connection_record, connection_proxy):
    """
    Verify connection is alive on checkout.
    pool_pre_ping handles most cases, this is extra safety.
    """
    try:
        dbapi_conn.cursor().execute("SELECT 1")
    except Exception:
        raise Exception("Database connection is dead")


# ============================================
# DEPENDENCY INJECTION
# ============================================

def get_db():
    """
    FastAPI dependency for database sessions.
    Ensures proper cleanup even on exceptions.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ============================================
# HEALTH CHECK
# ============================================

def check_database_health() -> dict:
    """
    Verify database connectivity.
    Returns status dict for health endpoints.
    """
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.scalar()
            return {
                "status": "healthy",
                "database": "connected"
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e)
        }


# ============================================
# MIGRATION HELPER
# ============================================

def init_tables():
    """
    Create all tables. Use Alembic in production.
    This is for development/bootstrap only.
    """
    Base.metadata.create_all(bind=engine)


def drop_tables():
    """
    Drop all tables. DANGEROUS - only for testing.
    """
    Base.metadata.drop_all(bind=engine)