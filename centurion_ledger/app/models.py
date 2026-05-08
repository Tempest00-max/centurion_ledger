from sqlalchemy import Column, String, Float, DateTime, ForeignKey, DECIMAL, Integer, Text, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import relationship
from datetime import datetime
from decimal import Decimal
from .database import Base
import uuid


# ============================================
# ACCOUNT MODEL
# ============================================

class Account(Base):
    __tablename__ = "accounts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_name = Column(String(255), nullable=False)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    pin_hash = Column(String(255), nullable=False)
    balance = Column(DECIMAL(15, 2), nullable=False, default=Decimal('0.00'))
    currency = Column(String(3), default='NGN', nullable=False)
    version = Column(Integer, default=1, nullable=False)
    failed_pin_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    sent = relationship(
        "Transaction", 
        foreign_keys="Transaction.sender_id", 
        back_populates="sender",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    received = relationship(
        "Transaction", 
        foreign_keys="Transaction.receiver_id", 
        back_populates="receiver",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    audit_logs = relationship(
        "AuditLog", 
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    
    def __repr__(self):
        return f"<Account(id={self.id}, email={self.email}, balance={self.balance})>"


# ============================================
# TRANSACTION MODEL
# ============================================

class Transaction(Base):
    __tablename__ = "transactions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sender_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("accounts.id", ondelete="CASCADE"), 
        nullable=False,
        index=True
    )
    receiver_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("accounts.id", ondelete="CASCADE"), 
        nullable=False,
        index=True
    )
    amount = Column(DECIMAL(15, 2), nullable=False)
    currency = Column(String(3), default='NGN', nullable=False)
    idempotency_key = Column(
        String(255), 
        unique=True, 
        nullable=False, 
        default=lambda: str(uuid.uuid4()),
        index=True
    )
    signature = Column(Text, nullable=False, default='')
    status = Column(String(20), default='COMPLETED', nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    sender = relationship(
        "Account", 
        foreign_keys=[sender_id], 
        back_populates="sent"
    )
    receiver = relationship(
        "Account", 
        foreign_keys=[receiver_id], 
        back_populates="received"
    )
    
    # Composite index for common query patterns
    __table_args__ = (
        Index('ix_transactions_sender_created', 'sender_id', 'created_at'),
        Index('ix_transactions_receiver_created', 'receiver_id', 'created_at'),
    )
    
    def __repr__(self):
        return f"<Transaction(id={self.id}, amount={self.amount}, status={self.status})>"


# ============================================
# AUDIT LOG MODEL
# ============================================

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("accounts.id", ondelete="CASCADE"), 
        nullable=False,
        index=True
    )
    action = Column(String(50), nullable=False, index=True)
    details = Column(JSONB, default=dict)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    user = relationship("Account", back_populates="audit_logs")
    
    # Index for compliance queries
    __table_args__ = (
        Index('ix_audit_logs_user_action', 'user_id', 'action'),
    )
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, action={self.action}, user_id={self.user_id})>"