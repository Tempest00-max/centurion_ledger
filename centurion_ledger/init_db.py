#!/usr/bin/env python3
"""
CENTURION LEDGER - DATABASE INITIALIZATION
Safe for re-runs: won't duplicate accounts, updates existing ones.
"""

import uuid
import sys
from decimal import Decimal
from sqlalchemy.orm import Session
from app import models, database, auth

def init_db():
    db: Session = database.SessionLocal()
    engine = database.engine

    print("=" * 60)
    print("CENTURION LEDGER INITIALIZATION v2.0")
    print("=" * 60)

    # 1. Ensure tables exist (safe to re-run)
    print("\n[1] Ensuring database schema exists...")
    models.Base.metadata.create_all(bind=engine)
    print("   ✓ Schema verified")

    # 2. Seed or update admin account
    print("\n[2] Provisioning Primary Ledger (Admin)...")
    
    admin_id = uuid.UUID('eb3da695-869b-4dab-b6de-8a2ecd0eb16b')
    
    admin = db.query(models.Account).filter(
        models.Account.id == admin_id
    ).first()
    
    if admin:
        print(f"   ⚠ Admin exists: {admin.email}")
        print("   ✓ Updating credentials...")
        admin.owner_name = "Primary Ledger"
        admin.username = "pandora_admin"
        admin.email = "otolulope635@gmail.com"
        admin.hashed_password = auth.get_password_hash("Centurion2026!")
        admin.pin_hash = auth.get_pin_hash("123456")
        admin.balance = Decimal('500.00')
        admin.currency = "NGN"
        admin.failed_pin_attempts = 0
        admin.locked_until = None
    else:
        print("   ✓ Creating new admin account...")
        admin = models.Account(
            id=admin_id,
            owner_name="Primary Ledger",
            username="pandora_admin",
            email="otolulope635@gmail.com",
            hashed_password=auth.get_password_hash("Centurion2026!"),
            pin_hash=auth.get_pin_hash("123456"),
            balance=Decimal('500.00'),
            currency="NGN"
        )
        db.add(admin)
    
    # 3. Seed or update Vault B (demo receiver)
    print("\n[3] Provisioning Vault B (Demo Receiver)...")
    
    receiver_id = uuid.UUID('f5e03b53-418b-43a4-8d13-91622409ebba')
    
    receiver = db.query(models.Account).filter(
        models.Account.id == receiver_id
    ).first()
    
    if receiver:
        print(f"   ⚠ Vault B exists: {receiver.email}")
        print("   ✓ Updating credentials...")
        receiver.owner_name = "Vault B"
        receiver.username = "vault_user"
        receiver.email = "vault@projectpandora.com"
        receiver.hashed_password = auth.get_password_hash("SecureVault789")
        receiver.pin_hash = auth.get_pin_hash("654321")
        receiver.balance = Decimal('0.00')
        receiver.currency = "NGN"
        receiver.failed_pin_attempts = 0
        receiver.locked_until = None
    else:
        print("   ✓ Creating new Vault B account...")
        receiver = models.Account(
            id=receiver_id,
            owner_name="Vault B",
            username="vault_user",
            email="vault@projectpandora.com",
            hashed_password=auth.get_password_hash("SecureVault789"),
            pin_hash=auth.get_pin_hash("654321"),
            balance=Decimal('0.00'),
            currency="NGN"
        )
        db.add(receiver)
    
    # 4. Commit all changes
    print("\n[4] Committing changes...")
    db.commit()
    
    print("=" * 60)
    print("SUCCESS: Database initialized")
    print("-" * 60)
    print("DEMO ACCOUNTS:")
    print(f"  Admin:    pandora_admin / Centurion2026! / PIN: 123456")
    print(f"            ID: {admin_id}")
    print(f"            Email: otolulope635@gmail.com")
    print(f"  Vault B:  vault_user / SecureVault789 / PIN: 654321")
    print(f"            ID: {receiver_id}")
    print(f"            Email: vault@projectpandora.com")
    print("-" * 60)
    print("NOTE: Run this script anytime to reset demo account passwords.")
    print("=" * 60)
    
    db.close()
    return 0


def reset_demo_balances():
    """Reset demo account balances without destroying data."""
    db: Session = database.SessionLocal()
    
    print("\n[RESET] Restoring demo balances...")
    
    accounts = [
        ('eb3da695-869b-4dab-b6de-8a2ecd0eb16b', Decimal('500.00')),
        ('f5e03b53-418b-43a4-8d13-91622409ebba', Decimal('0.00'))
    ]
    
    for uid_str, balance in accounts:
        acc = db.query(models.Account).filter(
            models.Account.id == uuid.UUID(uid_str)
        ).first()
        
        if acc:
            acc.balance = balance
            acc.failed_pin_attempts = 0
            acc.locked_until = None
            print(f"   ✓ Reset {acc.username}: {balance}")
    
    db.commit()
    db.close()
    print("   ✓ Done")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Centurion Ledger DB Tool")
    parser.add_argument(
        '--reset-balances', 
        action='store_true',
        help='Reset only demo balances, preserve accounts'
    )
    parser.add_argument(
        '--force-recreate',
        action='store_true',
        help='DROP all tables and recreate (DESTROYS DATA)'
    )
    
    args = parser.parse_args()
    
    if args.force_recreate:
        confirm = input("⚠️  This will DESTROY ALL DATA. Type 'DESTROY' to confirm: ")
        if confirm == "DESTROY":
            print("\n💀 Dropping all tables...")
            models.Base.metadata.drop_all(bind=database.engine)
            print("✓ Tables dropped. Re-initializing...")
            init_db()
        else:
            print("Aborted.")
            sys.exit(0)
    elif args.reset_balances:
        reset_demo_balances()
    else:
        sys.exit(init_db())