from decimal import Decimal
from datetime import datetime, timedelta

def calculate_forecast(transactions, current_balance):
    """Simple AI logic to predict end-of-month status."""
    if not transactions:
        return current_balance

    # Calculate average daily burn rate
    total_spent = sum(Decimal(str(tx.amount)) for tx in transactions if tx.amount < 0)
    # Simple projection logic based on the last 30 days
    projected_balance = Decimal(str(current_balance)) + (total_spent * Decimal('0.5'))
    
    return float(projected_balance)