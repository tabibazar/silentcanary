#!/usr/bin/env python3
"""
Database initialization script for SilentCanary
Run this script to create the database tables.
"""

from app import app, db

def init_database():
    """Initialize the database by creating all tables."""
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✅ Database tables created successfully!")
        print("📂 Database location: instance/silentcanary.db")
        
        # Display table info
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"📊 Created tables: {', '.join(tables)}")

if __name__ == '__main__':
    init_database()