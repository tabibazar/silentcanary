#!/usr/bin/env python3
"""
Database migration script to add Slack webhook support
"""

from app import app, db
import sqlite3

def migrate_database():
    """Add slack_webhook column to existing canary table."""
    with app.app_context():
        print("🔄 Migrating database to add Slack webhook support...")
        
        try:
            # Check if slack_webhook column already exists
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('canary')]
            
            if 'slack_webhook' in columns:
                print("✅ slack_webhook column already exists")
                return True
            
            # Add the new column
            with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE canary ADD COLUMN slack_webhook VARCHAR(500)"))
                conn.commit()
            
            print("✅ Added slack_webhook column to canary table")
            print("🎉 Database migration completed successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Migration failed: {e}")
            return False

if __name__ == '__main__':
    migrate_database()