#!/usr/bin/env python3
"""
Database migration script to add timezone column to user table
"""

from app import app, db
import sqlite3

def migrate_timezone():
    """Add timezone column to existing user table."""
    with app.app_context():
        print("🔄 Migrating database to add timezone support...")
        
        try:
            # Check if timezone column already exists
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('user')]
            
            if 'timezone' in columns:
                print("✅ timezone column already exists")
                return True
            
            # Add the new column
            with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE user ADD COLUMN timezone VARCHAR(50) DEFAULT 'UTC'"))
                conn.commit()
            
            print("✅ Added timezone column to user table")
            print("🎉 Database migration completed successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Migration failed: {e}")
            return False

if __name__ == '__main__':
    migrate_timezone()