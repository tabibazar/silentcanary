#!/usr/bin/env python3
"""
Migration script to move data from SQLite to DynamoDB
"""

from app import app, db, User as SQLUser, Canary as SQLCanary  # SQLAlchemy models
from models import User as DDBUser, Canary as DDBCanary  # DynamoDB models
from datetime import datetime

def migrate_users():
    """Migrate users from SQLite to DynamoDB"""
    print("🔄 Migrating users...")
    
    with app.app_context():
        sql_users = SQLUser.query.all()
        
        migrated = 0
        for sql_user in sql_users:
            # Create DynamoDB user
            ddb_user = DDBUser(
                username=sql_user.username,
                email=sql_user.email,
                password_hash=sql_user.password_hash,
                is_verified=sql_user.is_verified,
                timezone=getattr(sql_user, 'timezone', 'UTC'),
                created_at=sql_user.created_at.isoformat()
            )
            
            if ddb_user.save():
                print(f"✅ Migrated user: {sql_user.username}")
                migrated += 1
            else:
                print(f"❌ Failed to migrate user: {sql_user.username}")
        
        print(f"📊 Migrated {migrated}/{len(sql_users)} users")
        return migrated

def migrate_canaries():
    """Migrate canaries from SQLite to DynamoDB"""
    print("🔄 Migrating canaries...")
    
    with app.app_context():
        sql_canaries = SQLCanary.query.all()
        
        migrated = 0
        for sql_canary in sql_canaries:
            # Get corresponding DynamoDB user
            sql_user = SQLUser.query.get(sql_canary.user_id)
            ddb_user = DDBUser.get_by_email(sql_user.email)
            
            if not ddb_user:
                print(f"❌ Could not find DynamoDB user for canary: {sql_canary.name}")
                continue
            
            # Create DynamoDB canary
            ddb_canary = DDBCanary(
                name=sql_canary.name,
                user_id=ddb_user.user_id,
                interval_minutes=sql_canary.interval_minutes,
                grace_minutes=sql_canary.grace_minutes,
                token=sql_canary.token,
                status=sql_canary.status,
                is_active=sql_canary.is_active,
                alert_type=getattr(sql_canary, 'alert_type', 'email'),
                alert_email=getattr(sql_canary, 'alert_email', None),
                slack_webhook=getattr(sql_canary, 'slack_webhook', None),
                created_at=sql_canary.created_at.isoformat(),
                last_checkin=sql_canary.last_checkin.isoformat() if sql_canary.last_checkin else None,
                next_expected=sql_canary.next_expected.isoformat() if sql_canary.next_expected else None
            )
            
            if ddb_canary.save():
                print(f"✅ Migrated canary: {sql_canary.name}")
                migrated += 1
            else:
                print(f"❌ Failed to migrate canary: {sql_canary.name}")
        
        print(f"📊 Migrated {migrated}/{len(sql_canaries)} canaries")
        return migrated

def verify_migration():
    """Verify the migration by comparing counts"""
    print("🔍 Verifying migration...")
    
    with app.app_context():
        sql_user_count = SQLUser.query.count()
        sql_canary_count = SQLCanary.query.count()
    
    # Get DynamoDB counts (approximate, since scan can be expensive)
    from models import users_table, canaries_table
    
    users_response = users_table.scan(Select='COUNT')
    canaries_response = canaries_table.scan(Select='COUNT')
    
    ddb_user_count = users_response['Count']
    ddb_canary_count = canaries_response['Count']
    
    print(f"📊 Users: SQLite={sql_user_count}, DynamoDB={ddb_user_count}")
    print(f"📊 Canaries: SQLite={sql_canary_count}, DynamoDB={ddb_canary_count}")
    
    if sql_user_count == ddb_user_count and sql_canary_count == ddb_canary_count:
        print("✅ Migration verification successful!")
        return True
    else:
        print("⚠️ Migration counts don't match. Please review.")
        return False

def main():
    """Main migration function"""
    print("🚀 Starting SQLite to DynamoDB migration...")
    
    try:
        # Migrate users first (canaries depend on users)
        user_count = migrate_users()
        
        # Then migrate canaries
        canary_count = migrate_canaries()
        
        # Verify migration
        if verify_migration():
            print("🎉 Migration completed successfully!")
            print(f"📈 Total migrated: {user_count} users, {canary_count} canaries")
        else:
            print("⚠️ Migration completed with warnings. Please verify manually.")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()