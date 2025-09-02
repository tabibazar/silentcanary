#!/usr/bin/env python3
"""
DynamoDB setup script for SilentCanary
Creates tables and configures DynamoDB for local development or AWS
"""

import boto3
from botocore.exceptions import ClientError
import os
from dotenv import load_dotenv

load_dotenv()

def get_dynamodb_resource():
    """Get DynamoDB resource - local or AWS based on environment"""
    # For local development, you can use DynamoDB Local
    # For production, this will use AWS credentials
    if os.getenv('DYNAMODB_LOCAL'):
        return boto3.resource(
            'dynamodb',
            endpoint_url='http://localhost:8000',
            region_name='us-east-1',
            aws_access_key_id='dummy',
            aws_secret_access_key='dummy'
        )
    else:
        # AWS DynamoDB - uses AWS credentials from environment or IAM role
        return boto3.resource('dynamodb', region_name=os.getenv('AWS_REGION', 'us-east-1'))

def create_users_table(dynamodb):
    """Create Users table"""
    try:
        table = dynamodb.create_table(
            TableName='SilentCanary_Users',
            KeySchema=[
                {
                    'AttributeName': 'user_id',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'user_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'email',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'username',
                    'AttributeType': 'S'
                }
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'email-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'email',
                            'KeyType': 'HASH'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    }
                },
                {
                    'IndexName': 'username-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'username',
                            'KeyType': 'HASH'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    }
                }
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        print("✅ Users table created successfully")
        return table
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print("✅ Users table already exists")
            return dynamodb.Table('SilentCanary_Users')
        else:
            print(f"❌ Error creating Users table: {e}")
            raise

def create_canaries_table(dynamodb):
    """Create Canaries table"""
    try:
        table = dynamodb.create_table(
            TableName='SilentCanary_Canaries',
            KeySchema=[
                {
                    'AttributeName': 'canary_id',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'canary_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'user_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'token',
                    'AttributeType': 'S'
                }
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'user-id-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'user_id',
                            'KeyType': 'HASH'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    }
                },
                {
                    'IndexName': 'token-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'token',
                            'KeyType': 'HASH'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    }
                }
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        print("✅ Canaries table created successfully")
        return table
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print("✅ Canaries table already exists")
            return dynamodb.Table('SilentCanary_Canaries')
        else:
            print(f"❌ Error creating Canaries table: {e}")
            raise

def create_canary_logs_table(dynamodb):
    """Create Canary Logs table"""
    try:
        table = dynamodb.create_table(
            TableName='SilentCanary_CanaryLogs',
            KeySchema=[
                {
                    'AttributeName': 'log_id',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'log_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'canary_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'timestamp',
                    'AttributeType': 'S'
                }
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'canary-id-timestamp-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'canary_id',
                            'KeyType': 'HASH'
                        },
                        {
                            'AttributeName': 'timestamp',
                            'KeyType': 'RANGE'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    }
                }
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        print("✅ Canary Logs table created successfully")
        return table
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print("✅ Canary Logs table already exists")
            return dynamodb.Table('SilentCanary_CanaryLogs')
        else:
            print(f"❌ Error creating Canary Logs table: {e}")
            raise

def create_smart_alerts_table(dynamodb):
    """Create Smart Alerts table"""
    try:
        table = dynamodb.create_table(
            TableName='SilentCanary_SmartAlerts',
            KeySchema=[
                {
                    'AttributeName': 'smart_alert_id',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'smart_alert_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'canary_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'user_id',
                    'AttributeType': 'S'
                }
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'canary-id-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'canary_id',
                            'KeyType': 'HASH'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    }
                },
                {
                    'IndexName': 'user-id-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'user_id',
                            'KeyType': 'HASH'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    }
                }
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        print("✅ Smart Alerts table created successfully")
        return table
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print("✅ Smart Alerts table already exists")
            return dynamodb.Table('SilentCanary_SmartAlerts')
        else:
            print(f"❌ Error creating Smart Alerts table: {e}")
            raise

def create_api_usage_table(dynamodb):
    """Create API Usage table"""
    try:
        table = dynamodb.create_table(
            TableName='SilentCanary_APIUsage',
            KeySchema=[
                {
                    'AttributeName': 'log_id',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'log_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'user_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'timestamp',
                    'AttributeType': 'S'
                }
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'user-id-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'user_id',
                            'KeyType': 'HASH'
                        },
                        {
                            'AttributeName': 'timestamp',
                            'KeyType': 'RANGE'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    }
                }
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        print("✅ API Usage table created successfully")
        return table
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print("✅ API Usage table already exists")
            return dynamodb.Table('SilentCanary_APIUsage')
        else:
            print(f"❌ Error creating API Usage table: {e}")
            raise

def setup_tables():
    """Set up all DynamoDB tables"""
    print("🔄 Setting up DynamoDB tables for SilentCanary...")
    
    try:
        dynamodb = get_dynamodb_resource()
        
        # Create tables
        users_table = create_users_table(dynamodb)
        canaries_table = create_canaries_table(dynamodb)
        logs_table = create_canary_logs_table(dynamodb)
        smart_alerts_table = create_smart_alerts_table(dynamodb)
        api_usage_table = create_api_usage_table(dynamodb)
        
        # Wait for tables to be active
        print("⏳ Waiting for tables to be active...")
        users_table.wait_until_exists()
        canaries_table.wait_until_exists()
        logs_table.wait_until_exists()
        smart_alerts_table.wait_until_exists()
        api_usage_table.wait_until_exists()
        
        print("🎉 DynamoDB setup completed successfully!")
        print(f"📊 Users table: {users_table.table_status}")
        print(f"📊 Canaries table: {canaries_table.table_status}")
        print(f"📊 Canary Logs table: {logs_table.table_status}")
        print(f"📊 Smart Alerts table: {smart_alerts_table.table_status}")
        print(f"📊 API Usage table: {api_usage_table.table_status}")
        
        return True
        
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        return False

if __name__ == '__main__':
    setup_tables()