#!/usr/bin/env python3
"""
Create the APIKeys table in DynamoDB
"""

import boto3
from botocore.exceptions import ClientError
import os
from dotenv import load_dotenv

load_dotenv()

def create_api_keys_table():
    """Create the APIKeys table with proper indexes"""
    
    # Get DynamoDB client
    if os.getenv('DYNAMODB_LOCAL'):
        dynamodb = boto3.client(
            'dynamodb',
            endpoint_url='http://localhost:8000',
            region_name='ca-central-1',
            aws_access_key_id='dummy',
            aws_secret_access_key='dummy'
        )
    else:
        dynamodb = boto3.client('dynamodb', region_name=os.getenv('AWS_REGION', 'ca-central-1'))
    
    table_name = 'SilentCanary_APIKeys'
    
    try:
        # Check if table already exists
        try:
            response = dynamodb.describe_table(TableName=table_name)
            print(f"Table {table_name} already exists")
            return True
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                raise
            # Table doesn't exist, create it
            print(f"Creating table {table_name}...")
        
        # Create the table
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {
                    'AttributeName': 'api_key_id',
                    'KeyType': 'HASH'
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'api_key_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'user_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'key_value',
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
                    },
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                },
                {
                    'IndexName': 'key-value-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'key_value',
                            'KeyType': 'HASH'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    },
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        
        print(f"Table {table_name} created successfully!")
        print(f"Waiting for table to become active...")
        
        # Wait for table to become active
        waiter = dynamodb.get_waiter('table_exists')
        waiter.wait(TableName=table_name)
        
        print(f"Table {table_name} is now active and ready to use!")
        return True
        
    except ClientError as e:
        print(f"Error creating table: {e}")
        return False

if __name__ == '__main__':
    success = create_api_keys_table()
    if not success:
        exit(1)