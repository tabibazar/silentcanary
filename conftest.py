"""
Test configuration and fixtures for SilentCanary
"""
import pytest
import boto3
import os
from moto import mock_dynamodb
from datetime import datetime, timezone
import tempfile

# Import the app and models
from app import app
from models import User, Canary, CanaryLog

@pytest.fixture(scope="function")
def mock_aws():
    """Mock AWS services for testing"""
    with mock_dynamodb():
        yield

@pytest.fixture(scope="function") 
def dynamodb_tables(mock_aws):
    """Create test DynamoDB tables"""
    # Patch the models to use our test DynamoDB instance
    
    dynamodb = boto3.resource(
        'dynamodb',
        region_name='us-east-1',
        aws_access_key_id='testing',
        aws_secret_access_key='testing'
    )
    
    # Create Users table
    users_table = dynamodb.create_table(
        TableName='SilentCanary_Users',
        KeySchema=[
            {'AttributeName': 'user_id', 'KeyType': 'HASH'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'user_id', 'AttributeType': 'S'},
            {'AttributeName': 'email', 'AttributeType': 'S'},
            {'AttributeName': 'username', 'AttributeType': 'S'}
        ],
        GlobalSecondaryIndexes=[
            {
                'IndexName': 'email-index',
                'KeySchema': [{'AttributeName': 'email', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
            },
            {
                'IndexName': 'username-index', 
                'KeySchema': [{'AttributeName': 'username', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
            }
        ],
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
    )
    
    # Create Canaries table
    canaries_table = dynamodb.create_table(
        TableName='SilentCanary_Canaries',
        KeySchema=[
            {'AttributeName': 'canary_id', 'KeyType': 'HASH'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'canary_id', 'AttributeType': 'S'},
            {'AttributeName': 'user_id', 'AttributeType': 'S'},
            {'AttributeName': 'token', 'AttributeType': 'S'}
        ],
        GlobalSecondaryIndexes=[
            {
                'IndexName': 'user-id-index',
                'KeySchema': [{'AttributeName': 'user_id', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
            },
            {
                'IndexName': 'token-index',
                'KeySchema': [{'AttributeName': 'token', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
            }
        ],
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
    )
    
    # Create Canary Logs table
    logs_table = dynamodb.create_table(
        TableName='SilentCanary_CanaryLogs',
        KeySchema=[
            {'AttributeName': 'log_id', 'KeyType': 'HASH'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'log_id', 'AttributeType': 'S'},
            {'AttributeName': 'canary_id', 'AttributeType': 'S'},
            {'AttributeName': 'timestamp', 'AttributeType': 'S'}
        ],
        GlobalSecondaryIndexes=[
            {
                'IndexName': 'canary-id-timestamp-index',
                'KeySchema': [
                    {'AttributeName': 'canary_id', 'KeyType': 'HASH'},
                    {'AttributeName': 'timestamp', 'KeyType': 'RANGE'}
                ],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
            }
        ],
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
    )
    
    # Wait for tables to be active
    users_table.wait_until_exists()
    canaries_table.wait_until_exists() 
    logs_table.wait_until_exists()
    
    # Patch the models module to use our test tables
    import models
    original_users_table = models.users_table
    original_canaries_table = models.canaries_table
    original_canary_logs_table = models.canary_logs_table
    
    models.users_table = users_table
    models.canaries_table = canaries_table  
    models.canary_logs_table = logs_table
    
    yield {
        'users': users_table,
        'canaries': canaries_table,
        'logs': logs_table
    }
    
    # Restore original tables after test
    models.users_table = original_users_table
    models.canaries_table = original_canaries_table
    models.canary_logs_table = original_canary_logs_table

@pytest.fixture
def flask_app(dynamodb_tables):
    """Flask application configured for testing"""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['MAIL_SUPPRESS_SEND'] = True
    
    # Create app context
    with app.app_context():
        yield app

@pytest.fixture
def client(flask_app):
    """Flask test client"""
    return flask_app.test_client()

@pytest.fixture
def test_user(dynamodb_tables):
    """Create a test user"""
    user = User(
        username='testuser',
        email='test@example.com',
        user_timezone='UTC'
    )
    user.set_password('testpassword123')
    user.save()
    return user

@pytest.fixture
def test_canary(dynamodb_tables, test_user):
    """Create a test canary"""
    canary = Canary(
        name='Test Canary',
        user_id=test_user.user_id,
        interval_minutes=60,
        grace_minutes=5,
        alert_type='email',
        alert_email='alert@example.com'
    )
    canary.save()
    return canary

@pytest.fixture
def authenticated_client(client, test_user):
    """Client with authenticated user"""
    with client.session_transaction() as sess:
        sess['_user_id'] = test_user.user_id
        sess['_fresh'] = True
    return client

@pytest.fixture
def test_log_entries(dynamodb_tables, test_canary):
    """Create test log entries"""
    logs = []
    base_time = datetime.now(timezone.utc)
    
    # Create ping log
    ping_log = CanaryLog(
        canary_id=test_canary.canary_id,
        event_type='ping',
        status='success',
        message='Test ping',
        source_ip='127.0.0.1',
        user_agent='Test Agent'
    )
    ping_log.save()
    logs.append(ping_log)
    
    # Create miss log
    miss_log = CanaryLog(
        canary_id=test_canary.canary_id,
        event_type='miss',
        status='failed',
        message='Test miss'
    )
    miss_log.save()
    logs.append(miss_log)
    
    return logs

@pytest.fixture(autouse=True)
def cleanup_env():
    """Clean up environment variables after each test"""
    # Store original value
    original_value = os.environ.get('DYNAMODB_LOCAL')
    yield
    # Restore original value or remove if it didn't exist
    if original_value is not None:
        os.environ['DYNAMODB_LOCAL'] = original_value
    elif 'DYNAMODB_LOCAL' in os.environ:
        del os.environ['DYNAMODB_LOCAL']