"""
DynamoDB models for SilentCanary
"""

import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import uuid
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import pytz
import os
from dotenv import load_dotenv

load_dotenv()

def get_dynamodb_resource():
    """Get DynamoDB resource - local or AWS based on environment"""
    if os.getenv('DYNAMODB_LOCAL'):
        return boto3.resource(
            'dynamodb',
            endpoint_url='http://localhost:8000',
            region_name='us-east-1',
            aws_access_key_id='dummy',
            aws_secret_access_key='dummy'
        )
    else:
        return boto3.resource('dynamodb', region_name=os.getenv('AWS_REGION', 'us-east-1'))

# Get DynamoDB tables
dynamodb = get_dynamodb_resource()
users_table = dynamodb.Table('SilentCanary_Users')
canaries_table = dynamodb.Table('SilentCanary_Canaries')

class User:
    def __init__(self, user_id=None, username=None, email=None, password_hash=None, 
                 is_verified=False, timezone='UTC', created_at=None):
        self.user_id = user_id or str(uuid.uuid4())
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_verified = is_verified
        self.timezone = timezone
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password"""
        return check_password_hash(self.password_hash, password)
    
    def localize_datetime(self, dt):
        """Convert UTC datetime to user's local timezone"""
        if not dt:
            return None
        
        # Handle both datetime objects and ISO strings
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        user_tz = pytz.timezone(self.timezone)
        return dt.astimezone(user_tz)
    
    def save(self):
        """Save user to DynamoDB"""
        try:
            users_table.put_item(
                Item={
                    'user_id': self.user_id,
                    'username': self.username,
                    'email': self.email,
                    'password_hash': self.password_hash,
                    'is_verified': self.is_verified,
                    'timezone': self.timezone,
                    'created_at': self.created_at
                }
            )
            return True
        except ClientError as e:
            print(f"Error saving user: {e}")
            return False
    
    @staticmethod
    def get_by_id(user_id):
        """Get user by ID"""
        try:
            response = users_table.get_item(Key={'user_id': user_id})
            if 'Item' in response:
                item = response['Item']
                return User(
                    user_id=item['user_id'],
                    username=item['username'],
                    email=item['email'],
                    password_hash=item['password_hash'],
                    is_verified=item.get('is_verified', False),
                    timezone=item.get('timezone', 'UTC'),
                    created_at=item['created_at']
                )
            return None
        except ClientError as e:
            print(f"Error getting user by ID: {e}")
            return None
    
    @staticmethod
    def get_by_email(email):
        """Get user by email"""
        try:
            response = users_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )
            if response['Items']:
                item = response['Items'][0]
                return User(
                    user_id=item['user_id'],
                    username=item['username'],
                    email=item['email'],
                    password_hash=item['password_hash'],
                    is_verified=item.get('is_verified', False),
                    timezone=item.get('timezone', 'UTC'),
                    created_at=item['created_at']
                )
            return None
        except ClientError as e:
            print(f"Error getting user by email: {e}")
            return None
    
    @staticmethod
    def get_by_username(username):
        """Get user by username"""
        try:
            response = users_table.query(
                IndexName='username-index',
                KeyConditionExpression=Key('username').eq(username)
            )
            if response['Items']:
                item = response['Items'][0]
                return User(
                    user_id=item['user_id'],
                    username=item['username'],
                    email=item['email'],
                    password_hash=item['password_hash'],
                    is_verified=item.get('is_verified', False),
                    timezone=item.get('timezone', 'UTC'),
                    created_at=item['created_at']
                )
            return None
        except ClientError as e:
            print(f"Error getting user by username: {e}")
            return None

    # Flask-Login required methods
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return True
    
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return self.user_id

class Canary:
    def __init__(self, canary_id=None, name=None, user_id=None, interval_minutes=60, 
                 grace_minutes=5, token=None, status='waiting', is_active=True, 
                 alert_type='email', alert_email=None, slack_webhook=None, 
                 created_at=None, last_checkin=None, next_expected=None):
        self.canary_id = canary_id or str(uuid.uuid4())
        self.name = name
        self.user_id = user_id
        # Convert Decimal to int for DynamoDB compatibility
        self.interval_minutes = int(interval_minutes) if interval_minutes is not None else 60
        self.grace_minutes = int(grace_minutes) if grace_minutes is not None else 5
        self.token = token or str(uuid.uuid4())
        self.status = status
        self.is_active = bool(is_active) if is_active is not None else True
        self.alert_type = alert_type
        self.alert_email = alert_email
        self.slack_webhook = slack_webhook
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.last_checkin = last_checkin
        self.next_expected = next_expected
    
    def checkin(self):
        """Record a check-in"""
        now = datetime.now(timezone.utc)
        self.last_checkin = now.isoformat()
        self.next_expected = (now + timedelta(minutes=int(self.interval_minutes))).isoformat()
        self.status = 'healthy'
        self.save()
    
    def is_overdue(self):
        """Check if canary is overdue"""
        if not self.next_expected:
            return False
        
        # Parse next_expected from ISO string
        if isinstance(self.next_expected, str):
            next_expected_dt = datetime.fromisoformat(self.next_expected.replace('Z', '+00:00'))
        else:
            next_expected_dt = self.next_expected
        
        if next_expected_dt.tzinfo is None:
            next_expected_dt = next_expected_dt.replace(tzinfo=timezone.utc)
        
        grace_period = timedelta(minutes=int(self.grace_minutes))
        return datetime.now(timezone.utc) > (next_expected_dt + grace_period)
    
    def save(self):
        """Save canary to DynamoDB"""
        try:
            canaries_table.put_item(
                Item={
                    'canary_id': self.canary_id,
                    'name': self.name,
                    'user_id': self.user_id,
                    'interval_minutes': self.interval_minutes,
                    'grace_minutes': self.grace_minutes,
                    'token': self.token,
                    'status': self.status,
                    'is_active': self.is_active,
                    'alert_type': self.alert_type,
                    'alert_email': self.alert_email,
                    'slack_webhook': self.slack_webhook,
                    'created_at': self.created_at,
                    'last_checkin': self.last_checkin,
                    'next_expected': self.next_expected
                }
            )
            return True
        except ClientError as e:
            print(f"Error saving canary: {e}")
            return False
    
    def delete(self):
        """Delete canary from DynamoDB"""
        try:
            canaries_table.delete_item(Key={'canary_id': self.canary_id})
            return True
        except ClientError as e:
            print(f"Error deleting canary: {e}")
            return False
    
    @staticmethod
    def get_by_id(canary_id):
        """Get canary by ID"""
        try:
            response = canaries_table.get_item(Key={'canary_id': canary_id})
            if 'Item' in response:
                item = response['Item']
                return Canary(
                    canary_id=item['canary_id'],
                    name=item['name'],
                    user_id=item['user_id'],
                    interval_minutes=int(item['interval_minutes']),
                    grace_minutes=int(item['grace_minutes']),
                    token=item['token'],
                    status=item['status'],
                    is_active=bool(item['is_active']),
                    alert_type=item.get('alert_type', 'email'),
                    alert_email=item.get('alert_email'),
                    slack_webhook=item.get('slack_webhook'),
                    created_at=item['created_at'],
                    last_checkin=item.get('last_checkin'),
                    next_expected=item.get('next_expected')
                )
            return None
        except ClientError as e:
            print(f"Error getting canary by ID: {e}")
            return None
    
    @staticmethod
    def get_by_token(token):
        """Get canary by token"""
        try:
            response = canaries_table.query(
                IndexName='token-index',
                KeyConditionExpression=Key('token').eq(token)
            )
            if response['Items']:
                item = response['Items'][0]
                return Canary(
                    canary_id=item['canary_id'],
                    name=item['name'],
                    user_id=item['user_id'],
                    interval_minutes=int(item['interval_minutes']),
                    grace_minutes=int(item['grace_minutes']),
                    token=item['token'],
                    status=item['status'],
                    is_active=bool(item['is_active']),
                    alert_type=item.get('alert_type', 'email'),
                    alert_email=item.get('alert_email'),
                    slack_webhook=item.get('slack_webhook'),
                    created_at=item['created_at'],
                    last_checkin=item.get('last_checkin'),
                    next_expected=item.get('next_expected')
                )
            return None
        except ClientError as e:
            print(f"Error getting canary by token: {e}")
            return None
    
    @staticmethod
    def get_by_user_id(user_id):
        """Get all canaries for a user"""
        try:
            response = canaries_table.query(
                IndexName='user-id-index',
                KeyConditionExpression=Key('user_id').eq(user_id)
            )
            canaries = []
            for item in response['Items']:
                canaries.append(Canary(
                    canary_id=item['canary_id'],
                    name=item['name'],
                    user_id=item['user_id'],
                    interval_minutes=int(item['interval_minutes']),
                    grace_minutes=int(item['grace_minutes']),
                    token=item['token'],
                    status=item['status'],
                    is_active=bool(item['is_active']),
                    alert_type=item.get('alert_type', 'email'),
                    alert_email=item.get('alert_email'),
                    slack_webhook=item.get('slack_webhook'),
                    created_at=item['created_at'],
                    last_checkin=item.get('last_checkin'),
                    next_expected=item.get('next_expected')
                ))
            return canaries
        except ClientError as e:
            print(f"Error getting canaries by user ID: {e}")
            return []
    
    @staticmethod
    def get_active_canaries():
        """Get all active canaries for monitoring"""
        try:
            response = canaries_table.scan(
                FilterExpression=Attr('is_active').eq(True)
            )
            canaries = []
            for item in response['Items']:
                canaries.append(Canary(
                    canary_id=item['canary_id'],
                    name=item['name'],
                    user_id=item['user_id'],
                    interval_minutes=int(item['interval_minutes']),
                    grace_minutes=int(item['grace_minutes']),
                    token=item['token'],
                    status=item['status'],
                    is_active=bool(item['is_active']),
                    alert_type=item.get('alert_type', 'email'),
                    alert_email=item.get('alert_email'),
                    slack_webhook=item.get('slack_webhook'),
                    created_at=item['created_at'],
                    last_checkin=item.get('last_checkin'),
                    next_expected=item.get('next_expected')
                ))
            return canaries
        except ClientError as e:
            print(f"Error getting active canaries: {e}")
            return []