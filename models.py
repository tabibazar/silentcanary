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
canary_logs_table = dynamodb.Table('SilentCanary_CanaryLogs')

class User:
    def __init__(self, user_id=None, username=None, email=None, password_hash=None, 
                 is_verified=False, user_timezone='UTC', created_at=None):
        self.user_id = user_id or str(uuid.uuid4())
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_verified = is_verified
        self.timezone = user_timezone
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
                    user_timezone=item.get('timezone', 'UTC'),
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
                    user_timezone=item.get('timezone', 'UTC'),
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
                    user_timezone=item.get('timezone', 'UTC'),
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
        # Convert Decimal to int for DynamoDB compatibility and validate ranges
        if interval_minutes is not None:
            interval_val = int(interval_minutes)
            if interval_val < 1:
                raise ValueError("Interval minutes must be at least 1")
            self.interval_minutes = interval_val
        else:
            self.interval_minutes = 60
            
        if grace_minutes is not None:
            grace_val = int(grace_minutes)
            if grace_val < 0:
                raise ValueError("Grace period cannot be negative")
            self.grace_minutes = grace_val
        else:
            self.grace_minutes = 5
        self.token = token or str(uuid.uuid4())
        self.status = status
        self.is_active = bool(is_active) if is_active is not None else True
        self.alert_type = alert_type
        self.alert_email = alert_email
        self.slack_webhook = slack_webhook
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.last_checkin = last_checkin
        self.next_expected = next_expected
    
    def checkin(self, source_ip=None, user_agent=None):
        """Record a check-in"""
        now = datetime.now(timezone.utc)
        was_failed = self.status == 'failed'
        
        self.last_checkin = now.isoformat()
        self.next_expected = (now + timedelta(minutes=int(self.interval_minutes))).isoformat()
        self.status = 'healthy'
        self.save()
        
        # Log the check-in event
        CanaryLog.log_ping(self.canary_id, 'success', source_ip, user_agent)
        
        # Log recovery if canary was previously failed
        if was_failed:
            CanaryLog.log_recovery(self.canary_id)
    
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

class CanaryLog:
    def __init__(self, log_id=None, canary_id=None, event_type=None, timestamp=None, 
                 status=None, message=None, source_ip=None, user_agent=None,
                 email_sent_at=None, slack_sent_at=None, email_status=None, slack_status=None):
        self.log_id = log_id or str(uuid.uuid4())
        self.canary_id = canary_id
        self.event_type = event_type  # 'ping', 'miss', 'recovery'
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.status = status  # 'success', 'failed', 'late'
        self.message = message
        self.source_ip = source_ip
        self.user_agent = user_agent
        # Notification tracking fields
        self.email_sent_at = email_sent_at  # Timestamp when email was sent
        self.slack_sent_at = slack_sent_at  # Timestamp when Slack notification was sent
        self.email_status = email_status    # 'sent', 'failed', 'not_required'
        self.slack_status = slack_status    # 'sent', 'failed', 'not_required'
    
    def save(self):
        """Save log entry to DynamoDB"""
        try:
            item = {
                'log_id': self.log_id,
                'canary_id': self.canary_id,
                'event_type': self.event_type,
                'timestamp': self.timestamp,
                'status': self.status,
                'message': self.message,
                'source_ip': self.source_ip,
                'user_agent': self.user_agent
            }
            
            # Only include notification fields if they have values
            if self.email_sent_at:
                item['email_sent_at'] = self.email_sent_at
            if self.slack_sent_at:
                item['slack_sent_at'] = self.slack_sent_at
            if self.email_status:
                item['email_status'] = self.email_status
            if self.slack_status:
                item['slack_status'] = self.slack_status
                
            canary_logs_table.put_item(Item=item)
            return True
        except ClientError as e:
            print(f"Error saving canary log: {e}")
            return False
    
    @staticmethod
    def get_by_canary_id(canary_id, limit=50, last_evaluated_key=None):
        """Get paginated logs for a canary"""
        try:
            # Build query parameters
            query_params = {
                'IndexName': 'canary-id-timestamp-index',
                'KeyConditionExpression': Key('canary_id').eq(canary_id),
                'ScanIndexForward': False,  # Sort descending (newest first)
                'Limit': limit
            }
            
            if last_evaluated_key:
                query_params['ExclusiveStartKey'] = last_evaluated_key
            
            response = canary_logs_table.query(**query_params)
            
            logs = []
            for item in response['Items']:
                logs.append(CanaryLog(
                    log_id=item['log_id'],
                    canary_id=item['canary_id'],
                    event_type=item['event_type'],
                    timestamp=item['timestamp'],
                    status=item['status'],
                    message=item.get('message'),
                    source_ip=item.get('source_ip'),
                    user_agent=item.get('user_agent'),
                    email_sent_at=item.get('email_sent_at'),
                    slack_sent_at=item.get('slack_sent_at'),
                    email_status=item.get('email_status'),
                    slack_status=item.get('slack_status')
                ))
            
            return {
                'logs': logs,
                'last_evaluated_key': response.get('LastEvaluatedKey'),
                'has_more': 'LastEvaluatedKey' in response
            }
        except ClientError as e:
            print(f"Error getting canary logs: {e}")
            return {'logs': [], 'last_evaluated_key': None, 'has_more': False}
    
    @staticmethod
    def log_ping(canary_id, status='success', source_ip=None, user_agent=None):
        """Log a ping event"""
        message = 'Successful check-in' if status == 'success' else 'Failed check-in'
        log = CanaryLog(
            canary_id=canary_id,
            event_type='ping',
            status=status,
            message=message,
            source_ip=source_ip,
            user_agent=user_agent
        )
        return log.save()
    
    @staticmethod
    def log_miss(canary_id, message='Canary missed expected check-in'):
        """Log a missed check-in event"""
        log = CanaryLog(
            canary_id=canary_id,
            event_type='miss',
            status='failed',
            message=message
        )
        if log.save():
            return log
        return None
    
    @staticmethod
    def log_recovery(canary_id, message='Canary recovered after missing check-ins'):
        """Log a recovery event"""
        log = CanaryLog(
            canary_id=canary_id,
            event_type='recovery',
            status='success',
            message=message
        )
        return log.save()
    
    def update_email_notification(self, status, timestamp=None):
        """Update email notification status on this log entry"""
        self.email_status = status
        self.email_sent_at = timestamp or datetime.now(timezone.utc).isoformat()
        return self.save()
    
    def update_slack_notification(self, status, timestamp=None):
        """Update Slack notification status on this log entry"""
        self.slack_status = status
        self.slack_sent_at = timestamp or datetime.now(timezone.utc).isoformat()
        return self.save()
    
    @staticmethod
    def get_by_id(log_id):
        """Get a specific log entry by ID"""
        try:
            response = canary_logs_table.get_item(Key={'log_id': log_id})
            if 'Item' in response:
                item = response['Item']
                return CanaryLog(
                    log_id=item['log_id'],
                    canary_id=item['canary_id'],
                    event_type=item['event_type'],
                    timestamp=item['timestamp'],
                    status=item['status'],
                    message=item.get('message'),
                    source_ip=item.get('source_ip'),
                    user_agent=item.get('user_agent'),
                    email_sent_at=item.get('email_sent_at'),
                    slack_sent_at=item.get('slack_sent_at'),
                    email_status=item.get('email_status'),
                    slack_status=item.get('slack_status')
                )
            return None
        except ClientError as e:
            print(f"Error getting canary log: {e}")
            return None