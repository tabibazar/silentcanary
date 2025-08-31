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
                 is_verified=False, user_timezone='UTC', created_at=None, last_login=None):
        self.user_id = user_id or str(uuid.uuid4())
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_verified = is_verified
        self.timezone = user_timezone
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.last_login = last_login
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password"""
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Update last login timestamp to now"""
        from datetime import datetime, timezone
        self.last_login = datetime.now(timezone.utc).isoformat()
        return self.save()
    
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
            item = {
                'user_id': self.user_id,
                'username': self.username,
                'email': self.email,
                'password_hash': self.password_hash,
                'is_verified': self.is_verified,
                'timezone': self.timezone,
                'created_at': self.created_at
            }
            
            if self.last_login is not None:
                item['last_login'] = self.last_login
            
            users_table.put_item(Item=item)
            return True
        except ClientError as e:
            print(f"Error saving user: {e}")
            return False
    
    def delete(self):
        """Delete user from DynamoDB"""
        try:
            users_table.delete_item(Key={'user_id': self.user_id})
            return True
        except ClientError as e:
            print(f"Error deleting user: {e}")
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
                    created_at=item['created_at'],
                    last_login=item.get('last_login')
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
                    created_at=item['created_at'],
                    last_login=item.get('last_login')
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
                    created_at=item['created_at'],
                    last_login=item.get('last_login')
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
                 created_at=None, last_checkin=None, next_expected=None, sla_threshold=99.9):
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
        self.sla_threshold = float(sla_threshold) if sla_threshold is not None else 99.9
    
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
                    'next_expected': self.next_expected,
                    'sla_threshold': self.sla_threshold
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
    
    def get_uptime_stats(self, days=30):
        """Calculate uptime statistics for the past N days"""
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get all logs for this canary in the time period
            logs_result = CanaryLog.get_by_canary_id(self.canary_id, limit=1000)
            logs = logs_result['logs']
            
            # Filter logs to the time period
            period_logs = []
            for log in logs:
                log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                if start_time <= log_time <= end_time:
                    period_logs.append(log)
            
            # Calculate total time period in seconds
            total_seconds = (end_time - start_time).total_seconds()
            
            # Calculate downtime
            downtime_seconds = 0
            failure_start = None
            
            for log in sorted(period_logs, key=lambda x: x.timestamp):
                log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                
                if log.event_type == 'miss' and failure_start is None:
                    failure_start = log_time
                elif log.event_type in ['ping', 'recovery'] and failure_start is not None:
                    downtime_seconds += (log_time - failure_start).total_seconds()
                    failure_start = None
            
            # If still in failure state, count downtime to now
            if failure_start is not None:
                downtime_seconds += (end_time - failure_start).total_seconds()
            
            # Calculate uptime percentage
            uptime_seconds = total_seconds - downtime_seconds
            uptime_percentage = (uptime_seconds / total_seconds * 100) if total_seconds > 0 else 100
            
            return {
                'uptime_percentage': round(uptime_percentage, 2),
                'downtime_seconds': int(downtime_seconds),
                'total_incidents': len([log for log in period_logs if log.event_type == 'miss']),
                'days_analyzed': days,
                'start_date': start_time.isoformat(),
                'end_date': end_time.isoformat()
            }
        except Exception as e:
            print(f"Error calculating uptime stats: {e}")
            return {
                'uptime_percentage': 0,
                'downtime_seconds': 0,
                'total_incidents': 0,
                'days_analyzed': days,
                'start_date': start_time.isoformat() if 'start_time' in locals() else None,
                'end_date': end_time.isoformat() if 'end_time' in locals() else None
            }
    
    def get_downtime_incidents(self, days=30):
        """Get detailed downtime incidents for the past N days"""
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get all logs for this canary in the time period
            logs_result = CanaryLog.get_by_canary_id(self.canary_id, limit=1000)
            logs = logs_result['logs']
            
            # Filter logs to the time period
            period_logs = []
            for log in logs:
                log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                if start_time <= log_time <= end_time:
                    period_logs.append(log)
            
            # Group into incidents
            incidents = []
            current_incident = None
            
            for log in sorted(period_logs, key=lambda x: x.timestamp):
                log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                
                if log.event_type == 'miss' and current_incident is None:
                    current_incident = {
                        'start_time': log_time,
                        'end_time': None,
                        'duration_seconds': None,
                        'resolved': False
                    }
                elif log.event_type in ['ping', 'recovery'] and current_incident is not None:
                    current_incident['end_time'] = log_time
                    current_incident['duration_seconds'] = int((log_time - current_incident['start_time']).total_seconds())
                    current_incident['resolved'] = True
                    incidents.append(current_incident)
                    current_incident = None
            
            # Handle ongoing incident
            if current_incident is not None:
                current_incident['end_time'] = end_time
                current_incident['duration_seconds'] = int((end_time - current_incident['start_time']).total_seconds())
                current_incident['resolved'] = False
                incidents.append(current_incident)
            
            return incidents
        except Exception as e:
            print(f"Error getting downtime incidents: {e}")
            return []
    
    def get_trend_analysis(self, days=30):
        """Analyze failure patterns by time of day and day of week"""
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get all failure logs for this canary
            logs_result = CanaryLog.get_by_canary_id(self.canary_id, limit=1000)
            logs = logs_result['logs']
            
            failure_logs = []
            for log in logs:
                if log.event_type == 'miss':
                    log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                    if start_time <= log_time <= end_time:
                        failure_logs.append(log_time)
            
            # Analyze by hour of day
            hourly_failures = {}
            for hour in range(24):
                hourly_failures[hour] = 0
            
            # Analyze by day of week (0=Monday, 6=Sunday)
            daily_failures = {}
            for day in range(7):
                daily_failures[day] = 0
            
            for failure_time in failure_logs:
                hour = failure_time.hour
                day = failure_time.weekday()
                hourly_failures[hour] += 1
                daily_failures[day] += 1
            
            day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            
            return {
                'hourly_failures': hourly_failures,
                'daily_failures': {day_names[k]: v for k, v in daily_failures.items()},
                'total_failures': len(failure_logs),
                'analysis_period_days': days
            }
        except Exception as e:
            print(f"Error getting trend analysis: {e}")
            return {
                'hourly_failures': {},
                'daily_failures': {},
                'total_failures': 0,
                'analysis_period_days': days
            }
    
    def check_sla_breach(self, days=30):
        """Check if SLA has been breached in the given time period"""
        try:
            uptime_stats = self.get_uptime_stats(days)
            current_uptime = uptime_stats['uptime_percentage']
            
            is_breach = current_uptime < self.sla_threshold
            
            return {
                'is_breach': is_breach,
                'current_uptime': current_uptime,
                'sla_threshold': self.sla_threshold,
                'difference': current_uptime - self.sla_threshold,
                'days_analyzed': days,
                'total_incidents': uptime_stats['total_incidents'],
                'downtime_seconds': uptime_stats['downtime_seconds']
            }
        except Exception as e:
            print(f"Error checking SLA breach: {e}")
            return {
                'is_breach': False,
                'current_uptime': 0,
                'sla_threshold': self.sla_threshold,
                'difference': 0,
                'days_analyzed': days,
                'total_incidents': 0,
                'downtime_seconds': 0
            }
    
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
                    next_expected=item.get('next_expected'),
                    sla_threshold=item.get('sla_threshold', 99.9)
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
                    next_expected=item.get('next_expected'),
                    sla_threshold=item.get('sla_threshold', 99.9)
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
                    next_expected=item.get('next_expected'),
                    sla_threshold=item.get('sla_threshold', 99.9)
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
                    next_expected=item.get('next_expected'),
                    sla_threshold=item.get('sla_threshold', 99.9)
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