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
from decimal import Decimal
from dotenv import load_dotenv

load_dotenv()

def get_dynamodb_resource():
    """Get DynamoDB resource - local or AWS based on environment"""
    if os.getenv('DYNAMODB_LOCAL'):
        return boto3.resource(
            'dynamodb',
            endpoint_url='http://localhost:8000',
            region_name='ca-central-1',
            aws_access_key_id='dummy',
            aws_secret_access_key='dummy'
        )
    else:
        return boto3.resource('dynamodb', region_name=os.getenv('AWS_REGION', 'ca-central-1'))

# Get DynamoDB tables
dynamodb = get_dynamodb_resource()
users_table = dynamodb.Table('SilentCanary_Users')
canaries_table = dynamodb.Table('SilentCanary_Canaries')
canary_logs_table = dynamodb.Table('SilentCanary_CanaryLogs')
smart_alerts_table = dynamodb.Table('SilentCanary_SmartAlerts')

class User:
    def __init__(self, user_id=None, username=None, email=None, password_hash=None, 
                 is_verified=False, user_timezone='UTC', created_at=None, last_login=None, api_key=None):
        self.user_id = user_id or str(uuid.uuid4())
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_verified = is_verified
        self.timezone = user_timezone or 'UTC'  # Default to UTC if None
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.last_login = last_login
        self.api_key = api_key
    
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
        
        # Default to UTC if timezone is None or invalid
        timezone_str = self.timezone or 'UTC'
        try:
            user_tz = pytz.timezone(timezone_str)
        except pytz.exceptions.UnknownTimeZoneError:
            user_tz = pytz.UTC
        
        return dt.astimezone(user_tz)
    
    def generate_api_key(self):
        """Generate a new API key for this user"""
        print(f"DEBUG: Generating API key for user {self.user_id}")
        import base64
        secret = f"secret_{self.user_id[:8]}"
        credentials = f"{self.user_id}:{secret}"
        self.api_key = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        print(f"DEBUG: Generated API key: {self.api_key}")
        result = self.save()
        print(f"DEBUG: Save result: {result}")
        return result
    
    def regenerate_api_key(self):
        """Regenerate the API key"""
        return self.generate_api_key()
    
    def delete_api_key(self):
        """Delete the API key"""
        self.api_key = None
        return self.save()
    
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
                
            if self.api_key is not None:
                item['api_key'] = self.api_key
            
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
                    last_login=item.get('last_login'),
                    api_key=item.get('api_key')
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
                    last_login=item.get('last_login'),
                    api_key=item.get('api_key')
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
                    last_login=item.get('last_login'),
                    api_key=item.get('api_key')
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
                 created_at=None, last_checkin=None, next_expected=None, sla_threshold=99.9, 
                 tags=None):
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
        self.sla_threshold = Decimal(str(sla_threshold)) if sla_threshold is not None else Decimal('99.9')
        self.tags = tags or []
    
    def checkin(self, source_ip=None, user_agent=None, custom_message=None):
        """Record a check-in"""
        now = datetime.now(timezone.utc)
        was_failed = self.status == 'failed'
        
        self.last_checkin = now.isoformat()
        self.next_expected = (now + timedelta(minutes=int(self.interval_minutes))).isoformat()
        self.status = 'healthy'
        self.save()
        
        # Log the check-in event
        CanaryLog.log_ping(self.canary_id, 'success', source_ip, user_agent, custom_message)
        
        # Log recovery if canary was previously failed
        if was_failed:
            recovery_msg = f"Canary recovered after missing check-ins{': ' + custom_message if custom_message else ''}"
            CanaryLog.log_recovery(self.canary_id, recovery_msg)
        
        # Trigger smart alert pattern learning if enabled (async to avoid blocking check-in)
        try:
            smart_alert = SmartAlert.get_by_canary_id(self.canary_id)
            if smart_alert and smart_alert.is_enabled:
                # Always update patterns after every 3rd check-in for real-time learning
                logs_result = CanaryLog.get_by_canary_id(self.canary_id, limit=3)
                recent_checkins = [log for log in logs_result['logs'] if log.event_type == 'ping' and log.status == 'success']
                
                # Update patterns every 3 successful check-ins or if time-based update is due
                should_update = (len(recent_checkins) >= 3) or smart_alert.should_update_patterns()
                
                if should_update:
                    # Update patterns in background (don't block the check-in response)
                    import threading
                    def update_patterns():
                        try:
                            smart_alert.learn_patterns()
                            print(f"✅ Background pattern update completed for canary {self.canary_id}")
                        except Exception as e:
                            print(f"Background pattern update failed for {self.canary_id}: {e}")
                    
                    thread = threading.Thread(target=update_patterns)
                    thread.daemon = True
                    thread.start()
                    print(f"🧠 Triggered background pattern update for canary {self.canary_id}")
        except Exception as e:
            print(f"Error checking smart alert patterns for {self.canary_id}: {e}")
    
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
                    'sla_threshold': self.sla_threshold,
                    'tags': self.tags
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
            
            is_breach = current_uptime < float(self.sla_threshold)
            
            return {
                'is_breach': is_breach,
                'current_uptime': current_uptime,
                'sla_threshold': float(self.sla_threshold),
                'difference': current_uptime - float(self.sla_threshold),
                'days_analyzed': days,
                'total_incidents': uptime_stats['total_incidents'],
                'downtime_seconds': uptime_stats['downtime_seconds']
            }
        except Exception as e:
            print(f"Error checking SLA breach: {e}")
            return {
                'is_breach': False,
                'current_uptime': 0,
                'sla_threshold': float(self.sla_threshold),
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
                    sla_threshold=item.get('sla_threshold', Decimal('99.9')),
                    tags=item.get('tags', [])
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
                    sla_threshold=item.get('sla_threshold', Decimal('99.9'))
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
                    sla_threshold=item.get('sla_threshold', Decimal('99.9')),
                    tags=item.get('tags', [])
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
                    sla_threshold=item.get('sla_threshold', Decimal('99.9')),
                    tags=item.get('tags', [])
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
    def log_ping(canary_id, status='success', source_ip=None, user_agent=None, custom_message=None):
        """Log a ping event"""
        if custom_message:
            message = f"Successful check-in: {custom_message}" if status == 'success' else f"Failed check-in: {custom_message}"
        else:
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
    
    @staticmethod
    def log_deployment(canary_id, deployment_info):
        """Log a deployment event with metadata"""
        import json
        message = f"Deployment: {deployment_info.get('event', 'deployment')}"
        if deployment_info.get('commit_sha'):
            message += f" - {deployment_info['commit_sha'][:8]}"
        if deployment_info.get('deployment_id'):
            message += f" (ID: {deployment_info['deployment_id']})"
        
        log = CanaryLog(
            canary_id=canary_id,
            event_type='deployment',
            status='success',
            message=message
        )
        
        # Store deployment metadata in user_agent field as JSON
        # (could add a proper metadata field to the model later)
        log.user_agent = json.dumps(deployment_info)
        
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


class SmartAlert:
    """Smart alerting with ML-based anomaly detection for irregular check-in patterns"""
    
    def __init__(self, smart_alert_id=None, canary_id=None, user_id=None, is_enabled=True,
                 learning_period_days=7, sensitivity=0.8, created_at=None, 
                 pattern_data=None, last_analysis=None):
        self.smart_alert_id = smart_alert_id or str(uuid.uuid4())
        self.canary_id = canary_id
        self.user_id = user_id
        self.is_enabled = is_enabled
        self.learning_period_days = learning_period_days  # How many days to learn patterns
        self.sensitivity = Decimal(str(sensitivity))  # 0.5-1.0, higher = more sensitive
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.pattern_data = pattern_data or {}  # Stores learned patterns
        self.last_analysis = last_analysis
    
    def save(self):
        """Save smart alert configuration to DynamoDB"""
        try:
            smart_alerts_table.put_item(
                Item={
                    'smart_alert_id': self.smart_alert_id,
                    'canary_id': self.canary_id,
                    'user_id': self.user_id,
                    'is_enabled': self.is_enabled,
                    'learning_period_days': self.learning_period_days,
                    'sensitivity': self.sensitivity,
                    'created_at': self.created_at,
                    'pattern_data': self.pattern_data,
                    'last_analysis': self.last_analysis
                }
            )
            return True
        except ClientError as e:
            print(f"Error saving smart alert: {e}")
            return False
    
    def delete(self):
        """Delete smart alert from DynamoDB"""
        try:
            smart_alerts_table.delete_item(Key={'smart_alert_id': self.smart_alert_id})
            return True
        except ClientError as e:
            print(f"Error deleting smart alert: {e}")
            return False
    
    @staticmethod
    def get_by_canary_id(canary_id):
        """Get smart alert configuration for a canary"""
        try:
            response = smart_alerts_table.query(
                IndexName='canary-id-index',
                KeyConditionExpression=Key('canary_id').eq(canary_id)
            )
            if response['Items']:
                item = response['Items'][0]  # Should only be one per canary
                return SmartAlert(
                    smart_alert_id=item['smart_alert_id'],
                    canary_id=item['canary_id'],
                    user_id=item['user_id'],
                    is_enabled=item.get('is_enabled', True),
                    learning_period_days=int(item.get('learning_period_days', 7)),
                    sensitivity=item.get('sensitivity', Decimal('0.8')),
                    created_at=item['created_at'],
                    pattern_data=item.get('pattern_data', {}),
                    last_analysis=item.get('last_analysis')
                )
            return None
        except ClientError as e:
            print(f"Error getting smart alert: {e}")
            return None
    
    def learn_patterns(self):
        """Analyze check-in patterns and build ML model for anomaly detection"""
        import statistics
        from collections import defaultdict
        
        try:
            # Get canary to analyze
            canary = Canary.get_by_id(self.canary_id)
            if not canary:
                return False
            
            # Get check-in logs for learning period
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=self.learning_period_days)
            
            logs_result = CanaryLog.get_by_canary_id(self.canary_id, limit=1000)
            logs = logs_result['logs']
            
            # Filter to successful check-ins within learning period
            checkin_times = []
            for log in logs:
                if log.event_type == 'ping' and log.status == 'success':
                    log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                    if start_time <= log_time <= end_time:
                        checkin_times.append(log_time)
            
            if len(checkin_times) < 3:  # Need minimum data
                return False
            
            # Analyze patterns by day of week and hour
            hourly_patterns = defaultdict(list)
            daily_patterns = defaultdict(list)
            interval_patterns = []
            
            checkin_times.sort()
            
            for i, checkin_time in enumerate(checkin_times):
                hour = checkin_time.hour
                day = checkin_time.weekday()
                
                hourly_patterns[hour].append(1)
                daily_patterns[day].append(1)
                
                # Calculate intervals between check-ins
                if i > 0:
                    interval = (checkin_time - checkin_times[i-1]).total_seconds() / 60
                    interval_patterns.append(interval)
            
            # Calculate statistics for patterns
            pattern_data = {
                'hourly_distribution': {str(h): len(hourly_patterns[h]) for h in range(24)},
                'daily_distribution': {str(d): len(daily_patterns[d]) for d in range(7)},
                'avg_interval': statistics.mean(interval_patterns) if interval_patterns else canary.interval_minutes,
                'interval_std': statistics.stdev(interval_patterns) if len(interval_patterns) > 1 else 0,
                'total_checkins': len(checkin_times),
                'learning_start': start_time.isoformat(),
                'learning_end': end_time.isoformat(),
                'expected_interval': canary.interval_minutes
            }
            
            self.pattern_data = pattern_data
            self.last_analysis = datetime.now(timezone.utc).isoformat()
            
            return self.save()
            
        except Exception as e:
            print(f"Error learning patterns: {e}")
            return False
    
    def is_anomaly(self, current_time=None):
        """Check if current timing represents an anomaly based on learned patterns"""
        if not self.pattern_data or not self.is_enabled:
            return False
        
        current_time = current_time or datetime.now(timezone.utc)
        
        # Get canary and its last check-in
        canary = Canary.get_by_id(self.canary_id)
        if not canary or not canary.last_checkin:
            return False
        
        last_checkin = datetime.fromisoformat(canary.last_checkin.replace('Z', '+00:00'))
        time_since_last = (current_time - last_checkin).total_seconds() / 60
        
        # Check if interval is significantly different from learned pattern
        expected_interval = self.pattern_data.get('avg_interval', canary.interval_minutes)
        interval_std = self.pattern_data.get('interval_std', 0)
        
        # Define anomaly threshold based on sensitivity
        # Higher sensitivity = lower threshold for detecting anomalies
        sensitivity_factor = float(self.sensitivity)
        threshold_multiplier = 2.0 - sensitivity_factor  # 1.0 to 1.5 range
        
        if interval_std > 0:
            threshold = expected_interval + (interval_std * threshold_multiplier)
        else:
            # If no variance in historical data, use a percentage-based threshold
            threshold = expected_interval * (1 + (0.5 * threshold_multiplier))
        
        # Check hour/day patterns for additional context
        hour_anomaly = self._check_hour_anomaly(current_time)
        day_anomaly = self._check_day_anomaly(current_time)
        
        # Combine different anomaly indicators
        time_anomaly = time_since_last > threshold
        pattern_anomaly = hour_anomaly or day_anomaly
        
        return time_anomaly or (pattern_anomaly and sensitivity_factor > 0.7)
    
    def _check_hour_anomaly(self, current_time):
        """Check if the current hour is unusual for check-ins"""
        if 'hourly_distribution' not in self.pattern_data:
            return False
        
        current_hour = str(current_time.hour)
        hour_counts = self.pattern_data['hourly_distribution']
        total_checkins = self.pattern_data.get('total_checkins', 1)
        
        # Calculate expected frequency for this hour
        hour_frequency = hour_counts.get(current_hour, 0) / total_checkins
        
        # Consider it anomalous if this hour has < 10% of normal activity
        return hour_frequency < 0.1
    
    def _check_day_anomaly(self, current_time):
        """Check if the current day is unusual for check-ins"""
        if 'daily_distribution' not in self.pattern_data:
            return False
        
        current_day = str(current_time.weekday())
        day_counts = self.pattern_data['daily_distribution']
        total_checkins = self.pattern_data.get('total_checkins', 1)
        
        # Calculate expected frequency for this day
        day_frequency = day_counts.get(current_day, 0) / total_checkins
        
        # Consider it anomalous if this day has < 5% of normal activity
        return day_frequency < 0.05
    
    def should_update_patterns(self):
        """Determine if patterns should be updated based on time and new data availability"""
        if not self.is_enabled:
            return False
        
        # Update patterns frequently for real-time learning
        if self.last_analysis:
            try:
                last_analysis_time = datetime.fromisoformat(self.last_analysis.replace('Z', '+00:00'))
                time_since_analysis = datetime.now(timezone.utc) - last_analysis_time
                
                # Update every 5 minutes if patterns exist, or every 2 minutes if no patterns yet
                update_interval = timedelta(minutes=5) if self.pattern_data else timedelta(minutes=2)
                
                return time_since_analysis > update_interval
            except:
                return True  # If we can't parse the time, update patterns
        else:
            return True  # Never analyzed before, so update
    
    def get_learning_progress(self):
        """Get learning progress information for display"""
        try:
            # Get canary to analyze
            canary = Canary.get_by_id(self.canary_id)
            if not canary:
                return {
                    'status': 'error',
                    'message': 'Canary not found',
                    'progress': 0
                }
            
            # Get check-in logs for learning period
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=self.learning_period_days)
            
            logs_result = CanaryLog.get_by_canary_id(self.canary_id, limit=1000)
            logs = logs_result['logs']
            
            # Filter to successful check-ins within learning period
            checkin_times = []
            for log in logs:
                if log.event_type == 'ping' and log.status == 'success':
                    log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                    if start_time <= log_time <= end_time:
                        checkin_times.append(log_time)
            
            total_checkins = len(checkin_times)
            min_required = 3
            
            # Calculate progress percentage (more granular for better visual feedback)
            if total_checkins == 0:
                progress = 0
            elif total_checkins < min_required:
                progress = (total_checkins / min_required) * 90  # Show up to 90% before patterns are ready
            else:
                progress = 100
            
            if total_checkins >= min_required:
                status = 'ready'
                message = f'Patterns learned from {total_checkins} check-ins'
            elif total_checkins > 0:
                status = 'learning'
                message = f'Learning: {total_checkins}/{min_required} check-ins needed'
            else:
                status = 'waiting'
                message = 'Waiting for check-ins to start learning'
            
            # Calculate pattern confidence if patterns exist
            confidence = 0
            if self.pattern_data and 'total_checkins' in self.pattern_data:
                pattern_checkins = self.pattern_data.get('total_checkins', 0)
                # Confidence increases with more data, maxes out at 20 check-ins for faster feedback
                confidence = min(100, (pattern_checkins / 20) * 100)
            
            return {
                'status': status,
                'message': message,
                'progress': round(progress, 1),
                'total_checkins': total_checkins,
                'min_required': min_required,
                'confidence': round(confidence, 1),
                'last_updated': self.last_analysis,
                'learning_period_days': self.learning_period_days
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Error calculating progress: {e}',
                'progress': 0,
                'confidence': 0
            }