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
api_keys_table = dynamodb.Table('SilentCanary_APIKeys')
subscriptions_table = dynamodb.Table('SilentCanary_Subscriptions')
api_usage_table = dynamodb.Table('SilentCanary_APIUsage')

class User:
    def __init__(self, user_id=None, username=None, email=None, password_hash=None, 
                 is_verified=False, user_timezone='UTC', created_at=None, last_login=None, api_key=None, 
                 anthropic_api_key=None, recaptcha_site_key=None, recaptcha_secret_key=None):
        self.user_id = user_id or str(uuid.uuid4())
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_verified = is_verified
        self.timezone = user_timezone or 'UTC'  # Default to UTC if None
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.last_login = last_login
        self.api_key = api_key
        self.anthropic_api_key = anthropic_api_key
        self.recaptcha_site_key = recaptcha_site_key
        self.recaptcha_secret_key = recaptcha_secret_key
    
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
            try:
                dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            except ValueError:
                # If string is not a valid datetime (e.g., error message), return as-is
                return dt
        
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
        import secrets
        # Security fix: Use cryptographically secure random generation with sc- prefix
        self.api_key = f"sc-{secrets.token_urlsafe(32)}"
        return self.save()
    
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
                
            if self.anthropic_api_key is not None:
                item['anthropic_api_key'] = self.anthropic_api_key
                
            if self.recaptcha_site_key is not None:
                item['recaptcha_site_key'] = self.recaptcha_site_key
                
            if self.recaptcha_secret_key is not None:
                item['recaptcha_secret_key'] = self.recaptcha_secret_key
            
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
                    api_key=item.get('api_key'),
                    anthropic_api_key=item.get('anthropic_api_key'),
                    recaptcha_site_key=item.get('recaptcha_site_key'),
                    recaptcha_secret_key=item.get('recaptcha_secret_key')
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
                    api_key=item.get('api_key'),
                    anthropic_api_key=item.get('anthropic_api_key'),
                    recaptcha_site_key=item.get('recaptcha_site_key'),
                    recaptcha_secret_key=item.get('recaptcha_secret_key')
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
                    api_key=item.get('api_key'),
                    anthropic_api_key=item.get('anthropic_api_key'),
                    recaptcha_site_key=item.get('recaptcha_site_key'),
                    recaptcha_secret_key=item.get('recaptcha_secret_key')
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


class ApiUsageLog:
    def __init__(self, log_id=None, user_id=None, api_type='anthropic', endpoint=None, 
                 model=None, input_tokens=None, output_tokens=None, total_tokens=None,
                 estimated_cost=None, success=None, error_message=None, response_time_ms=None,
                 timestamp=None, feature_used=None, canary_id=None):
        self.log_id = log_id or str(uuid.uuid4())
        self.user_id = user_id
        self.api_type = api_type  # 'anthropic', 'openai', etc.
        self.endpoint = endpoint  # 'chat', 'validation', 'smart_alert', etc.
        self.model = model
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.total_tokens = total_tokens
        self.estimated_cost = estimated_cost  # In USD
        self.success = success
        self.error_message = error_message
        self.response_time_ms = response_time_ms
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.feature_used = feature_used  # 'chat', 'smart_alert', 'validation', etc.
        self.canary_id = canary_id  # If related to specific canary
    
    def save(self):
        """Save API usage log to DynamoDB"""
        try:
            item = {
                'log_id': self.log_id,
                'user_id': self.user_id,
                'api_type': self.api_type,
                'timestamp': self.timestamp
            }
            
            # Add optional fields if they exist
            optional_fields = ['endpoint', 'model', 'input_tokens', 'output_tokens', 
                             'total_tokens', 'estimated_cost', 'success', 'error_message',
                             'response_time_ms', 'feature_used', 'canary_id']
            
            for field in optional_fields:
                value = getattr(self, field)
                if value is not None:
                    item[field] = value
            
            api_usage_table.put_item(Item=item)
            return True
        except ClientError as e:
            print(f"Error saving API usage log: {e}")
            return False
    
    @staticmethod
    def get_by_user_id(user_id, limit=50):
        """Get API usage logs for a user"""
        try:
            response = api_usage_table.query(
                IndexName='user-id-index',
                KeyConditionExpression=Key('user_id').eq(user_id),
                ScanIndexForward=False,  # Most recent first
                Limit=limit
            )
            
            logs = []
            for item in response.get('Items', []):
                log = ApiUsageLog(
                    log_id=item.get('log_id'),
                    user_id=item.get('user_id'),
                    api_type=item.get('api_type'),
                    endpoint=item.get('endpoint'),
                    model=item.get('model'),
                    input_tokens=item.get('input_tokens'),
                    output_tokens=item.get('output_tokens'),
                    total_tokens=item.get('total_tokens'),
                    estimated_cost=item.get('estimated_cost'),
                    success=item.get('success'),
                    error_message=item.get('error_message'),
                    response_time_ms=item.get('response_time_ms'),
                    timestamp=item.get('timestamp'),
                    feature_used=item.get('feature_used'),
                    canary_id=item.get('canary_id')
                )
                logs.append(log)
            
            return logs
        except ClientError as e:
            print(f"Error getting API usage logs: {e}")
            return []
    
    @staticmethod
    def get_user_usage_summary(user_id, days=30):
        """Get usage summary for a user"""
        try:
            from datetime import datetime, timezone, timedelta
            cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            
            response = api_usage_table.query(
                IndexName='user-id-index',
                KeyConditionExpression=Key('user_id').eq(user_id),
                FilterExpression=Attr('timestamp').gte(cutoff_date)
            )
            
            items = response.get('Items', [])
            
            summary = {
                'total_calls': len(items),
                'successful_calls': len([i for i in items if i.get('success', False)]),
                'failed_calls': len([i for i in items if i.get('success', False) == False]),
                'total_tokens': sum(i.get('total_tokens', 0) for i in items),
                'estimated_cost': sum(float(i.get('estimated_cost', 0)) for i in items),
                'features_used': {},
                'models_used': {}
            }
            
            # Count feature usage
            for item in items:
                feature = item.get('feature_used', 'unknown')
                summary['features_used'][feature] = summary['features_used'].get(feature, 0) + 1
                
                model = item.get('model', 'unknown')
                summary['models_used'][model] = summary['models_used'].get(model, 0) + 1
            
            return summary
        except ClientError as e:
            print(f"Error getting usage summary: {e}")
            return {}

class SmartAlert:
    """Smart alerting with ML-based anomaly detection for irregular check-in patterns"""
    
    def __init__(self, smart_alert_id=None, canary_id=None, user_id=None, is_enabled=True,
                 learning_period_days=7, sensitivity=0.8, created_at=None, 
                 pattern_data=None, last_analysis=None, last_alert_sent=None):
        self.smart_alert_id = smart_alert_id or str(uuid.uuid4())
        self.canary_id = canary_id
        self.user_id = user_id
        self.is_enabled = is_enabled
        self.learning_period_days = learning_period_days  # How many days to learn patterns
        self.sensitivity = Decimal(str(sensitivity))  # 0.5-1.0, higher = more sensitive
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.pattern_data = pattern_data or {}  # Stores learned patterns
        self.last_analysis = last_analysis
        self.last_alert_sent = last_alert_sent  # Track when last alert was sent
    
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
                    'last_analysis': self.last_analysis,
                    'last_alert_sent': self.last_alert_sent
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
                    last_analysis=item.get('last_analysis'),
                    last_alert_sent=item.get('last_alert_sent')
                )
            return None
        except ClientError as e:
            print(f"Error getting smart alert: {e}")
            return None
    
    def learn_patterns(self):
        """Analyze check-in patterns and build ML model for anomaly detection"""
        import statistics
        from collections import defaultdict
        from decimal import Decimal
        
        try:
            # Get canary to analyze
            canary = Canary.get_by_id(self.canary_id)
            if not canary:
                return False
            
            # Get check-in logs for learning period (optimized retrieval)
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=self.learning_period_days)
            
            # Optimize: Use incremental learning if we have recent patterns
            use_incremental = False
            existing_checkin_times = []
            
            if self.pattern_data and self.last_analysis:
                try:
                    last_analysis_time = datetime.fromisoformat(self.last_analysis.replace('Z', '+00:00'))
                    # If last analysis was recent (< 6 hours), do incremental update
                    if (end_time - last_analysis_time).total_seconds() < 21600:  # 6 hours
                        use_incremental = True
                        # Start from last analysis time for new data
                        incremental_start = last_analysis_time
                except:
                    pass
            
            if use_incremental:
                # Fetch only new logs since last analysis + preserve existing pattern data
                logs_result = CanaryLog.get_by_canary_id(self.canary_id, limit=200)  # Smaller limit for incremental
                logs = logs_result['logs']
                
                # Get existing checkin times from pattern metadata if available
                existing_total = self.pattern_data.get('total_checkins', 0)
                
                # Filter new logs since last analysis
                new_checkin_times = []
                for log in logs:
                    if log.event_type == 'ping' and log.status == 'success':
                        log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                        if incremental_start < log_time <= end_time and start_time <= log_time:
                            new_checkin_times.append(log_time)
                
                # If we have few new checkins, don't update patterns unnecessarily
                if len(new_checkin_times) < 2 and existing_total > 10:
                    return True  # Skip update, existing patterns are sufficient
                    
                checkin_times = new_checkin_times
                
            else:
                # Full analysis: fetch comprehensive data
                # Use larger limit but with better filtering
                logs_result = CanaryLog.get_by_canary_id(self.canary_id, limit=1500)
                logs = logs_result['logs']
                
                # Filter to successful check-ins within learning period
                checkin_times = []
                for log in logs:
                    if log.event_type == 'ping' and log.status == 'success':
                        log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                        if start_time <= log_time <= end_time:
                            checkin_times.append(log_time)
            
            # Adjust minimum data requirements based on update type
            min_required = 2 if use_incremental else 3
            if len(checkin_times) < min_required:
                # For incremental updates with insufficient new data, return existing patterns
                if use_incremental and self.pattern_data:
                    return True  # Keep existing patterns
                return False
            
            # Enhanced pattern analysis with seasonal detection
            # Initialize pattern containers - support both incremental and full updates
            if use_incremental and self.pattern_data:
                # Start with existing pattern distributions
                existing_hourly = self.pattern_data.get('hourly_distribution', {})
                existing_daily = self.pattern_data.get('daily_distribution', {})
                existing_monthly = self.pattern_data.get('monthly_distribution', {})
                
                hourly_patterns = defaultdict(list)
                daily_patterns = defaultdict(list) 
                monthly_patterns = defaultdict(list)
                
                # Pre-populate with existing counts
                for h in range(24):
                    existing_count = int(existing_hourly.get(str(h), 0))
                    hourly_patterns[h] = [1] * existing_count
                    
                for d in range(7):
                    existing_count = int(existing_daily.get(str(d), 0))
                    daily_patterns[d] = [1] * existing_count
                    
                for m in range(1, 13):
                    existing_count = int(existing_monthly.get(str(m), 0))
                    monthly_patterns[m] = [1] * existing_count
                    
            else:
                # Full analysis - start fresh
                hourly_patterns = defaultdict(list)
                daily_patterns = defaultdict(list)
                monthly_patterns = defaultdict(list)
            
            seasonal_patterns = defaultdict(list)  # Always recalculate seasonal patterns
            interval_patterns = []
            
            checkin_times.sort()
            
            # Analyze check-in patterns with enhanced categorization
            for i, checkin_time in enumerate(checkin_times):
                hour = checkin_time.hour
                day = checkin_time.weekday()  # 0=Monday, 6=Sunday
                month = checkin_time.month
                
                # Traditional patterns
                hourly_patterns[hour].append(1)
                daily_patterns[day].append(1)
                monthly_patterns[month].append(1)
                
                # Seasonal patterns (business vs personal schedules)
                is_weekend = day >= 5  # Saturday=5, Sunday=6
                season_key = 'weekend' if is_weekend else 'weekday'
                seasonal_patterns[season_key].append(1)
                
                # Calculate intervals between check-ins with trend analysis
                if i > 0:
                    interval = (checkin_time - checkin_times[i-1]).total_seconds() / 60
                    interval_patterns.append({
                        'interval': interval,
                        'timestamp': checkin_time,
                        'is_weekend': is_weekend,
                        'hour': hour,
                        'day': day
                    })
            
            # Calculate enhanced statistics for patterns (optimized for incremental updates)
            if use_incremental and self.pattern_data:
                # Merge new interval data with existing statistics
                existing_avg = float(self.pattern_data.get('avg_interval', canary.interval_minutes))
                existing_count = self.pattern_data.get('total_checkins', 0) - 1  # Subtract 1 for intervals
                new_intervals = [p['interval'] for p in interval_patterns]
                
                if new_intervals and existing_count > 0:
                    # Weighted average calculation
                    total_existing_sum = existing_avg * existing_count
                    new_sum = sum(new_intervals)
                    new_count = len(new_intervals)
                    
                    avg_interval = (total_existing_sum + new_sum) / (existing_count + new_count)
                    # Simplified std calculation for incremental updates
                    all_intervals = new_intervals  # For std calculation, use available data
                    interval_std = statistics.stdev(all_intervals) if len(all_intervals) > 1 else float(self.pattern_data.get('interval_std', 0))
                else:
                    avg_interval = existing_avg
                    interval_std = float(self.pattern_data.get('interval_std', 0))
                    
                # For seasonal patterns, merge with existing data
                existing_seasonal = self.pattern_data.get('seasonal_patterns', {})
                existing_weekday_count = existing_seasonal.get('weekday_count', 0)
                existing_weekend_count = existing_seasonal.get('weekend_count', 0)
                existing_business_hours = existing_seasonal.get('business_hours_count', 0)
                existing_after_hours = existing_seasonal.get('after_hours_count', 0)
                
            else:
                # Full calculation
                avg_interval = statistics.mean([p['interval'] for p in interval_patterns]) if interval_patterns else canary.interval_minutes
                interval_std = statistics.stdev([p['interval'] for p in interval_patterns]) if len(interval_patterns) > 1 else 0
                existing_weekday_count = existing_weekend_count = 0
                existing_business_hours = existing_after_hours = 0
            
            # Analyze weekday vs weekend patterns
            weekday_intervals = [p['interval'] for p in interval_patterns if not p['is_weekend']]
            weekend_intervals = [p['interval'] for p in interval_patterns if p['is_weekend']]
            
            # Use incremental data if available, otherwise calculate fresh
            total_weekday_count = existing_weekday_count + len([p for p in interval_patterns if not p['is_weekend']])
            total_weekend_count = existing_weekend_count + len([p for p in interval_patterns if p['is_weekend']])
            
            if use_incremental and self.pattern_data:
                existing_seasonal = self.pattern_data.get('seasonal_patterns', {})
                existing_weekday_avg = float(existing_seasonal.get('weekday_avg_interval', avg_interval))
                existing_weekend_avg = float(existing_seasonal.get('weekend_avg_interval', avg_interval))
                
                # Weighted average for incremental updates
                if weekday_intervals and existing_weekday_count > 0:
                    weekday_avg = ((existing_weekday_avg * existing_weekday_count) + sum(weekday_intervals)) / (existing_weekday_count + len(weekday_intervals))
                elif weekday_intervals:
                    weekday_avg = statistics.mean(weekday_intervals)
                else:
                    weekday_avg = existing_weekday_avg
                    
                if weekend_intervals and existing_weekend_count > 0:
                    weekend_avg = ((existing_weekend_avg * existing_weekend_count) + sum(weekend_intervals)) / (existing_weekend_count + len(weekend_intervals))
                elif weekend_intervals:
                    weekend_avg = statistics.mean(weekend_intervals)
                else:
                    weekend_avg = existing_weekend_avg
            else:
                weekday_avg = statistics.mean(weekday_intervals) if weekday_intervals else avg_interval
                weekend_avg = statistics.mean(weekend_intervals) if weekend_intervals else avg_interval
            
            # Detect business hour patterns (9 AM - 5 PM) - optimized counting
            business_hour_checkins = existing_business_hours + sum(1 for p in interval_patterns if 9 <= p['hour'] <= 17)
            after_hours_checkins = existing_after_hours + len(interval_patterns) - sum(1 for p in interval_patterns if 9 <= p['hour'] <= 17)
            
            # Trend analysis for gradual schedule changes
            trend_data = self._analyze_trends(interval_patterns)
            
            # Calculate total checkins for confidence scoring
            if use_incremental and self.pattern_data:
                total_checkins = self.pattern_data.get('total_checkins', 0) + len(checkin_times)
            else:
                total_checkins = len(checkin_times)
            
            pattern_data = {
                'hourly_distribution': {str(h): len(hourly_patterns[h]) for h in range(24)},
                'daily_distribution': {str(d): len(daily_patterns[d]) for d in range(7)},
                'monthly_distribution': {str(m): len(monthly_patterns[m]) for m in range(1, 13)},
                'seasonal_patterns': {
                    'weekday_count': total_weekday_count,
                    'weekend_count': total_weekend_count,
                    'weekday_avg_interval': Decimal(str(round(weekday_avg, 2))),
                    'weekend_avg_interval': Decimal(str(round(weekend_avg, 2))),
                    'business_hours_count': business_hour_checkins,
                    'after_hours_count': after_hours_checkins
                },
                'trend_analysis': trend_data,
                'avg_interval': Decimal(str(round(avg_interval, 2))),
                'interval_std': Decimal(str(round(interval_std, 2))),
                'total_checkins': total_checkins,
                'learning_start': start_time.isoformat(),
                'learning_end': end_time.isoformat(),
                'expected_interval': canary.interval_minutes,
                'pattern_confidence': min(1.0, total_checkins / 20),  # Confidence increases with more data
                'last_update_type': 'incremental' if use_incremental else 'full',
                'optimization_enabled': True  # Flag to indicate this uses optimized storage
            }
            
            self.pattern_data = pattern_data
            self.last_analysis = datetime.now(timezone.utc).isoformat()
            
            return self.save()
            
        except Exception as e:
            print(f"Error learning patterns: {e}")
            return False
    
    def is_anomaly(self, current_time=None):
        """Check if current timing represents an anomaly based on learned patterns with seasonal awareness"""
        if not self.pattern_data or not self.is_enabled:
            return False
        
        current_time = current_time or datetime.now(timezone.utc)
        
        # Cooldown period: don't send alerts too frequently (minimum 30 minutes between alerts)
        if self.last_alert_sent:
            try:
                last_alert_time = datetime.fromisoformat(self.last_alert_sent.replace('Z', '+00:00'))
                time_since_last_alert = (current_time - last_alert_time).total_seconds() / 60
                if time_since_last_alert < 30:  # 30-minute cooldown
                    return False
            except:
                pass  # If we can't parse the time, continue with analysis
        
        # Get canary and its last check-in
        canary = Canary.get_by_id(self.canary_id)
        if not canary or not canary.last_checkin:
            return False
        
        last_checkin = datetime.fromisoformat(canary.last_checkin.replace('Z', '+00:00'))
        time_since_last = (current_time - last_checkin).total_seconds() / 60
        
        # Enhanced seasonal pattern analysis
        current_is_weekend = current_time.weekday() >= 5  # Saturday=5, Sunday=6
        current_is_business_hours = 9 <= current_time.hour <= 17
        seasonal_patterns = self.pattern_data.get('seasonal_patterns', {})
        
        # Use seasonal-aware expected intervals when available
        expected_interval = self.pattern_data.get('avg_interval', canary.interval_minutes)
        
        # Apply seasonal adjustments if we have sufficient seasonal data
        if seasonal_patterns:
            weekday_count = seasonal_patterns.get('weekday_count', 0)
            weekend_count = seasonal_patterns.get('weekend_count', 0)
            
            # Only use seasonal patterns if we have reasonable data for both contexts
            if weekday_count >= 3 and weekend_count >= 3:
                if current_is_weekend:
                    seasonal_interval = seasonal_patterns.get('weekend_avg_interval')
                    if seasonal_interval:
                        expected_interval = float(seasonal_interval)
                else:
                    seasonal_interval = seasonal_patterns.get('weekday_avg_interval')
                    if seasonal_interval:
                        expected_interval = float(seasonal_interval)
        
        interval_std = self.pattern_data.get('interval_std', 0)
        
        # Convert Decimal to float for calculations
        expected_interval = float(expected_interval)
        interval_std = float(interval_std)
        
        # Define anomaly threshold based on sensitivity (more conservative)
        # Higher sensitivity = lower threshold, but with reasonable minimums
        sensitivity_factor = float(self.sensitivity)
        
        if interval_std > 0:
            # Use standard deviations but with minimum buffer
            # Even at max sensitivity (1.0), allow at least 1.5 std deviations
            threshold_multiplier = max(1.5, 3.0 - sensitivity_factor)  # 1.5 to 2.0 range
            threshold = expected_interval + (interval_std * threshold_multiplier)
        else:
            # More conservative percentage-based threshold
            # Even at max sensitivity, allow at least 30% variance
            threshold_percentage = max(0.3, 1.0 - (sensitivity_factor * 0.4))  # 0.3 to 0.6 range
            threshold = expected_interval * (1 + threshold_percentage)
        
        # Enhanced pattern anomaly detection with seasonal awareness
        hour_anomaly = self._check_hour_anomaly(current_time)
        day_anomaly = self._check_day_anomaly(current_time)
        seasonal_anomaly = self._check_seasonal_anomaly(current_time)
        trend_anomaly = self._check_trend_anomaly(time_since_last, expected_interval)
        
        # Combine different anomaly indicators with conservative logic
        time_anomaly = time_since_last > threshold
        
        # Only trigger on pattern anomalies if they're extreme AND sensitivity is very high
        # AND we have sufficient confidence in our patterns
        pattern_confidence = self.pattern_data.get('total_checkins', 0) >= 10
        extreme_sensitivity = sensitivity_factor >= 0.9
        pattern_anomaly = (hour_anomaly or day_anomaly or seasonal_anomaly) and pattern_confidence and extreme_sensitivity
        
        # Trend-based anomalies are more nuanced - they adjust expectations based on detected trends
        # This helps prevent false positives when schedules are naturally evolving
        if trend_anomaly:
            # If we detect a trend violation, it's a strong signal even at lower sensitivity
            pattern_anomaly = True
        
        # Primary trigger should be time-based anomaly
        # Pattern anomalies are secondary and require high confidence
        is_anomalous = time_anomaly or pattern_anomaly
        
        # If we detect an anomaly, record the alert timestamp
        if is_anomalous:
            self.last_alert_sent = current_time.isoformat()
            self.save()  # Save to persist the alert timestamp
        
        return is_anomalous
    
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
    
    def _check_seasonal_anomaly(self, current_time):
        """Check if current timing violates weekday/weekend or business hours patterns"""
        seasonal_patterns = self.pattern_data.get('seasonal_patterns', {})
        if not seasonal_patterns:
            return False
        
        current_is_weekend = current_time.weekday() >= 5  # Saturday=5, Sunday=6
        current_is_business_hours = 9 <= current_time.hour <= 17
        
        # Check weekday/weekend pattern violations
        weekday_count = seasonal_patterns.get('weekday_count', 0)
        weekend_count = seasonal_patterns.get('weekend_count', 0)
        total_checkins = self.pattern_data.get('total_checkins', 1)
        
        # Only apply seasonal logic if we have sufficient data for both contexts
        if weekday_count >= 5 and weekend_count >= 5:
            if current_is_weekend:
                weekend_frequency = weekend_count / total_checkins
                # Anomalous if weekend check-in but pattern shows < 15% weekend activity
                if weekend_frequency < 0.15:
                    return True
            else:
                weekday_frequency = weekday_count / total_checkins
                # Anomalous if weekday check-in but pattern shows < 15% weekday activity
                if weekday_frequency < 0.15:
                    return True
        
        # Check business hours pattern violations
        business_hours_count = seasonal_patterns.get('business_hours_count', 0)
        after_hours_count = seasonal_patterns.get('after_hours_count', 0)
        
        # Only apply if we have reasonable data for both contexts
        if business_hours_count >= 3 and after_hours_count >= 3:
            if current_is_business_hours:
                business_frequency = business_hours_count / total_checkins
                # Anomalous if business hours check-in but pattern shows < 10% business activity
                if business_frequency < 0.10:
                    return True
            else:
                after_hours_frequency = after_hours_count / total_checkins
                # Anomalous if after hours check-in but pattern shows < 10% after hours activity
                if after_hours_frequency < 0.10:
                    return True
        
        return False
    
    def _check_trend_anomaly(self, current_interval, expected_interval):
        """Check if current interval violates detected trends"""
        trend_analysis = self.pattern_data.get('trend_analysis', {})
        if not trend_analysis or not trend_analysis.get('trend_detected'):
            return False
        
        trend_direction = trend_analysis.get('trend_direction', 'stable')
        trend_strength = float(trend_analysis.get('trend_strength', 0))
        trend_confidence = float(trend_analysis.get('trend_confidence', 0))
        
        # Only apply trend logic if we have reasonable confidence (> 0.6) and strength (> 10%)
        if trend_confidence < 0.6 or trend_strength < 10:
            return False
        
        # Adjust expected interval based on trend direction
        if trend_direction == 'increasing':
            # If trend is increasing, expect slightly longer intervals
            adjusted_expected = expected_interval * (1 + (trend_strength / 200))  # Half the trend strength
            # Anomalous if actual interval is significantly shorter than trend expectation
            return current_interval < (adjusted_expected * 0.7)  # 30% tolerance
        
        elif trend_direction == 'decreasing':
            # If trend is decreasing, expect slightly shorter intervals
            adjusted_expected = expected_interval * (1 - (trend_strength / 200))  # Half the trend strength
            # Anomalous if actual interval is significantly longer than trend expectation
            return current_interval > (adjusted_expected * 1.3)  # 30% tolerance
        
        return False  # Stable trends don't trigger anomalies
    
    def get_cached_patterns(self):
        """Get cached pattern data with performance optimization"""
        if not self.pattern_data:
            return None
        
        # Check if patterns are recent enough to use from cache
        if self.last_analysis:
            try:
                last_analysis_time = datetime.fromisoformat(self.last_analysis.replace('Z', '+00:00'))
                age_hours = (datetime.now(timezone.utc) - last_analysis_time).total_seconds() / 3600
                
                # Use cached patterns if they're less than 12 hours old and have good confidence
                pattern_confidence = self.pattern_data.get('pattern_confidence', 0)
                if age_hours < 12 and pattern_confidence > 0.3:
                    return {
                        'cached': True,
                        'age_hours': round(age_hours, 1),
                        'confidence': pattern_confidence,
                        'patterns': self.pattern_data
                    }
            except:
                pass
        
        return None
    
    def should_update_patterns(self):
        """Determine if patterns should be updated based on time and new data availability (optimized)"""
        if not self.is_enabled:
            return False
        
        # Check if we have cached patterns that are still valid
        cached_patterns = self.get_cached_patterns()
        if cached_patterns:
            # If patterns are very recent (< 2 hours) and high confidence, skip update
            if cached_patterns['age_hours'] < 2 and cached_patterns['confidence'] > 0.7:
                return False
        
        # Dynamic update frequency based on pattern maturity and confidence
        if self.last_analysis:
            try:
                last_analysis_time = datetime.fromisoformat(self.last_analysis.replace('Z', '+00:00'))
                time_since_analysis = datetime.now(timezone.utc) - last_analysis_time
                
                # Adaptive update intervals based on pattern confidence
                pattern_confidence = self.pattern_data.get('pattern_confidence', 0) if self.pattern_data else 0
                total_checkins = self.pattern_data.get('total_checkins', 0) if self.pattern_data else 0
                
                if pattern_confidence > 0.8 and total_checkins > 50:
                    # High confidence patterns: update less frequently (2 hours)
                    update_interval = timedelta(hours=2)
                elif pattern_confidence > 0.5 and total_checkins > 20:
                    # Medium confidence patterns: moderate frequency (1 hour)
                    update_interval = timedelta(hours=1)
                elif self.pattern_data:
                    # Low confidence or few data points: update more frequently (30 minutes)
                    update_interval = timedelta(minutes=30)
                else:
                    # No patterns yet: update frequently to build baseline (10 minutes)
                    update_interval = timedelta(minutes=10)
                
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
            
            # If pattern data was deleted, show zero progress until new patterns are learned
            if not self.pattern_data or not self.last_analysis:
                return {
                    'status': 'waiting',
                    'message': 'Pattern data cleared. Waiting for new check-ins to start learning patterns.',
                    'progress': 0,
                    'confidence': 0,
                    'min_required': 3,
                    'learned_patterns': 0,
                    'recent_checkins': 0,
                    'last_updated': None,
                    'learning_period_days': self.learning_period_days
                }
            
            # If we have pattern data, use the existing pattern information
            if self.pattern_data:
                total_checkins = self.pattern_data.get('total_checkins', 0)
                pattern_confidence = self.pattern_data.get('pattern_confidence', 0)
                min_required = 3
                
                # Calculate progress based on learned patterns, not current logs
                if total_checkins == 0:
                    progress = 0
                    status = 'waiting'
                    message = 'Waiting for check-ins to start learning'
                elif total_checkins < min_required:
                    progress = (total_checkins / min_required) * 90
                    status = 'learning'
                    message = f'Learning: {total_checkins}/{min_required} check-ins analyzed'
                else:
                    progress = 100
                    status = 'ready'
                    message = f'Patterns learned from {total_checkins} check-ins'
                
                # Get recent check-ins for display (last 24 hours)
                end_time = datetime.now(timezone.utc)
                recent_start = end_time - timedelta(hours=24)
                
                logs_result = CanaryLog.get_by_canary_id(self.canary_id, limit=100)
                logs = logs_result['logs']
                
                recent_checkins = 0
                for log in logs:
                    if log.event_type == 'ping' and log.status == 'success':
                        log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                        if recent_start <= log_time <= end_time:
                            recent_checkins += 1
                
                # Calculate pattern confidence
                confidence = min(100, (total_checkins / 20) * 100)
                
                return {
                    'status': status,
                    'message': message,
                    'progress': round(progress, 1),
                    'total_checkins': total_checkins,
                    'min_required': min_required,
                    'confidence': round(confidence, 1),
                    'learned_patterns': total_checkins,
                    'recent_checkins': recent_checkins,
                    'last_updated': self.last_analysis,
                    'learning_period_days': self.learning_period_days
                }
            
            # This should never be reached now, but keep as fallback
            return {
                'status': 'error',
                'message': 'Unexpected state in learning progress calculation',
                'progress': 0,
                'confidence': 0,
                'learned_patterns': 0,
                'recent_checkins': 0,
                'last_updated': None,
                'learning_period_days': self.learning_period_days
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Error calculating progress: {e}',
                'progress': 0,
                'confidence': 0
            }
    
    def _analyze_trends(self, interval_patterns):
        """Analyze trends in check-in patterns to detect gradual schedule changes"""
        from decimal import Decimal
        import statistics
        
        if len(interval_patterns) < 5:  # Need minimum data for trend analysis
            return {
                'trend_detected': False,
                'trend_direction': 'stable',
                'trend_strength': 0,
                'trend_confidence': 0
            }
        
        # Sort patterns by timestamp for chronological analysis
        sorted_patterns = sorted(interval_patterns, key=lambda x: x['timestamp'])
        intervals = [p['interval'] for p in sorted_patterns]
        
        # Calculate moving averages to detect trends
        # Use 25% of data points as window size (minimum 3, maximum 10)
        window_size = max(3, min(10, len(intervals) // 4))
        moving_averages = []
        
        for i in range(len(intervals) - window_size + 1):
            window = intervals[i:i + window_size]
            avg = statistics.mean(window)
            moving_averages.append(avg)
        
        if len(moving_averages) < 3:  # Need at least 3 points for trend
            return {
                'trend_detected': False,
                'trend_direction': 'stable',
                'trend_strength': 0,
                'trend_confidence': 0
            }
        
        # Calculate trend using linear regression on moving averages
        x_values = list(range(len(moving_averages)))
        y_values = moving_averages
        
        # Simple linear regression: y = mx + b
        n = len(x_values)
        sum_x = sum(x_values)
        sum_y = sum(y_values)
        sum_xy = sum(x * y for x, y in zip(x_values, y_values))
        sum_x2 = sum(x * x for x in x_values)
        
        # Calculate slope (trend direction and strength)
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            slope = 0
        else:
            slope = (n * sum_xy - sum_x * sum_y) / denominator
        
        # Calculate correlation coefficient for trend confidence
        if len(y_values) > 1:
            x_std = statistics.stdev(x_values) if len(x_values) > 1 else 0
            y_std = statistics.stdev(y_values) if len(y_values) > 1 else 0
            
            if x_std > 0 and y_std > 0:
                correlation = (sum_xy - (sum_x * sum_y) / n) / ((n - 1) * x_std * y_std)
                correlation = max(-1, min(1, correlation))  # Clamp between -1 and 1
            else:
                correlation = 0
        else:
            correlation = 0
        
        # Determine trend characteristics
        avg_interval = statistics.mean(intervals)
        slope_percentage = (slope / avg_interval) * 100 if avg_interval > 0 else 0
        
        # Classify trend direction
        if abs(slope_percentage) < 2:  # Less than 2% change
            trend_direction = 'stable'
            trend_detected = False
        elif slope_percentage > 0:
            trend_direction = 'increasing'  # Intervals getting longer
            trend_detected = abs(slope_percentage) > 5  # Only detect if > 5% change
        else:
            trend_direction = 'decreasing'  # Intervals getting shorter
            trend_detected = abs(slope_percentage) > 5  # Only detect if > 5% change
        
        trend_strength = abs(slope_percentage)
        trend_confidence = abs(correlation)
        
        return {
            'trend_detected': trend_detected,
            'trend_direction': trend_direction,
            'trend_strength': Decimal(str(round(trend_strength, 2))),
            'trend_confidence': Decimal(str(round(trend_confidence, 2))),
            'slope_per_interval': Decimal(str(round(slope, 2))),
            'correlation_coefficient': Decimal(str(round(correlation, 3))),
            'analysis_window_size': window_size,
            'total_intervals_analyzed': len(intervals)
        }


class Subscription:
    """Model for managing user subscriptions with Stripe integration"""
    
    def __init__(self, subscription_id=None, user_id=None, stripe_subscription_id=None, 
                 stripe_customer_id=None, status='active', plan_name='free', canary_limit=1,
                 current_period_start=None, current_period_end=None, created_at=None):
        self.subscription_id = subscription_id or str(uuid.uuid4())
        self.user_id = user_id
        self.stripe_subscription_id = stripe_subscription_id
        self.stripe_customer_id = stripe_customer_id
        self.status = status  # active, canceled, past_due, incomplete
        self.plan_name = plan_name  # free, starter, pro, business
        self.canary_limit = canary_limit
        self.current_period_start = current_period_start
        self.current_period_end = current_period_end
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
    
    def save(self):
        """Save subscription to DynamoDB"""
        try:
            item = {
                'subscription_id': self.subscription_id,
                'user_id': self.user_id,
                'status': self.status,
                'plan_name': self.plan_name,
                'canary_limit': self.canary_limit,
                'created_at': self.created_at
            }
            
            if self.stripe_subscription_id:
                item['stripe_subscription_id'] = self.stripe_subscription_id
            if self.stripe_customer_id:
                item['stripe_customer_id'] = self.stripe_customer_id
            if self.current_period_start:
                item['current_period_start'] = self.current_period_start
            if self.current_period_end:
                item['current_period_end'] = self.current_period_end
                
            subscriptions_table.put_item(Item=item)
            return True
        except ClientError as e:
            print(f"Error saving subscription: {e}")
            return False
    
    def delete(self):
        """Delete subscription from DynamoDB"""
        try:
            subscriptions_table.delete_item(Key={'subscription_id': self.subscription_id})
            return True
        except ClientError as e:
            print(f"Error deleting subscription: {e}")
            return False
    
    def get_usage(self):
        """Get current usage for this user"""
        canaries = Canary.get_by_user_id(self.user_id)
        active_canaries = [c for c in canaries if c.is_active]
        return {
            'canaries_used': len(active_canaries),
            'canary_limit': self.canary_limit,
            'usage_percentage': (len(active_canaries) / self.canary_limit) * 100 if self.canary_limit > 0 else 0
        }
    
    def can_create_canary(self):
        """Check if user can create another canary"""
        usage = self.get_usage()
        return usage['canaries_used'] < self.canary_limit
    
    @staticmethod
    def get_by_user_id(user_id):
        """Get subscription for a user"""
        try:
            response = subscriptions_table.query(
                IndexName='user-id-index',
                KeyConditionExpression=Key('user_id').eq(user_id)
            )
            
            items = response.get('Items', [])
            if items:
                item = items[0]  # Should only be one active subscription per user
                return Subscription(
                    subscription_id=item['subscription_id'],
                    user_id=item['user_id'],
                    stripe_subscription_id=item.get('stripe_subscription_id'),
                    stripe_customer_id=item.get('stripe_customer_id'),
                    status=item['status'],
                    plan_name=item['plan_name'],
                    canary_limit=item['canary_limit'],
                    current_period_start=item.get('current_period_start'),
                    current_period_end=item.get('current_period_end'),
                    created_at=item['created_at']
                )
            return None
        except ClientError as e:
            print(f"Error fetching subscription: {e}")
            return None
    
    def create_stripe_customer(self):
        """Create Stripe customer for this subscription"""
        import stripe
        from models import User
        
        try:
            user = User.get_by_id(self.user_id)
            if not user:
                return False
            
            customer = stripe.Customer.create(
                email=user.email,
                name=user.username,
                metadata={
                    'user_id': self.user_id,
                    'subscription_id': self.subscription_id
                }
            )
            
            self.stripe_customer_id = customer.id
            return self.save()
            
        except Exception as e:
            print(f"Error creating Stripe customer: {e}")
            return False
    
    def create_stripe_subscription(self, price_id):
        """Create Stripe subscription"""
        import stripe
        
        try:
            if not self.stripe_customer_id:
                if not self.create_stripe_customer():
                    return False
            
            # Create the subscription
            stripe_subscription = stripe.Subscription.create(
                customer=self.stripe_customer_id,
                items=[{
                    'price': price_id,
                }],
                metadata={
                    'user_id': self.user_id,
                    'subscription_id': self.subscription_id
                }
            )
            
            self.stripe_subscription_id = stripe_subscription.id
            self.status = stripe_subscription.status
            self.current_period_start = datetime.fromtimestamp(stripe_subscription.current_period_start).isoformat()
            self.current_period_end = datetime.fromtimestamp(stripe_subscription.current_period_end).isoformat()
            
            return self.save()
            
        except Exception as e:
            print(f"Error creating Stripe subscription: {e}")
            return False
    
    @staticmethod
    def create_default_subscription(user_id):
        """Create default free subscription for new user"""
        subscription = Subscription(
            user_id=user_id,
            plan_name='free',
            canary_limit=1,
            status='active'
        )
        return subscription.save()

class APIKey:
    """Model for managing user API keys with usage tracking"""
    
    def __init__(self, api_key_id=None, user_id=None, name=None, key_value=None, 
                 created_at=None, last_used=None, is_active=True, usage_count=0):
        self.api_key_id = api_key_id or str(uuid.uuid4())
        self.user_id = user_id
        self.name = name
        self.key_value = key_value
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.last_used = last_used
        self.is_active = is_active
        self.usage_count = usage_count or 0
    
    @staticmethod
    def generate_key_value(user_id):
        """Generate a new API key value"""
        import secrets
        # Security fix: Use cryptographically secure random generation with sc- prefix
        return f"sc-{secrets.token_urlsafe(32)}"
    
    def save(self):
        """Save API key to DynamoDB"""
        try:
            item = {
                'api_key_id': self.api_key_id,
                'user_id': self.user_id,
                'name': self.name,
                'key_value': self.key_value,
                'created_at': self.created_at,
                'is_active': self.is_active,
                'usage_count': self.usage_count
            }
            
            if self.last_used:
                item['last_used'] = self.last_used
                
            api_keys_table.put_item(Item=item)
            return True
        except ClientError as e:
            print(f"Error saving API key: {e}")
            return False
    
    def delete(self):
        """Delete API key from DynamoDB"""
        try:
            api_keys_table.delete_item(Key={'api_key_id': self.api_key_id})
            return True
        except ClientError as e:
            print(f"Error deleting API key {self.api_key_id}: {e}")
            return False
    
    def record_usage(self, endpoint=None, ip_address=None, canary_id=None, status='success'):
        """Record usage of this API key with detailed logging"""
        self.last_used = datetime.now(timezone.utc).isoformat()
        self.usage_count += 1
        
        # Log detailed usage
        try:
            usage_log = APIKeyUsageLog(
                api_key_id=self.api_key_id,
                user_id=self.user_id,
                endpoint=endpoint or 'unknown',
                ip_address=ip_address or 'unknown',
                canary_id=canary_id,
                status=status
            )
            usage_log.save()
        except Exception as e:
            print(f"Failed to log API key usage: {e}")
        
        return self.save()
    
    @staticmethod
    def get_by_user_id(user_id):
        """Get all API keys for a user"""
        try:
            response = api_keys_table.query(
                IndexName='user-id-index',
                KeyConditionExpression=Key('user_id').eq(user_id)
            )
            
            api_keys = []
            for item in response.get('Items', []):
                api_key = APIKey(
                    api_key_id=item['api_key_id'],
                    user_id=item['user_id'],
                    name=item['name'],
                    key_value=item['key_value'],
                    created_at=item['created_at'],
                    last_used=item.get('last_used'),
                    is_active=item['is_active'],
                    usage_count=item.get('usage_count', 0)
                )
                api_keys.append(api_key)
            
            return api_keys
        except ClientError as e:
            print(f"Error fetching API keys: {e}")
            return []
    
    @staticmethod  
    def get_by_key_value(key_value):
        """Get API key by its value"""
        try:
            response = api_keys_table.query(
                IndexName='key-value-index',
                KeyConditionExpression=Key('key_value').eq(key_value)
            )
            
            items = response.get('Items', [])
            if items:
                item = items[0]
                return APIKey(
                    api_key_id=item['api_key_id'],
                    user_id=item['user_id'],
                    name=item['name'],
                    key_value=item['key_value'],
                    created_at=item['created_at'],
                    last_used=item.get('last_used'),
                    is_active=item['is_active'],
                    usage_count=item.get('usage_count', 0)
                )
            return None
        except ClientError as e:
            print(f"Error fetching API key: {e}")
            return None
    
    @staticmethod
    def get_by_id(api_key_id):
        """Get API key by ID"""
        try:
            response = api_keys_table.get_item(Key={'api_key_id': api_key_id})
            
            item = response.get('Item')
            if item:
                return APIKey(
                    api_key_id=item['api_key_id'],
                    user_id=item['user_id'],
                    name=item['name'],
                    key_value=item['key_value'],
                    created_at=item['created_at'],
                    last_used=item.get('last_used'),
                    is_active=item['is_active'],
                    usage_count=item.get('usage_count', 0)
                )
            return None
        except ClientError as e:
            print(f"Error fetching API key: {e}")
            return None

class APIKeyUsageLog:
    """Model for tracking detailed API key usage logs"""
    
    def __init__(self, log_id=None, api_key_id=None, user_id=None, endpoint=None,
                 ip_address=None, canary_id=None, status='success', timestamp=None):
        self.log_id = log_id or str(uuid.uuid4())
        self.api_key_id = api_key_id
        self.user_id = user_id
        self.endpoint = endpoint
        self.ip_address = ip_address
        self.canary_id = canary_id
        self.status = status
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    
    def save(self):
        """Save usage log to DynamoDB"""
        try:
            item = {
                'log_id': self.log_id,
                'api_key_id': self.api_key_id,
                'user_id': self.user_id,
                'endpoint': self.endpoint,
                'ip_address': self.ip_address,
                'timestamp': self.timestamp,
                'status': self.status
            }
            
            # Only add canary_id if it exists
            if self.canary_id:
                item['canary_id'] = self.canary_id
            
            # Store in APIUsage table (reusing existing table structure)
            api_usage_table = get_dynamodb_resource().Table('SilentCanary_APIUsage')
            api_usage_table.put_item(Item=item)
            return True
        except Exception as e:
            print(f"Error saving API key usage log: {e}")
            return False
    
    @staticmethod
    def get_by_api_key_id(api_key_id, limit=50):
        """Get usage logs for a specific API key"""
        try:
            api_usage_table = get_dynamodb_resource().Table('SilentCanary_APIUsage')
            # We'll need to scan since we don't have an index on api_key_id
            # In production, you'd want to add a GSI for this
            response = api_usage_table.scan(
                FilterExpression='api_key_id = :api_key_id',
                ExpressionAttributeValues={':api_key_id': api_key_id},
                Limit=limit
            )
            
            logs = []
            for item in response.get('Items', []):
                logs.append(APIKeyUsageLog(
                    log_id=item['log_id'],
                    api_key_id=item['api_key_id'],
                    user_id=item['user_id'],
                    endpoint=item['endpoint'],
                    ip_address=item['ip_address'],
                    canary_id=item.get('canary_id'),
                    status=item['status'],
                    timestamp=item['timestamp']
                ))
            
            # Sort by timestamp (most recent first)
            logs.sort(key=lambda x: x.timestamp, reverse=True)
            return logs
            
        except Exception as e:
            print(f"Error fetching API key usage logs: {e}")
            return []

class EmailVerification:
    """Model for email verification during canary creation"""
    
    def __init__(self, verification_id=None, canary_id=None, user_id=None, email=None, 
                 verification_code=None, is_verified=False, created_at=None, verified_at=None, expires_at=None):
        self.verification_id = verification_id or str(uuid.uuid4())
        self.canary_id = canary_id
        self.user_id = user_id
        self.email = email
        self.verification_code = verification_code or self._generate_verification_code()
        self.is_verified = is_verified
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.verified_at = verified_at
        # Email verification expires in 24 hours
        if expires_at:
            self.expires_at = expires_at
        else:
            expires_time = datetime.now(timezone.utc) + timedelta(hours=24)
            self.expires_at = expires_time.isoformat()
    
    def _generate_verification_code(self):
        """Generate a secure 6-digit verification code"""
        import secrets
        return ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    def save(self):
        """Save email verification to DynamoDB"""
        try:
            # Use APIUsage table with email verification data structure
            api_usage_table = get_dynamodb_resource().Table('SilentCanary_APIUsage')
            item = {
                'log_id': self.verification_id,  # Using log_id as primary key
                'user_id': self.user_id,
                'api_type': 'email_verification',
                'endpoint': self.email,  # Store email in endpoint field
                'model': self.canary_id,  # Store canary_id in model field
                'feature_used': self.verification_code,  # Store verification code
                'success': self.is_verified,
                'timestamp': self.created_at,
                'response_time_ms': int(datetime.fromisoformat(self.expires_at.replace('Z', '+00:00')).timestamp() * 1000) if self.expires_at else None,
                'error_message': self.verified_at
            }
            
            api_usage_table.put_item(Item=item)
            return True
        except Exception as e:
            print(f"Error saving email verification: {e}")
            return False
    
    def verify(self, code):
        """Verify the email with the provided code"""
        if self.is_verified:
            return True, "Email already verified"
        
        # Check if verification has expired
        if self.expires_at:
            expires_dt = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
            if datetime.now(timezone.utc) > expires_dt:
                return False, "Verification code has expired"
        
        # Check if code matches
        if self.verification_code != code:
            return False, "Invalid verification code"
        
        # Mark as verified
        self.is_verified = True
        self.verified_at = datetime.now(timezone.utc).isoformat()
        
        if self.save():
            return True, "Email verified successfully"
        else:
            return False, "Failed to save verification status"
    
    @staticmethod
    def get_by_canary_id(canary_id):
        """Get email verification by canary ID"""
        try:
            api_usage_table = get_dynamodb_resource().Table('SilentCanary_APIUsage')
            response = api_usage_table.scan(
                FilterExpression='api_type = :api_type AND model = :canary_id',
                ExpressionAttributeValues={
                    ':api_type': 'email_verification',
                    ':canary_id': canary_id
                }
            )
            
            items = response.get('Items', [])
            if items:
                item = items[0]  # Get the first matching item
                return EmailVerification(
                    verification_id=item['log_id'],
                    canary_id=item['model'],
                    user_id=item['user_id'],
                    email=item['endpoint'],
                    verification_code=item['feature_used'],
                    is_verified=item['success'],
                    created_at=item['timestamp'],
                    verified_at=item.get('error_message'),
                    expires_at=datetime.fromtimestamp(item['response_time_ms'] / 1000, tz=timezone.utc).isoformat() if item.get('response_time_ms') else None
                )
            return None
        except Exception as e:
            print(f"Error fetching email verification: {e}")
            return None
    
    @staticmethod  
    def get_by_verification_id(verification_id):
        """Get email verification by verification ID"""
        try:
            api_usage_table = get_dynamodb_resource().Table('SilentCanary_APIUsage')
            response = api_usage_table.get_item(Key={'log_id': verification_id})
            
            item = response.get('Item')
            if item and item.get('api_type') == 'email_verification':
                return EmailVerification(
                    verification_id=item['log_id'],
                    canary_id=item['model'],
                    user_id=item['user_id'],
                    email=item['endpoint'],
                    verification_code=item['feature_used'],
                    is_verified=item['success'],
                    created_at=item['timestamp'],
                    verified_at=item.get('error_message'),
                    expires_at=datetime.fromtimestamp(item['response_time_ms'] / 1000, tz=timezone.utc).isoformat() if item.get('response_time_ms') else None
                )
            return None
        except Exception as e:
            print(f"Error fetching email verification by ID: {e}")
            return None