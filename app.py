from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from functools import wraps
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional, NumberRange, ValidationError
from datetime import datetime, timezone, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import os
import uuid
import pytz
import requests

# Import our DynamoDB models
from models import User, Canary, CanaryLog, get_dynamodb_resource

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'asdfkjahc rha384y92834yc cx832b48234918xb487214jhasf')

# SendGrid Email Configuration
app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'apikey'
app.config['MAIL_PASSWORD'] = os.environ.get('SENDGRID_API_KEY')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'auth@avriz.com')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Initialize scheduler
scheduler = BackgroundScheduler()

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

def is_admin():
    """Check if current user is admin"""
    return current_user.is_authenticated and current_user.email == 'reza@tabibazar.com'

def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            flash('Admin access required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.template_filter('user_timezone')
def user_timezone_filter(dt):
    """Template filter to convert datetime to user's timezone."""
    if not current_user.is_authenticated or not dt:
        return dt
    return current_user.localize_datetime(dt)

# Custom validators
def validate_integer_required(form, field):
    """Custom validator that treats 0 as valid but requires a value"""
    if field.data is None:
        raise ValidationError('This field is required.')

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class CanaryForm(FlaskForm):
    name = StringField('Canary Name', validators=[DataRequired(), Length(min=1, max=100)])
    interval_minutes = IntegerField('Check-in Interval (minutes)', validators=[
        DataRequired(), 
        NumberRange(min=1, message='Interval must be at least 1 minute')
    ], default=60)
    grace_minutes = IntegerField('Grace Period (minutes)', validators=[
        validate_integer_required,
        NumberRange(min=0, message='Grace period cannot be negative')
    ], default=5)
    alert_type = SelectField('Alert Type', choices=[
        ('email', 'Email'),
        ('slack', 'Slack'),
        ('both', 'Email + Slack')
    ], validators=[DataRequired()], default='email')
    alert_email = StringField('Alert Email', validators=[Optional(), Email()])
    slack_webhook = StringField('Slack Webhook URL', validators=[Optional()])
    submit = SubmitField('Create Canary')

class SettingsForm(FlaskForm):
    username = StringField('Username', render_kw={'readonly': True})
    email = StringField('Email', render_kw={'readonly': True})  
    timezone = SelectField('Timezone', choices=[], validators=[Optional()])
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[Optional(), EqualTo('new_password')])
    submit = SubmitField('Update Settings')
    verify_email = SubmitField('Verify Email')
    delete_account = SubmitField('Delete Account')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

# Routes
@app.route('/health')
def health():
    """Health check endpoint for Kubernetes probes"""
    try:
        # Test DynamoDB connection
        dynamodb = get_dynamodb_resource()
        # Simple health check - just verify we can access DynamoDB
        return jsonify({'status': 'healthy', 'service': 'silentcanary'}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if user already exists
        existing_user = User.get_by_email(form.email.data)
        if existing_user:
            flash('Email already registered')
            return render_template('register.html', form=form)
        
        existing_username = User.get_by_username(form.username.data)
        if existing_username:
            flash('Username already taken')
            return render_template('register.html', form=form)
        
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        
        if user.save():
            # Send verification email automatically
            try:
                serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
                token = serializer.dumps({'user_id': user.user_id}, salt='email-verification')
                verification_link = url_for('verify_email', token=token, _external=True)
                
                msg = Message(
                    subject='Welcome to SilentCanary - Please verify your email',
                    sender=('SilentCanary', app.config['MAIL_DEFAULT_SENDER']),
                    recipients=[user.email],
                    html=f'''
                    <h2>Welcome to SilentCanary!</h2>
                    <p>Hello {user.username},</p>
                    <p>Thank you for registering with SilentCanary!</p>
                    <p>Please verify your email address to complete your account setup:</p>
                    <p><a href="{verification_link}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email Address</a></p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't create this account, please ignore this email.</p>
                    <hr>
                    <p><small>SilentCanary - Dead Man's Switch Monitoring</small></p>
                    '''
                )
                mail.send(msg)
                flash('Registration successful! Please check your email to verify your account.')
            except Exception as e:
                print(f"Registration email error: {e}")
                flash('Registration successful! Please log in. Note: verification email could not be sent.')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Please try again.')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user and user.check_password(form.password.data):
            user.update_last_login()
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        flash('Invalid email or password')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user:
            # Generate reset token
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            token = serializer.dumps({'user_id': user.user_id}, salt='password-reset')
            
            # Send reset email
            try:
                reset_link = url_for('reset_password', token=token, _external=True)
                msg = Message(
                    subject='SilentCanary Password Reset',
                    sender=('SilentCanary', app.config['MAIL_DEFAULT_SENDER']),
                    recipients=[user.email],
                    html=f'''
                    <h2>Password Reset Request</h2>
                    <p>Hello {user.username},</p>
                    <p>You requested a password reset for your SilentCanary account.</p>
                    <p>Click the link below to reset your password:</p>
                    <p><a href="{reset_link}">Reset Password</a></p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this reset, please ignore this email.</p>
                    <hr>
                    <p><small>SilentCanary</small></p>
                    '''
                )
                mail.send(msg)
                flash('Password reset link sent to your email')
            except Exception as e:
                flash('Failed to send reset email. Please try again.')
                print(f"Email error: {e}")
        else:
            # Don't reveal if email exists or not for security
            flash('Password reset link sent to your email')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Verify token
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        data = serializer.loads(token, salt='password-reset', max_age=3600)  # 1 hour
        user_id = data['user_id']
        user = User.get_by_id(user_id)
        if not user:
            flash('Invalid or expired reset link')
            return redirect(url_for('forgot_password'))
    except:
        flash('Invalid or expired reset link')
        return redirect(url_for('forgot_password'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        if user.save():
            flash('Password reset successful! Please log in.')
            return redirect(url_for('login'))
        else:
            flash('Failed to reset password. Please try again.')
    
    return render_template('reset_password.html', form=form)

@app.route('/verify_email/<token>')
def verify_email(token):
    """Handle email verification"""
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        data = serializer.loads(token, salt='email-verification', max_age=3600)  # 1 hour
        user_id = data['user_id']
        user = User.get_by_id(user_id)
        if not user:
            flash('Invalid or expired verification link')
            return redirect(url_for('index'))
    except:
        flash('Invalid or expired verification link')
        return redirect(url_for('index'))
    
    # Update user verification status
    user.is_verified = True
    if user.save():
        flash('Email verified successfully! Your account is now fully activated.')
    else:
        flash('Failed to update verification status. Please try again.')
    
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    canaries = Canary.get_by_user_id(current_user.user_id)
    return render_template('dashboard.html', canaries=canaries)

@app.route('/admin')
@login_required
@admin_required
def admin():
    """Admin dashboard showing all users and statistics"""
    try:
        # Get all users from DynamoDB
        from models import get_dynamodb_resource
        dynamodb = get_dynamodb_resource()
        users_table = dynamodb.Table('SilentCanary_Users')
        canaries_table = dynamodb.Table('SilentCanary_Canaries')
        
        # Get all users
        users_response = users_table.scan()
        users_data = users_response['Items']
        
        # Get all canaries to count per user
        canaries_response = canaries_table.scan()
        canaries_data = canaries_response['Items']
        
        # Process user data and add canary counts
        admin_users = []
        for user_data in users_data:
            # Count canaries for this user
            canary_count = len([c for c in canaries_data if c.get('user_id') == user_data.get('user_id')])
            
            # Parse created_at datetime
            created_at = None
            if user_data.get('created_at'):
                try:
                    from datetime import datetime
                    created_at = datetime.fromisoformat(user_data['created_at'].replace('Z', '+00:00'))
                except:
                    pass
            
            # Parse last_login if it exists
            last_login = None
            if user_data.get('last_login'):
                try:
                    last_login = datetime.fromisoformat(user_data['last_login'].replace('Z', '+00:00'))
                except:
                    pass
            
            admin_user = {
                'user_id': user_data.get('user_id', 'N/A'),
                'username': user_data.get('username', 'N/A'),
                'email': user_data.get('email', 'N/A'),
                'canary_count': canary_count,
                'created_at': created_at,
                'last_login': last_login,
                'is_verified': user_data.get('is_verified', False),
                'timezone': user_data.get('timezone', 'UTC')
            }
            admin_users.append(admin_user)
        
        # Sort by creation date (newest first)
        admin_users.sort(key=lambda x: x['created_at'] or datetime.min, reverse=True)
        
        # Calculate summary stats
        total_users = len(admin_users)
        total_canaries = len(canaries_data)
        verified_users = len([u for u in admin_users if u['is_verified']])
        active_canaries = len([c for c in canaries_data if c.get('status') != 'failed'])
        
        stats = {
            'total_users': total_users,
            'total_canaries': total_canaries,
            'verified_users': verified_users,
            'active_canaries': active_canaries,
            'verification_rate': round((verified_users / total_users * 100) if total_users > 0 else 0, 1)
        }
        
        return render_template('admin.html', users=admin_users, stats=stats)
        
    except Exception as e:
        flash(f'Error loading admin data: {e}')
        return redirect(url_for('dashboard'))

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    """Admin function to delete a user and all their data"""
    try:
        # Prevent admin from deleting themselves
        if user_id == current_user.user_id:
            flash('Cannot delete your own admin account', 'error')
            return redirect(url_for('admin'))
        
        # Get user to delete
        user = User.get_by_id(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin'))
        
        # Delete all user's canaries first
        from models import Canary, get_dynamodb_resource
        canaries = Canary.get_by_user_id(user_id)
        for canary in canaries:
            canary.delete()
        
        # Delete user's canary logs
        dynamodb = get_dynamodb_resource()
        logs_table = dynamodb.Table('SilentCanary_CanaryLogs')
        
        # Scan for logs belonging to this user's canaries
        logs_response = logs_table.scan(
            FilterExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': user_id}
        )
        
        # Delete logs in batches
        for log in logs_response['Items']:
            logs_table.delete_item(
                Key={
                    'canary_id': log['canary_id'],
                    'timestamp': log['timestamp']
                }
            )
        
        # Finally delete the user
        if user.delete():
            flash(f'User {user.username} and all associated data deleted successfully', 'success')
        else:
            flash('Failed to delete user', 'error')
            
    except Exception as e:
        flash(f'Error deleting user: {e}', 'error')
    
    return redirect(url_for('admin'))

@app.route('/admin/update_email/<user_id>', methods=['POST'])
@login_required
@admin_required  
def admin_update_email(user_id):
    """Admin function to update a user's email address"""
    try:
        new_email = request.form.get('new_email', '').strip()
        
        if not new_email:
            flash('Email address is required', 'error')
            return redirect(url_for('admin'))
        
        # Basic email validation
        import re
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', new_email):
            flash('Invalid email format', 'error')
            return redirect(url_for('admin'))
        
        # Get user to update
        user = User.get_by_id(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin'))
        
        # Check if new email already exists
        existing_user = User.get_by_email(new_email)
        if existing_user and existing_user.user_id != user_id:
            flash('Email address already in use by another user', 'error')
            return redirect(url_for('admin'))
        
        old_email = user.email
        user.email = new_email
        user.is_verified = False  # Reset verification status for new email
        
        if user.save():
            flash(f'Email updated from {old_email} to {new_email}. User will need to verify new email.', 'success')
        else:
            flash('Failed to update email address', 'error')
            
    except Exception as e:
        flash(f'Error updating email: {e}', 'error')
    
    return redirect(url_for('admin'))

@app.route('/create_canary', methods=['GET', 'POST'])
@login_required
def create_canary():
    form = CanaryForm()
    if form.validate_on_submit():
        canary = Canary(
            name=form.name.data,
            user_id=current_user.user_id,
            interval_minutes=form.interval_minutes.data,
            grace_minutes=form.grace_minutes.data,
            alert_type=form.alert_type.data,
            alert_email=form.alert_email.data if form.alert_email.data else None,
            slack_webhook=form.slack_webhook.data if form.slack_webhook.data else None
        )
        
        if canary.save():
            flash(f'Canary "{canary.name}" created successfully!')
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to create canary. Please try again.')
    
    return render_template('create_canary.html', form=form)

@app.route('/checkin/<token>', methods=['GET', 'POST'])
def checkin(token):
    canary = Canary.get_by_token(token)
    if not canary:
        return jsonify({'status': 'error', 'message': 'Invalid token'}), 404
    
    # Get client info for logging
    source_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    canary.checkin(source_ip=source_ip, user_agent=user_agent)
    return jsonify({'status': 'success', 'message': 'Check-in received'})

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingsForm()
    
    # Populate timezone choices
    common_timezones = [
        'UTC', 'US/Eastern', 'US/Central', 'US/Mountain', 'US/Pacific', 
        'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Asia/Tokyo', 
        'Asia/Shanghai', 'Australia/Sydney', 'America/New_York', 
        'America/Chicago', 'America/Denver', 'America/Los_Angeles'
    ]
    try:
        all_timezones = sorted(pytz.all_timezones)
        form.timezone.choices = [(tz, tz) for tz in common_timezones] + [(tz, tz) for tz in all_timezones if tz not in common_timezones]
    except Exception as e:
        # Fallback to just common timezones if there's an issue
        form.timezone.choices = [(tz, tz) for tz in common_timezones]
    
    if form.validate_on_submit():
        # Handle verify email button
        if form.verify_email.data:
            # Generate verification token
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            token = serializer.dumps({'user_id': current_user.user_id}, salt='email-verification')
            
            # Send verification email
            try:
                verification_link = url_for('verify_email', token=token, _external=True)
                msg = Message(
                    subject='SilentCanary - Verify Your Email',
                    sender=('SilentCanary', app.config['MAIL_DEFAULT_SENDER']),
                    recipients=[current_user.email],
                    html=f'''
                    <h2>Email Verification</h2>
                    <p>Hello {current_user.username},</p>
                    <p>Please verify your email address to complete your SilentCanary account setup.</p>
                    <p>Click the link below to verify your email:</p>
                    <p><a href="{verification_link}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email Address</a></p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this verification, please ignore this email.</p>
                    <hr>
                    <p><small>SilentCanary</small></p>
                    '''
                )
                mail.send(msg)
                flash('Verification email sent! Check your inbox and click the link to verify your email.')
            except Exception as e:
                flash('Failed to send verification email. Please try again.')
                print(f"Email error: {e}")
            return redirect(url_for('settings'))
            
        # Handle delete account button
        elif form.delete_account.data:
            try:
                # Delete all user's canaries first
                canaries = Canary.get_by_user_id(current_user.user_id)
                for canary in canaries:
                    canary.delete()
                
                # Delete user account
                user_email = current_user.email
                username = current_user.username
                
                # Delete from DynamoDB
                from models import users_table
                users_table.delete_item(Key={'user_id': current_user.user_id})
                
                # Log out user
                logout_user()
                
                flash(f'Account {username} ({user_email}) has been permanently deleted.')
                return redirect(url_for('index'))
                
            except Exception as e:
                flash('Failed to delete account. Please try again.')
                print(f"Delete account error: {e}")
                return redirect(url_for('settings'))
        
        # Handle regular settings update
        else:
            # Check if user is trying to change password
            if form.new_password.data:
                if not form.current_password.data:
                    flash('Current password is required when changing password')
                    return render_template('settings.html', form=form)
                if not current_user.check_password(form.current_password.data):
                    flash('Current password is incorrect')
                    return render_template('settings.html', form=form)
                current_user.set_password(form.new_password.data)
            
            # Update timezone
            current_user.timezone = form.timezone.data
            
            if current_user.save():
                flash('Settings updated successfully!')
            else:
                flash('Failed to update settings.')
            return redirect(url_for('settings'))
    
    # Always populate form data (for both GET and failed POST requests)
    form.username.data = current_user.username
    form.email.data = current_user.email
    if not form.timezone.data:
        form.timezone.data = current_user.timezone or 'UTC'
    
    return render_template('settings.html', form=form)

@app.route('/edit_canary/<canary_id>', methods=['GET', 'POST'])
@login_required
def edit_canary(canary_id):
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    form = CanaryForm()
    
    if form.validate_on_submit():
        canary.name = form.name.data
        canary.interval_minutes = form.interval_minutes.data
        canary.grace_minutes = form.grace_minutes.data
        canary.alert_type = form.alert_type.data
        canary.alert_email = form.alert_email.data if form.alert_email.data else None
        canary.slack_webhook = form.slack_webhook.data if form.slack_webhook.data else None
        
        # Recalculate next expected check-in if interval changed
        if canary.last_checkin:
            if isinstance(canary.last_checkin, str):
                last_checkin_dt = datetime.fromisoformat(canary.last_checkin.replace('Z', '+00:00'))
            else:
                last_checkin_dt = canary.last_checkin
            canary.next_expected = (last_checkin_dt + timedelta(minutes=canary.interval_minutes)).isoformat()
        
        if canary.save():
            flash(f'Canary "{canary.name}" updated successfully')
        else:
            flash('Failed to update canary')
        return redirect(url_for('dashboard'))
    
    # Pre-populate form with current values
    if request.method == 'GET':
        form.name.data = canary.name
        form.interval_minutes.data = canary.interval_minutes
        form.grace_minutes.data = canary.grace_minutes
        form.alert_type.data = canary.alert_type
        form.alert_email.data = canary.alert_email
        form.slack_webhook.data = canary.slack_webhook
    
    return render_template('edit_canary.html', form=form, canary=canary)

@app.route('/delete_canary/<canary_id>', methods=['POST'])
@login_required
def delete_canary(canary_id):
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    canary_name = canary.name
    if canary.delete():
        flash(f'Canary "{canary_name}" deleted')
    else:
        flash('Failed to delete canary')
    return redirect(url_for('dashboard'))

@app.route('/canary_logs/<canary_id>')
@login_required
def canary_logs(canary_id):
    # Verify canary ownership
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    # Get pagination parameters
    page = int(request.args.get('page', 1))
    per_page = 25
    last_evaluated_key = request.args.get('last_key')
    
    # Decode last_evaluated_key if present
    if last_evaluated_key:
        import json
        import base64
        try:
            last_evaluated_key = json.loads(base64.b64decode(last_evaluated_key))
        except:
            last_evaluated_key = None
    
    # Get logs with pagination
    result = CanaryLog.get_by_canary_id(canary_id, limit=per_page, last_evaluated_key=last_evaluated_key)
    logs = result['logs']
    has_more = result['has_more']
    next_key = result['last_evaluated_key']
    
    # Encode next_key for URL
    next_key_encoded = None
    if next_key:
        import json
        import base64
        next_key_encoded = base64.b64encode(json.dumps(next_key, default=str).encode()).decode()
    
    return render_template('canary_logs.html', 
                         canary=canary, 
                         logs=logs, 
                         has_more=has_more,
                         next_key=next_key_encoded,
                         page=page)

def send_notifications(canary, log_entry=None):
    """Send notifications based on canary alert type and log timestamps."""
    subject = f'SilentCanary Alert: {canary.name} has failed'
    
    # Get user for email fallback
    user = User.get_by_id(canary.user_id)
    
    # Email message with HTML formatting
    html_message = f'''
    <h2>🚨 SilentCanary Alert</h2>
    <p>Your canary "<strong>{canary.name}</strong>" has failed to check in!</p>
    
    <h3>Details:</h3>
    <ul>
        <li><strong>Last check-in:</strong> {canary.last_checkin or 'Never'}</li>
        <li><strong>Expected check-in:</strong> {canary.next_expected or 'N/A'}</li>
        <li><strong>Grace period:</strong> {canary.grace_minutes} minutes</li>
        <li><strong>Check-in interval:</strong> {canary.interval_minutes} minutes</li>
    </ul>
    
    <p>Please investigate your monitoring target immediately.</p>
    
    <hr>
    <p><small>This alert was sent by SilentCanary</small></p>
    '''
    
    # Slack message with markdown formatting
    slack_message = f"""🚨 *SilentCanary Alert*

Canary "*{canary.name}*" has failed to check in!

• Last check-in: {canary.last_checkin or 'Never'}
• Expected check-in: {canary.next_expected or 'N/A'}
• Grace period: {canary.grace_minutes} minutes
• Check-in interval: {canary.interval_minutes} minutes

Please investigate your monitoring target immediately."""

    from datetime import datetime, timezone
    
    try:
        # Send email notification
        if canary.alert_type in ['email', 'both']:
            recipient = canary.alert_email or (user.email if user else None)
            if recipient:
                try:
                    msg = Message(
                        subject=subject,
                        sender=('SilentCanary', app.config['MAIL_DEFAULT_SENDER']),
                        recipients=[recipient],
                        html=html_message
                    )
                    mail.send(msg)
                    print(f"📧 Email notification sent to {recipient}")
                    
                    # Log successful email notification
                    if log_entry:
                        log_entry.update_email_notification('sent')
                        
                except Exception as e:
                    print(f"❌ Email notification failed: {e}")
                    # Log failed email notification
                    if log_entry:
                        log_entry.update_email_notification('failed')
            else:
                print("❌ No email recipient available")
                # Log that email was not required
                if log_entry:
                    log_entry.update_email_notification('not_required')
        
        # Send Slack notification
        if canary.alert_type in ['slack', 'both'] and canary.slack_webhook:
            try:
                payload = {"text": slack_message}
                response = requests.post(canary.slack_webhook, json=payload)
                if response.status_code == 200:
                    print(f"💬 Slack notification sent")
                    
                    # Log successful Slack notification
                    if log_entry:
                        log_entry.update_slack_notification('sent')
                        
                else:
                    print(f"❌ Slack notification failed: {response.status_code}")
                    # Log failed Slack notification
                    if log_entry:
                        log_entry.update_slack_notification('failed')
                        
            except Exception as e:
                print(f"❌ Slack notification error: {e}")
                # Log failed Slack notification
                if log_entry:
                    log_entry.update_slack_notification('failed')
        elif canary.alert_type in ['slack', 'both']:
            # Slack was requested but no webhook available
            if log_entry:
                log_entry.update_slack_notification('not_configured')
        
    except Exception as e:
        print(f"❌ Error sending notifications: {e}")
        # Log general failure
        if log_entry:
            if canary.alert_type in ['email', 'both'] and not log_entry.email_status:
                log_entry.update_email_notification('failed')
            if canary.alert_type in ['slack', 'both'] and not log_entry.slack_status:
                log_entry.update_slack_notification('failed')

@app.route('/api/canaries/status')
@login_required
def api_canaries_status():
    """API endpoint to get current canary status for real-time updates"""
    try:
        canaries = Canary.get_by_user_id(current_user.user_id)
        canary_status = []
        
        for canary in canaries:
            # Check if canary is overdue in real-time
            is_overdue = canary.is_overdue()
            current_status = 'failed' if is_overdue else canary.status
            
            canary_data = {
                'canary_id': canary.canary_id,
                'name': canary.name,
                'status': current_status,
                'last_checkin': canary.last_checkin,
                'next_expected': canary.next_expected,
                'is_overdue': is_overdue
            }
            canary_status.append(canary_data)
        
        return jsonify({
            'status': 'success',
            'canaries': canary_status,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def check_failed_canaries():
    with app.app_context():
        print(f"🔍 Checking for failed canaries at {datetime.now(timezone.utc)}")
        active_canaries = Canary.get_active_canaries()
        
        failed_count = 0
        for canary in active_canaries:
            if canary.status != 'failed' and canary.is_overdue():
                print(f"⚠️ Canary '{canary.name}' is overdue - sending notifications")
                canary.status = 'failed'
                canary.save()
                
                # Log the miss event
                miss_log = CanaryLog.log_miss(canary.canary_id, f"Canary '{canary.name}' missed expected check-in")
                
                # Send notifications and log timestamps
                send_notifications(canary, miss_log)
                failed_count += 1
        
        if failed_count > 0:
            print(f"📧 Processed {failed_count} failed canaries")
        else:
            print("✅ All canaries are healthy")

# Start scheduler automatically when module is imported (not just when run as main)
def start_background_scheduler():
    """Start the scheduler for background canary monitoring"""
    if not scheduler.running:
        try:
            scheduler.add_job(
                func=check_failed_canaries,
                trigger="interval",
                minutes=1,
                id='canary_check'
            )
            scheduler.start()
            print("✅ Background scheduler started successfully")
        except Exception as e:
            print(f"❌ Failed to start background scheduler: {e}")

# Initialize scheduler when module loads
start_background_scheduler()

if __name__ == '__main__':
    # Initialize DynamoDB tables
    print("🔄 Initializing DynamoDB...")
    try:
        # Test connection
        dynamodb = get_dynamodb_resource()
        print("✅ DynamoDB connection successful")
    except Exception as e:
        print(f"❌ DynamoDB connection failed: {e}")
        exit(1)
    
    print("✅ Scheduler already initialized during module import")
    
    try:
        app.run(debug=False, port=5000, host='0.0.0.0')
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()