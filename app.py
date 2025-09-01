from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from functools import wraps
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField, SelectField, FloatField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional, NumberRange, ValidationError
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from apscheduler.schedulers.background import BackgroundScheduler
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import os
import uuid
import pytz
import requests

# Import our DynamoDB models
from models import User, Canary, CanaryLog, SmartAlert, get_dynamodb_resource

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'asdfkjahc rha384y92834yc cx832b48234918xb487214jhasf')
app.config['PREFERRED_URL_SCHEME'] = 'https'

# Handle proxy headers for HTTPS detection
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

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
    sla_threshold = FloatField('SLA Threshold (%)', validators=[
        DataRequired(),
        NumberRange(min=0.0, max=100.0, message='SLA threshold must be between 0 and 100')
    ], default=99.9)
    tags = StringField('Tags', validators=[Optional()], 
                      render_kw={'placeholder': 'database, prod, api (comma-separated)'})
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
        # Process tags - split by comma and clean up whitespace
        tags = []
        if form.tags.data:
            tags = [tag.strip() for tag in form.tags.data.split(',') if tag.strip()]
        
        canary = Canary(
            name=form.name.data,
            user_id=current_user.user_id,
            interval_minutes=form.interval_minutes.data,
            grace_minutes=form.grace_minutes.data,
            alert_type=form.alert_type.data,
            alert_email=form.alert_email.data if form.alert_email.data else None,
            slack_webhook=form.slack_webhook.data if form.slack_webhook.data else None,
            sla_threshold=form.sla_threshold.data,
            tags=tags
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
    
    # Get custom message from POST data, JSON data, or query parameters
    custom_message = None
    if request.method == 'POST':
        # Try to get message from JSON data first
        if request.is_json:
            custom_message = request.get_json().get('message')
        # Then try form data
        elif request.form:
            custom_message = request.form.get('message')
    
    # Also check query parameters for both GET and POST
    if not custom_message:
        custom_message = request.args.get('message')
    
    # Sanitize message (limit length and remove potentially harmful content)
    if custom_message:
        custom_message = str(custom_message)[:500]  # Limit to 500 characters
        custom_message = custom_message.strip()
        if not custom_message:
            custom_message = None
    
    canary.checkin(source_ip=source_ip, user_agent=user_agent, custom_message=custom_message)
    
    response_data = {'status': 'success', 'message': 'Check-in received'}
    if custom_message:
        response_data['received_message'] = custom_message
    
    return jsonify(response_data)

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
    
    if request.method == 'POST':
        # Handle API key actions (these are not form fields, so handle them first)
        if request.form.get('generate_api_key'):
            print(f"DEBUG: Generate API key requested for user {current_user.user_id}")
            result = current_user.generate_api_key()
            print(f"DEBUG: generate_api_key returned: {result}")
            print(f"DEBUG: User API key after generation: {current_user.api_key}")
            if result:
                flash('API key generated successfully!', 'success')
            else:
                flash('Failed to generate API key. Please try again.', 'error')
            return redirect(url_for('settings'))
            
        elif request.form.get('regenerate_api_key'):
            if current_user.regenerate_api_key():
                flash('API key regenerated successfully! Please update your CI/CD configurations.', 'success')
            else:
                flash('Failed to regenerate API key. Please try again.', 'error')
            return redirect(url_for('settings'))
            
        elif request.form.get('delete_api_key'):
            if current_user.delete_api_key():
                flash('API key deleted successfully. CI/CD integrations will stop working.', 'warning')
            else:
                flash('Failed to delete API key. Please try again.', 'error')
            return redirect(url_for('settings'))
    
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
        canary.sla_threshold = Decimal(str(form.sla_threshold.data))
        
        # Process tags - split by comma and clean up whitespace
        tags = []
        if form.tags.data:
            tags = [tag.strip() for tag in form.tags.data.split(',') if tag.strip()]
        canary.tags = tags
        
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
        form.sla_threshold.data = canary.sla_threshold
        form.tags.data = ', '.join(canary.tags) if canary.tags else ''
    
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

@app.route('/canary_analytics/<canary_id>')
@login_required
def canary_analytics(canary_id):
    """Display analytics for a specific canary"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        flash('Canary not found or access denied')
        return redirect(url_for('dashboard'))
    
    # Get analytics data for different time periods
    days_30 = canary.get_uptime_stats(30)
    days_7 = canary.get_uptime_stats(7)
    days_1 = canary.get_uptime_stats(1)
    
    # Get downtime incidents
    incidents = canary.get_downtime_incidents(30)
    
    # Get trend analysis
    trends = canary.get_trend_analysis(30)
    
    # Check SLA status
    sla_status = canary.check_sla_breach(30)
    
    return render_template('canary_analytics.html',
                         canary=canary,
                         stats_30=days_30,
                         stats_7=days_7,
                         stats_1=days_1,
                         incidents=incidents,
                         trends=trends,
                         sla_status=sla_status)

@app.route('/test_failure_data/<canary_id>')
@login_required
def test_failure_data(canary_id):
    """Generate test failure data for analytics (development only)"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        flash('Canary not found or access denied')
        return redirect(url_for('dashboard'))
    
    # Generate some test failure logs across different hours and days
    import random
    from datetime import timedelta
    
    base_time = datetime.now(timezone.utc) - timedelta(days=7)
    
    for i in range(10):  # Create 10 test failures
        # Random hour between 0-23 and random day within the past week
        random_hours = random.randint(0, 23)
        random_days = random.randint(0, 6)
        test_time = base_time + timedelta(days=random_days, hours=random_hours)
        
        # Create a test log entry with the specific timestamp
        test_log = CanaryLog(
            canary_id=canary_id,
            event_type='miss',
            status='failed',
            message=f'Test failure at {test_time}',
            timestamp=test_time.isoformat()
        )
        test_log.save()
    
    flash(f'Generated 10 test failure entries for {canary.name}', 'success')
    return redirect(url_for('canary_analytics', canary_id=canary_id))

@app.route('/export_canary_data/<canary_id>/<format>')
@login_required
def export_canary_data(canary_id, format):
    """Export canary analytics data in CSV or JSON format"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        flash('Canary not found or access denied')
        return redirect(url_for('dashboard'))
    
    # Get comprehensive analytics data
    stats = canary.get_uptime_stats(30)
    incidents = canary.get_downtime_incidents(30)
    trends = canary.get_trend_analysis(30)
    sla_status = canary.check_sla_breach(30)
    
    if format.lower() == 'json':
        import json
        from flask import Response
        
        data = {
            'canary': {
                'id': canary.canary_id,
                'name': canary.name,
                'interval_minutes': canary.interval_minutes,
                'grace_minutes': canary.grace_minutes,
                'sla_threshold': canary.sla_threshold,
                'created_at': canary.created_at
            },
            'uptime_stats': stats,
            'downtime_incidents': [
                {
                    'start_time': inc['start_time'].isoformat() if inc['start_time'] else None,
                    'end_time': inc['end_time'].isoformat() if inc['end_time'] else None,
                    'duration_seconds': inc['duration_seconds'],
                    'resolved': inc['resolved']
                } for inc in incidents
            ],
            'trend_analysis': trends,
            'sla_status': sla_status,
            'export_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        response = Response(
            json.dumps(data, indent=2, default=str),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename={canary.name}_analytics.json'}
        )
        return response
    
    elif format.lower() == 'csv':
        import csv
        import io
        from flask import Response
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write canary info header
        writer.writerow(['Canary Analytics Report'])
        writer.writerow(['Generated:', datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')])
        writer.writerow(['Canary Name:', canary.name])
        writer.writerow(['Interval:', f'{canary.interval_minutes} minutes'])
        writer.writerow(['SLA Threshold:', f'{canary.sla_threshold}%'])
        writer.writerow([])
        
        # Write uptime statistics
        writer.writerow(['Uptime Statistics (Last 30 Days)'])
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Uptime Percentage', f"{stats['uptime_percentage']}%"])
        writer.writerow(['Downtime (seconds)', stats['downtime_seconds']])
        writer.writerow(['Total Incidents', stats['total_incidents']])
        writer.writerow([])
        
        # Write SLA status
        writer.writerow(['SLA Status'])
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Current Uptime', f"{sla_status['current_uptime']}%"])
        writer.writerow(['SLA Threshold', f"{sla_status['sla_threshold']}%"])
        writer.writerow(['SLA Breach', 'Yes' if sla_status['is_breach'] else 'No'])
        writer.writerow(['Difference', f"{sla_status['difference']:.2f}%"])
        writer.writerow([])
        
        # Write incidents
        writer.writerow(['Downtime Incidents'])
        writer.writerow(['Start Time', 'End Time', 'Duration (minutes)', 'Resolved'])
        for incident in incidents:
            start_str = incident['start_time'].strftime('%Y-%m-%d %H:%M:%S') if incident['start_time'] else 'N/A'
            end_str = incident['end_time'].strftime('%Y-%m-%d %H:%M:%S') if incident['end_time'] else 'Ongoing'
            duration_min = round(incident['duration_seconds'] / 60, 2) if incident['duration_seconds'] else 0
            writer.writerow([start_str, end_str, duration_min, 'Yes' if incident['resolved'] else 'No'])
        writer.writerow([])
        
        # Write trend analysis
        writer.writerow(['Failure Trends by Hour'])
        writer.writerow(['Hour', 'Failures'])
        for hour, count in trends['hourly_failures'].items():
            writer.writerow([f'{hour}:00', count])
        writer.writerow([])
        
        writer.writerow(['Failure Trends by Day'])
        writer.writerow(['Day', 'Failures'])
        for day, count in trends['daily_failures'].items():
            writer.writerow([day, count])
        
        output.seek(0)
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename={canary.name}_analytics.csv'}
        )
        return response
    
    else:
        flash('Invalid export format. Use CSV or JSON.')
        return redirect(url_for('canary_analytics', canary_id=canary_id))

@app.route('/smart_alert/<canary_id>')
@login_required
def smart_alert_config(canary_id):
    """Configure smart alerting for a canary"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        flash('Canary not found or access denied')
        return redirect(url_for('dashboard'))
    
    # Get existing smart alert configuration
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    
    return render_template('smart_alert_config.html', canary=canary, smart_alert=smart_alert)

@app.route('/enable_smart_alert/<canary_id>', methods=['POST'])
@login_required
def enable_smart_alert(canary_id):
    """Enable smart alerting for a canary"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    # Get form data
    sensitivity = request.form.get('sensitivity', 0.8)
    learning_period = request.form.get('learning_period', 7)
    
    try:
        sensitivity = max(0.5, min(1.0, float(sensitivity)))
        learning_period = max(1, min(30, int(learning_period)))
    except (ValueError, TypeError):
        flash('Invalid configuration values')
        return redirect(url_for('smart_alert_config', canary_id=canary_id))
    
    # Create or update smart alert
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    if smart_alert:
        smart_alert.is_enabled = True
        smart_alert.sensitivity = Decimal(str(sensitivity))
        smart_alert.learning_period_days = learning_period
    else:
        smart_alert = SmartAlert(
            canary_id=canary_id,
            user_id=current_user.user_id,
            sensitivity=Decimal(str(sensitivity)),
            learning_period_days=learning_period
        )
    
    if smart_alert.save():
        # Start learning patterns
        if smart_alert.learn_patterns():
            flash(f'Smart alerting enabled for "{canary.name}" and patterns learned successfully!', 'success')
        else:
            flash(f'Smart alerting enabled for "{canary.name}", but insufficient data for pattern learning. Patterns will be learned as more check-ins occur.', 'warning')
    else:
        flash('Failed to enable smart alerting')
    
    return redirect(url_for('smart_alert_config', canary_id=canary_id))

@app.route('/disable_smart_alert/<canary_id>', methods=['POST'])
@login_required
def disable_smart_alert(canary_id):
    """Disable smart alerting for a canary"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    if smart_alert:
        smart_alert.is_enabled = False
        if smart_alert.save():
            flash(f'Smart alerting disabled for "{canary.name}"')
        else:
            flash('Failed to disable smart alerting')
    
    return redirect(url_for('smart_alert_config', canary_id=canary_id))

@app.route('/relearn_patterns/<canary_id>', methods=['POST'])
@login_required
def relearn_patterns(canary_id):
    """Re-learn patterns for smart alerting"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    if smart_alert and smart_alert.is_enabled:
        if smart_alert.learn_patterns():
            flash(f'Patterns re-learned successfully for "{canary.name}"!', 'success')
        else:
            flash('Insufficient data to learn patterns. More check-ins are needed.', 'warning')
    else:
        flash('Smart alerting is not enabled for this canary')
    
    return redirect(url_for('smart_alert_config', canary_id=canary_id))

@app.route('/smart_alert_progress/<canary_id>', methods=['GET'])
@login_required
def smart_alert_progress(canary_id):
    """API endpoint to get learning progress for a Smart Alert"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        return jsonify({'status': 'error', 'message': 'Canary not found'}), 404
    
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    if not smart_alert:
        return jsonify({
            'status': 'error', 
            'message': 'Smart alerting is not enabled for this canary',
            'progress': 0,
            'confidence': 0
        }), 404
    
    # Get learning progress information
    progress = smart_alert.get_learning_progress()
    return jsonify(progress)

@app.route('/smart_alert_insights/<canary_id>', methods=['GET'])
@login_required
def smart_alert_insights(canary_id):
    """API endpoint to get pattern insights for Smart Alerts"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        return jsonify({'error': 'Canary not found'}), 404
    
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    if not smart_alert or not smart_alert.is_enabled:
        return jsonify({'error': 'Smart alerting not enabled'}), 404
    
    # Get pattern insights
    insights = {
        'timing_patterns': [],
        'anomaly_indicators': [],
        'next_expected': None,
        'confidence': 0
    }
    
    if smart_alert.pattern_data:
        pattern_data = smart_alert.pattern_data
        
        # Generate timing pattern insights
        if pattern_data.get('avg_interval'):
            avg_interval = float(pattern_data['avg_interval'])
            expected_interval = pattern_data.get('expected_interval', avg_interval)
            std_dev = float(pattern_data.get('interval_std', 0))
            
            insights['timing_patterns'].append(f"You typically check in every {expected_interval:.1f} minutes")
            
            if std_dev > 0:
                insights['timing_patterns'].append(f"Your timing varies by ±{std_dev:.1f} minutes normally")
            
            if pattern_data.get('total_checkins', 0) > 0:
                insights['timing_patterns'].append(f"Analysis based on {pattern_data['total_checkins']} check-ins")
        
        # Check for recent anomalies
        recent_logs_data = CanaryLog.get_by_canary_id(canary_id, limit=5)
        recent_logs = recent_logs_data.get('logs', [])
        if recent_logs:
            for log in recent_logs:
                if hasattr(log, 'anomaly_score') and log.anomaly_score and float(log.anomaly_score) > 0.6:
                    try:
                        log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                        time_ago = (datetime.utcnow().replace(tzinfo=timezone.utc) - log_time).total_seconds() / 60
                        insights['anomaly_indicators'].append(f"Unusual timing detected {time_ago:.0f} minutes ago")
                    except:
                        insights['anomaly_indicators'].append("Recent anomaly detected")
        
        # Predict next expected check-in
        if pattern_data.get('expected_interval') and canary.last_checkin:
            from datetime import datetime, timedelta
            try:
                last_checkin = datetime.fromisoformat(canary.last_checkin.replace('Z', '+00:00'))
                next_expected = last_checkin + timedelta(minutes=expected_interval)
                insights['next_expected'] = next_expected.strftime('%Y-%m-%d %H:%M UTC')
                insights['confidence'] = min(95, max(50, 100 - (std_dev / avg_interval * 100)))
            except:
                pass
    
    return jsonify(insights)

@app.route('/smart_alert_timeline/<canary_id>', methods=['GET'])
@login_required
def smart_alert_timeline(canary_id):
    """API endpoint to get check-in timeline with pattern analysis"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        return jsonify({'error': 'Canary not found'}), 404
    
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    if not smart_alert or not smart_alert.is_enabled:
        return jsonify({'error': 'Smart alerting not enabled'}), 404
    
    # Get recent check-ins
    recent_logs_data = CanaryLog.get_by_canary_id(canary_id, limit=10)
    recent_logs = recent_logs_data.get('logs', [])
    
    timeline_data = {
        'checkins': [],
        'summary': None
    }
    
    if recent_logs:
        pattern_data = smart_alert.pattern_data or {}
        expected_interval = pattern_data.get('expected_interval', 60)  # Default 1 hour
        interval_std = float(pattern_data.get('interval_std', 30))  # Default 30 min std
        
        prev_checkin = None
        anomaly_count = 0
        
        for log in recent_logs:
            try:
                log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                formatted_time = log_time.strftime('%m/%d %H:%M')
            except:
                formatted_time = str(log.timestamp)[:16]  # Fallback formatting
                
            checkin_data = {
                'timestamp': formatted_time,
                'interval': None,
                'pattern_match': 100,
                'analysis': 'Normal',
                'anomaly_score': 0
            }
            
            # Calculate interval from previous check-in
            if prev_checkin:
                try:
                    prev_time = datetime.fromisoformat(prev_checkin.timestamp.replace('Z', '+00:00'))
                    curr_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                    interval_minutes = (prev_time - curr_time).total_seconds() / 60
                except:
                    interval_minutes = 0
                checkin_data['interval'] = f"{interval_minutes:.1f} min"
                
                # Calculate pattern match percentage
                if expected_interval > 0:
                    deviation = abs(interval_minutes - expected_interval)
                    if interval_std > 0:
                        # Use statistical deviation to calculate match
                        z_score = deviation / interval_std
                        pattern_match = max(0, min(100, 100 - (z_score * 20)))  # Scale z-score to percentage
                    else:
                        # Simple percentage deviation
                        pattern_match = max(0, min(100, 100 - (deviation / expected_interval * 100)))
                    
                    checkin_data['pattern_match'] = round(pattern_match)
                    checkin_data['anomaly_score'] = (100 - pattern_match) / 100
                    
                    # Analysis based on deviation
                    if pattern_match < 60:
                        checkin_data['analysis'] = 'Significant deviation from normal pattern'
                        anomaly_count += 1
                    elif pattern_match < 80:
                        checkin_data['analysis'] = 'Slightly irregular timing'
                    else:
                        checkin_data['analysis'] = 'Matches expected pattern'
            
            timeline_data['checkins'].append(checkin_data)
            prev_checkin = log
        
        # Generate summary
        total_checkins = len(recent_logs)
        if total_checkins > 0:
            normal_count = total_checkins - anomaly_count
            if anomaly_count == 0:
                timeline_data['summary'] = f"All {total_checkins} recent check-ins match your normal patterns perfectly."
            elif anomaly_count == 1:
                timeline_data['summary'] = f"{normal_count} of {total_checkins} check-ins are normal. 1 check-in shows unusual timing."
            else:
                timeline_data['summary'] = f"{normal_count} of {total_checkins} check-ins are normal. {anomaly_count} check-ins show unusual timing patterns."
    
    return jsonify(timeline_data)

@app.route('/smart_alert_logic/<canary_id>', methods=['GET'])
@login_required
def smart_alert_logic(canary_id):
    """API endpoint to explain current alert logic and thresholds"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        return jsonify({'error': 'Canary not found'}), 404
    
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    if not smart_alert or not smart_alert.is_enabled:
        return jsonify({'error': 'Smart alerting not enabled'}), 404
    
    logic_data = {
        'current_thresholds': [],
        'recent_evaluations': [],
        'explanation': None
    }
    
    if smart_alert.pattern_data:
        pattern_data = smart_alert.pattern_data
        expected_interval = pattern_data.get('expected_interval', 60)
        sensitivity = float(smart_alert.sensitivity)
        interval_std = float(pattern_data.get('interval_std', 30))
        
        # Calculate actual alert thresholds
        alert_threshold_minutes = expected_interval * (1 + sensitivity)
        warning_threshold_minutes = expected_interval * (1 + sensitivity * 0.7)
        
        logic_data['current_thresholds'] = [
            {
                'condition': 'Critical Alert Threshold',
                'value': f'{alert_threshold_minutes:.1f} minutes late'
            },
            {
                'condition': 'Warning Threshold',  
                'value': f'{warning_threshold_minutes:.1f} minutes late'
            },
            {
                'condition': 'Expected Interval',
                'value': f'{expected_interval:.1f} minutes'
            },
            {
                'condition': 'Normal Variance Accepted',
                'value': f'±{interval_std:.1f} minutes'
            },
            {
                'condition': 'Sensitivity Setting',
                'value': f'{sensitivity * 100:.0f}%'
            }
        ]
        
        # Get recent check-ins to simulate evaluations
        recent_logs_data = CanaryLog.get_by_canary_id(canary_id, limit=3)
        recent_logs = recent_logs_data.get('logs', [])
        if recent_logs:
            for log in recent_logs:
                # Calculate if this check-in would have triggered an alert
                time_since_expected = 0
                would_trigger = False
                result = "Normal"
                reason = "Check-in occurred within expected timeframe"
                
                # Simple simulation - in reality this would be more complex
                if hasattr(log, 'interval_from_expected'):
                    time_since_expected = getattr(log, 'interval_from_expected', 0)
                    if time_since_expected > alert_threshold_minutes:
                        would_trigger = True
                        result = "ALERT"
                        reason = f"Check-in was {time_since_expected:.1f} minutes late (threshold: {alert_threshold_minutes:.1f})"
                    elif time_since_expected > warning_threshold_minutes:
                        would_trigger = False
                        result = "Warning"
                        reason = f"Check-in was {time_since_expected:.1f} minutes late (within warning range)"
                
                try:
                    log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                    formatted_time = log_time.strftime('%m/%d %H:%M')
                except:
                    formatted_time = str(log.timestamp)[:16]
                    
                logic_data['recent_evaluations'].append({
                    'timestamp': formatted_time,
                    'would_trigger': would_trigger,
                    'result': result,
                    'reason': reason
                })
        
        logic_data['explanation'] = f"""
        Smart alerts trigger when your check-in patterns deviate significantly from learned behavior. 
        With {sensitivity * 100:.0f}% sensitivity, alerts activate when check-ins are {alert_threshold_minutes:.1f} minutes late 
        (your normal {expected_interval:.1f}-minute interval + {sensitivity * 100:.0f}% tolerance). 
        The system accounts for your typical ±{interval_std:.1f} minute variance in timing.
        """
    else:
        logic_data['explanation'] = "Alert thresholds will be calculated once sufficient check-in data is collected and patterns are learned."
    
    return jsonify(logic_data)

# CI/CD Integration API Routes
@app.route('/api/v1/deployment/webhook', methods=['POST'])
def deployment_webhook():
    """Webhook endpoint for CI/CD deployments to auto-create/manage canaries"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Validate required fields
        required_fields = ['service_name', 'environment', 'deployment_id']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        # Extract deployment information
        service_name = data['service_name']
        environment = data['environment']
        deployment_id = data['deployment_id']
        pipeline_url = data.get('pipeline_url')
        commit_sha = data.get('commit_sha')
        branch = data.get('branch', 'main')
        user_id = data.get('user_id')  # Optional: if provided, link to specific user
        template_name = data.get('template', 'default')
        
        # Authentication via API key or user_id
        api_key = request.headers.get('X-API-Key')
        if api_key:
            # Validate API key (implement API key validation)
            user_id = validate_api_key(api_key)
            if not user_id:
                return jsonify({'error': 'Invalid API key'}), 401
        elif not user_id:
            return jsonify({'error': 'Either X-API-Key header or user_id field required'}), 401
        
        # Check if user exists
        user = User.get_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate canary name
        canary_name = f"{service_name}-{environment}"
        
        # Check if canary already exists for this service/environment
        existing_canaries = Canary.get_by_user_id(user_id)
        existing_canary = None
        for canary in existing_canaries:
            if canary.name == canary_name:
                existing_canary = canary
                break
        
        if existing_canary:
            # Update existing canary with deployment info
            result = update_canary_for_deployment(existing_canary, data)
            return jsonify({
                'status': 'updated',
                'canary_id': existing_canary.canary_id,
                'message': f'Updated existing canary for {service_name} in {environment}',
                'canary_url': f"{request.url_root}canary/{existing_canary.canary_id}",
                'deployment_info': result
            })
        else:
            # Create new canary from template
            new_canary = create_canary_from_template(user_id, service_name, environment, template_name, data)
            return jsonify({
                'status': 'created',
                'canary_id': new_canary.canary_id,
                'canary_token': new_canary.token,
                'message': f'Created new canary for {service_name} in {environment}',
                'canary_url': f"{request.url_root}canary/{new_canary.canary_id}",
                'check_in_url': f"{request.url_root}ping/{new_canary.token}",
                'deployment_info': {
                    'deployment_id': deployment_id,
                    'commit_sha': commit_sha,
                    'branch': branch,
                    'pipeline_url': pipeline_url
                }
            })
            
    except Exception as e:
        print(f"❌ Deployment webhook error: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/api/v1/canary/template', methods=['POST'])
def create_canary_from_api():
    """API endpoint to create canary with template"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Validate API key
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'X-API-Key header required'}), 401
            
        user_id = validate_api_key(api_key)
        if not user_id:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Validate required fields
        required_fields = ['name', 'interval_minutes']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        # Create canary
        canary = create_canary_from_data(user_id, data)
        
        return jsonify({
            'status': 'success',
            'canary_id': canary.canary_id,
            'canary_token': canary.token,
            'check_in_url': f"{request.url_root}ping/{canary.token}",
            'dashboard_url': f"{request.url_root}canary/{canary.canary_id}"
        })
        
    except Exception as e:
        print(f"❌ API canary creation error: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/api/v1/canary/<canary_id>/deployment', methods=['POST'])
def update_canary_deployment(canary_id):
    """Update canary with new deployment information"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Validate API key
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'X-API-Key header required'}), 401
            
        user_id = validate_api_key(api_key)
        if not user_id:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Get canary and validate ownership
        canary = Canary.get_by_id(canary_id)
        if not canary or canary.user_id != user_id:
            return jsonify({'error': 'Canary not found'}), 404
        
        # Update deployment metadata
        deployment_info = {
            'deployment_id': data.get('deployment_id'),
            'commit_sha': data.get('commit_sha'),
            'branch': data.get('branch'),
            'pipeline_url': data.get('pipeline_url'),
            'deployed_at': datetime.utcnow().isoformat(),
            'version': data.get('version'),
            'environment': data.get('environment')
        }
        
        # Store deployment info (would need to add deployment_metadata field to Canary model)
        # For now, log the deployment
        CanaryLog.log_deployment(canary_id, deployment_info)
        
        return jsonify({
            'status': 'success',
            'message': 'Deployment information updated',
            'deployment_info': deployment_info
        })
        
    except Exception as e:
        print(f"❌ Deployment update error: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

# Help Documentation Routes
@app.route('/help')
@app.route('/help/overview')
def help_overview():
    """Help overview page"""
    return render_template('help/overview.html')

@app.route('/help/getting-started')
def help_getting_started():
    """Getting started guide"""
    return render_template('help/getting_started.html')

@app.route('/help/examples')
def help_examples():
    """Real-world examples"""
    return render_template('help/examples.html')

@app.route('/help/smart-alerts')
def help_smart_alerts():
    """Smart alerts documentation"""
    return render_template('help/smart_alerts.html')

@app.route('/help/api')
def help_api():
    """API documentation"""
    return render_template('help/api.html')

@app.route('/help/troubleshooting')
def help_troubleshooting():
    """Troubleshooting guide"""
    return render_template('help/troubleshooting.html')

@app.route('/help/faq')
def help_faq():
    """Frequently asked questions"""
    return render_template('help/faq.html')

@app.route('/help/cicd-integration')
def help_cicd_integration():
    """CI/CD Integration documentation"""
    return render_template('help/cicd_integration.html')

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

def validate_api_key(api_key):
    """Validate API key and return associated user_id"""
    # Simple API key validation - in production, store API keys in database
    # For now, use a simple format: "user_id:secret" encoded in base64
    try:
        import base64
        decoded = base64.b64decode(api_key).decode('utf-8')
        if ':' in decoded:
            user_id, secret = decoded.split(':', 1)
            # Validate user exists and secret matches expected pattern
            user = User.get_by_id(user_id)
            if user and secret == f"secret_{user_id[:8]}":  # Simple secret validation
                return user_id
        return None
    except:
        return None

def create_canary_from_template(user_id, service_name, environment, template_name, deployment_data):
    """Create a new canary based on a template"""
    # Define templates
    templates = {
        'default': {
            'interval_minutes': 60,
            'alert_type': 'both',
            'smart_alerts_enabled': True,
            'description': 'Auto-created from CI/CD deployment'
        },
        'microservice': {
            'interval_minutes': 30,
            'alert_type': 'slack',
            'smart_alerts_enabled': True,
            'description': 'Microservice monitoring canary'
        },
        'batch_job': {
            'interval_minutes': 1440,  # 24 hours
            'alert_type': 'email',
            'smart_alerts_enabled': False,
            'description': 'Daily batch job monitoring'
        },
        'api_service': {
            'interval_minutes': 15,
            'alert_type': 'both',
            'smart_alerts_enabled': True,
            'description': 'High-frequency API service monitoring'
        }
    }
    
    template = templates.get(template_name, templates['default'])
    
    # Create canary with template settings
    canary_name = f"{service_name}-{environment}"
    canary = Canary(
        user_id=user_id,
        name=canary_name,
        description=f"{template['description']} - {service_name} in {environment}",
        interval_minutes=template['interval_minutes'],
        alert_type=template['alert_type'],
        is_active=True
    )
    
    # Override with any provided settings
    if 'interval_minutes' in deployment_data:
        canary.interval_minutes = deployment_data['interval_minutes']
    if 'alert_type' in deployment_data:
        canary.alert_type = deployment_data['alert_type']
    if 'email' in deployment_data:
        canary.email = deployment_data['email']
    if 'slack_webhook' in deployment_data:
        canary.slack_webhook = deployment_data['slack_webhook']
    
    canary.save()
    
    # Enable smart alerts if template requires it
    if template.get('smart_alerts_enabled') and deployment_data.get('enable_smart_alerts', True):
        smart_alert = SmartAlert(
            canary_id=canary.canary_id,
            user_id=user_id,
            sensitivity=Decimal('0.8'),
            learning_period_days=7,
            is_enabled=True
        )
        smart_alert.save()
    
    # Log the creation
    CanaryLog.log_deployment(canary.canary_id, {
        'event': 'canary_created',
        'deployment_id': deployment_data.get('deployment_id'),
        'commit_sha': deployment_data.get('commit_sha'),
        'template': template_name,
        'created_by': 'ci_cd_webhook'
    })
    
    return canary

def create_canary_from_data(user_id, data):
    """Create canary from direct API data"""
    canary = Canary(
        user_id=user_id,
        name=data['name'],
        description=data.get('description', 'Created via API'),
        interval_minutes=data['interval_minutes'],
        alert_type=data.get('alert_type', 'email'),
        email=data.get('email'),
        slack_webhook=data.get('slack_webhook'),
        is_active=data.get('is_active', True)
    )
    
    canary.save()
    
    # Enable smart alerts if requested
    if data.get('enable_smart_alerts', False):
        smart_alert = SmartAlert(
            canary_id=canary.canary_id,
            user_id=user_id,
            sensitivity=Decimal(str(data.get('smart_alert_sensitivity', 0.8))),
            learning_period_days=data.get('smart_alert_learning_period', 7),
            is_enabled=True
        )
        smart_alert.save()
    
    return canary

def update_canary_for_deployment(canary, deployment_data):
    """Update existing canary with new deployment information"""
    # Log the deployment
    deployment_info = {
        'event': 'deployment_updated',
        'deployment_id': deployment_data.get('deployment_id'),
        'commit_sha': deployment_data.get('commit_sha'),
        'branch': deployment_data.get('branch'),
        'pipeline_url': deployment_data.get('pipeline_url'),
        'updated_by': 'ci_cd_webhook'
    }
    
    CanaryLog.log_deployment(canary.canary_id, deployment_info)
    
    # Update canary description if provided
    if 'description' in deployment_data:
        canary.description = deployment_data['description']
        canary.save()
    
    return deployment_info

def send_smart_alert_notifications(canary, log_entry, smart_alert):
    """Send smart alert notifications with ML context"""
    subject = f'SilentCanary Smart Alert: {canary.name} pattern anomaly detected'
    
    # Get user for email fallback
    user = User.get_by_id(canary.user_id)
    
    # Create enhanced message for smart alerts
    pattern_info = ""
    if smart_alert.pattern_data:
        avg_interval = smart_alert.pattern_data.get('avg_interval', canary.interval_minutes)
        expected_interval = smart_alert.pattern_data.get('expected_interval', canary.interval_minutes)
        pattern_info = f"""
        <h3>🧠 Smart Alert Details:</h3>
        <ul>
            <li><strong>Expected average interval:</strong> {avg_interval:.1f} minutes</li>
            <li><strong>Configured interval:</strong> {expected_interval} minutes</li>
            <li><strong>Sensitivity:</strong> {float(smart_alert.sensitivity) * 100:.1f}%</li>
            <li><strong>Analysis period:</strong> {smart_alert.learning_period_days} days</li>
        </ul>
        <p><em>This alert was triggered by machine learning analysis of your check-in patterns, indicating behavior that deviates from your normal schedule.</em></p>
        """
    
    # Email message with ML context
    html_message = f'''
    <h2>🧠 SilentCanary Smart Alert</h2>
    <p>Our machine learning system detected an anomaly in your canary "<strong>{canary.name}</strong>" check-in patterns!</p>
    
    <h3>Current Status:</h3>
    <ul>
        <li><strong>Last check-in:</strong> {canary.last_checkin or 'Never'}</li>
        <li><strong>Next expected:</strong> {canary.next_expected or 'N/A'}</li>
        <li><strong>Current status:</strong> {canary.status}</li>
    </ul>
    
    {pattern_info}
    
    <h3>🔧 What to do:</h3>
    <ol>
        <li>Check if your process is running normally</li>
        <li>Verify if this timing change is expected</li>
        <li>If this is normal behavior, you can adjust sensitivity in Smart Alert settings</li>
        <li>Consider if external factors might be affecting your schedule</li>
    </ol>
    
    <p><strong>Dashboard:</strong> <a href="{request.url_root}dashboard">View Dashboard</a></p>
    <p><strong>Smart Alerts:</strong> <a href="{request.url_root}smart_alert/{canary.canary_id}">Configure Smart Alerts</a></p>
    
    <hr>
    <small>This is a smart alert - meaning it was triggered by pattern analysis, not just a simple timeout.</small>
    '''
    
    # Send notifications based on alert type
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
                    print(f"📧 Smart alert email sent to {recipient}")
                    
                    if log_entry:
                        log_entry.update_email_notification('sent')
                        
                except Exception as e:
                    print(f"❌ Smart alert email failed: {e}")
                    if log_entry:
                        log_entry.update_email_notification('failed', str(e))
        
        # Send Slack notification with ML context
        if canary.alert_type in ['slack', 'both'] and canary.slack_webhook:
            try:
                slack_message = {
                    "text": f"🧠 SilentCanary Smart Alert: Pattern anomaly detected",
                    "attachments": [
                        {
                            "color": "warning",
                            "title": f"Smart Alert: {canary.name}",
                            "fields": [
                                {
                                    "title": "Anomaly Detected",
                                    "value": f"ML analysis detected unusual check-in patterns",
                                    "short": True
                                },
                                {
                                    "title": "Last Check-in",
                                    "value": canary.last_checkin or 'Never',
                                    "short": True
                                },
                                {
                                    "title": "Sensitivity",
                                    "value": f"{float(smart_alert.sensitivity) * 100:.1f}%",
                                    "short": True
                                },
                                {
                                    "title": "Learning Period",
                                    "value": f"{smart_alert.learning_period_days} days",
                                    "short": True
                                }
                            ],
                            "footer": "SilentCanary Smart Alerts",
                            "footer_icon": "🧠"
                        }
                    ]
                }
                
                response = requests.post(canary.slack_webhook, json=slack_message, timeout=10)
                if response.status_code == 200:
                    print(f"💬 Smart alert Slack notification sent")
                    if log_entry:
                        log_entry.update_slack_notification('sent')
                else:
                    print(f"❌ Smart alert Slack notification failed: {response.status_code}")
                    if log_entry:
                        log_entry.update_slack_notification('failed', f'HTTP {response.status_code}')
                        
            except Exception as e:
                print(f"❌ Smart alert Slack notification failed: {e}")
                if log_entry:
                    log_entry.update_slack_notification('failed', str(e))
                    
    except Exception as e:
        print(f"❌ Smart alert notification system error: {e}")

def check_failed_canaries():
    with app.app_context():
        print(f"🔍 Checking for failed canaries at {datetime.now(timezone.utc)}")
        active_canaries = Canary.get_active_canaries()
        
        failed_count = 0
        smart_anomaly_count = 0
        learning_updates = 0
        
        for canary in active_canaries:
            # Check for regular failures (overdue based on interval + grace)
            if canary.status != 'failed' and canary.is_overdue():
                print(f"⚠️ Canary '{canary.name}' is overdue - sending notifications")
                canary.status = 'failed'
                canary.save()
                
                # Log the miss event
                miss_log = CanaryLog.log_miss(canary.canary_id, f"Canary '{canary.name}' missed expected check-in")
                
                # Send notifications and log timestamps
                send_notifications(canary, miss_log)
                failed_count += 1
            
            # Check for smart alert anomalies (even if not technically overdue)
            elif canary.status != 'failed':
                smart_alert = SmartAlert.get_by_canary_id(canary.canary_id)
                if smart_alert and smart_alert.is_enabled:
                    # Continuously update patterns if enabled
                    try:
                        # Check if patterns should be updated (every hour or when significant new data)
                        should_update = smart_alert.should_update_patterns()
                        if should_update:
                            print(f"🧠 Updating patterns for Smart Alert '{canary.name}'")
                            if smart_alert.learn_patterns():
                                learning_updates += 1
                                print(f"✅ Patterns updated successfully for '{canary.name}'")
                            else:
                                print(f"⚠️ Insufficient data for pattern update '{canary.name}'")
                    except Exception as e:
                        print(f"❌ Error updating patterns for '{canary.name}': {e}")
                    
                    # Check for anomalies
                    if smart_alert.is_anomaly():
                        print(f"🧠 Smart alert detected anomaly for '{canary.name}' - sending notifications")
                        
                        # Log the smart anomaly event
                        smart_log = CanaryLog.log_miss(canary.canary_id, f"Smart alert detected anomaly: '{canary.name}' pattern deviation")
                        
                        # Send notifications with smart alert context
                        send_smart_alert_notifications(canary, smart_log, smart_alert)
                        smart_anomaly_count += 1
        
        if failed_count > 0 or smart_anomaly_count > 0 or learning_updates > 0:
            status_parts = []
            if failed_count > 0:
                status_parts.append(f"{failed_count} failed canaries")
            if smart_anomaly_count > 0:
                status_parts.append(f"{smart_anomaly_count} smart anomalies")
            if learning_updates > 0:
                status_parts.append(f"{learning_updates} pattern updates")
            print(f"📧 Processed {', '.join(status_parts)}")
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