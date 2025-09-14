from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from functools import wraps
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
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
import time
import logging
import json
# Import our DynamoDB models  
from models import User, Canary, CanaryLog, SmartAlert, Subscription, SystemSettings, ContactRequest, get_dynamodb_resource

# Load environment variables from .env file
load_dotenv()

# Stripe integration for subscription payments
# Required environment variables for Stripe:
# - STRIPE_SECRET_KEY: Your Stripe secret key
# - STRIPE_WEBHOOK_SECRET: Webhook signing secret from Stripe dashboard
# - STRIPE_STARTUP_MONTHLY_PRICE_ID: Price ID for Startup monthly plan
# - STRIPE_STARTUP_ANNUAL_PRICE_ID: Price ID for Startup annual plan  
# - STRIPE_GROWTH_MONTHLY_PRICE_ID: Price ID for Growth monthly plan
# - STRIPE_GROWTH_ANNUAL_PRICE_ID: Price ID for Growth annual plan
# - STRIPE_ENTERPRISE_MONTHLY_PRICE_ID: Price ID for Enterprise monthly plan
# - STRIPE_ENTERPRISE_ANNUAL_PRICE_ID: Price ID for Enterprise annual plan

app = Flask(__name__)
# Security fix: Remove hardcoded fallback secret key
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    raise RuntimeError("SECRET_KEY environment variable must be set for security")
app.config['SECRET_KEY'] = secret_key
app.config['PREFERRED_URL_SCHEME'] = 'https'

# Initialize CSRF protection with extended timeout
app.config['WTF_CSRF_TIME_LIMIT'] = 7200  # 2 hours instead of default 1 hour
csrf = CSRFProtect(app)

# We'll add route debugging at the end of the file

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
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@silentcanary.com')

# reCAPTCHA configuration
app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY')

# Stripe configuration
app.config['STRIPE_PUBLISHABLE_KEY'] = os.environ.get('STRIPE_PUBLISHABLE_KEY')
app.config['STRIPE_SECRET_KEY'] = os.environ.get('STRIPE_SECRET_KEY')


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.unauthorized_handler
def unauthorized_callback():
    print(f"🚫 Unauthorized access attempt to: {request.endpoint}")
    print(f"🚫 Request URL: {request.url}")
    print(f"🚫 Request path: {request.path}")
    return redirect(url_for('login'))

@app.before_request
def log_all_requests():
    print(f"📍 REQUEST: {request.method} {request.path} -> Endpoint: {request.endpoint}")
    if request.path.startswith('/upgrade/'):
        print(f"📍 UPGRADE REQUEST INTERCEPTED: {request.path}")
        print(f"📍 User authenticated: {current_user.is_authenticated}")
        if current_user.is_authenticated:
            print(f"📍 User ID: {current_user.user_id}")
    return None  # Continue processing
mail = Mail(app)

# Add custom Jinja2 filters
from markupsafe import Markup

@app.template_filter('nl2br')
def nl2br(value):
    """Convert newlines to <br> tags"""
    if not value:
        return value
    return Markup(value.replace('\n', '<br>\n'))

# Email templating function
def send_templated_email(recipients, subject, template_name, **template_vars):
    """
    Send an email using consistent SilentCanary templates
    
    Args:
        recipients: List of email addresses or single email string
        subject: Email subject line
        template_name: Name of template file (without .html extension)
        **template_vars: Variables to pass to the template
    
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    try:
        if isinstance(recipients, str):
            recipients = [recipients]
            
        app.logger.info(f"Preparing to send email to {recipients} with subject: {subject}")
        
        # Render the template
        html_content = render_template(f'emails/{template_name}.html', **template_vars)
        
        # Create and send the message
        # Use RFC 2822 format for sender with display name
        sender_address = f"SilentCanary <{app.config['MAIL_DEFAULT_SENDER']}>"
        msg = Message(
            subject=subject,
            sender=sender_address,
            recipients=recipients,
            html=html_content
        )
        
        app.logger.info(f"Sending email via mail.send() to {recipients}")
        app.logger.info(f"Message details - From: {msg.sender}, To: {msg.recipients}, Subject: {msg.subject}")
        app.logger.info(f"Mail config - Server: {app.config['MAIL_SERVER']}, Username: {app.config['MAIL_USERNAME']}, Default_Sender: {app.config['MAIL_DEFAULT_SENDER']}")
        mail.send(msg)
        app.logger.info(f"Email sent successfully to {recipients}")
        return True
        
    except Exception as e:
        app.logger.error(f"Error sending templated email to {recipients}: {str(e)}")
        print(f"Error sending templated email: {e}")
        return False

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

@app.template_filter('parse_iso')
def parse_iso_filter(iso_string):
    """Template filter to parse ISO datetime string to datetime object."""
    if not iso_string:
        return None
    try:
        from datetime import datetime
        # Handle both with and without timezone info
        if iso_string.endswith('Z'):
            iso_string = iso_string[:-1] + '+00:00'
        return datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
    except:
        return None

# Custom validators
def validate_integer_required(form, field):
    """Custom validator that treats 0 as valid but requires a value"""
    if field.data is None:
        raise ValidationError('This field is required.')

def validate_secure_email(form, field):
    """Enhanced email validator with security checks"""
    if not field.data:
        return
    
    email = field.data.lower().strip()
    
    # Check for suspicious patterns
    suspicious_patterns = [
        '...',  # Multiple consecutive dots
        '..',   # Double dots
        '+--',  # Suspicious plus patterns
        '--+',  # Suspicious dash patterns
        'javascript:',  # XSS attempt
        'data:',        # Data URI scheme
        'vbscript:',    # VBScript attempt
    ]
    
    for pattern in suspicious_patterns:
        if pattern in email:
            raise ValidationError('Invalid email format detected.')
    
    # Check for excessively long local or domain parts
    if '@' in email:
        local, domain = email.split('@', 1)
        if len(local) > 64 or len(domain) > 255:
            raise ValidationError('Email address too long.')
        
        # Check for suspicious characters in local part
        import re
        if not re.match(r'^[a-zA-Z0-9._%+-]+$', local):
            raise ValidationError('Invalid characters in email address.')

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)], render_kw={'autocomplete': 'username'})
    email = StringField('Email', validators=[DataRequired(), Email(), validate_secure_email])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)], render_kw={'autocomplete': 'new-password'})
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')], render_kw={'autocomplete': 'new-password'})
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), validate_secure_email])
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'autocomplete': 'current-password'})
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
        ('slack', 'Webhook'),
        ('both', 'Email + Webhook')
    ], validators=[DataRequired()], default='email')
    alert_email = StringField('Alert Email', validators=[Optional(), Email(), validate_secure_email])
    slack_webhook = StringField('Slack-compatible Webhook URL', validators=[Optional()])
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
    anthropic_api_key = StringField('Anthropic API Key (Optional)', validators=[Optional()], render_kw={'placeholder': 'sk-ant-api03-... (for AI-powered insights)'})
    current_password = PasswordField('Current Password', render_kw={'autocomplete': 'current-password'})
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=8)], render_kw={'autocomplete': 'new-password'})
    confirm_password = PasswordField('Confirm New Password', validators=[Optional(), EqualTo('new_password')], render_kw={'autocomplete': 'new-password'})
    submit = SubmitField('Update Settings')
    verify_email = SubmitField('Verify Email')
    delete_account = SubmitField('Delete Account')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), validate_secure_email])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)], render_kw={'autocomplete': 'new-password'})
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], render_kw={'autocomplete': 'new-password'})
    submit = SubmitField('Reset Password')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=1, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email(), validate_secure_email])
    subject = StringField('Subject', validators=[DataRequired(), Length(min=1, max=200)])
    category = SelectField('Category', choices=[
        ('general', 'General Question'),
        ('technical', 'Technical Support'),
        ('billing', 'Billing & Payments'),
        ('feature', 'Feature Request'),
        ('bug', 'Bug Report'),
        ('enterprise', 'Enterprise Sales')
    ], validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10, max=2000)])
    submit = SubmitField('Send Message')


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

# Debug endpoints removed for security - Phase 4

# Security Headers - Phase 5
@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers to all responses"""
    # Content Security Policy - Prevent XSS and injection attacks
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://www.google.com https://www.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://www.google.com https://www.gstatic.com; "
        "frame-src https://www.google.com https://www.gstatic.com https://recaptcha.google.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    
    # Strict Transport Security - Force HTTPS
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # X-Frame-Options - Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # X-Content-Type-Options - Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # X-XSS-Protection - Enable XSS filtering
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer Policy - Control referrer information
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy - Restrict browser features
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=(), '
        'magnetometer=(), gyroscope=(), payment=()'
    )
    
    # Cache Control for sensitive pages
    if '/settings' in request.path or '/dashboard' in request.path:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

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
        # Validate reCAPTCHA if enabled
        if app.config.get('RECAPTCHA_SECRET_KEY'):
            recaptcha_response = request.form.get('g-recaptcha-response')
            client_ip = request.remote_addr
            
            if not recaptcha_response:
                flash('Please complete the reCAPTCHA verification.', 'error')
                return render_template('register.html', form=form)
            
            # Verify reCAPTCHA Enterprise with Google
            try:
                # Use reCAPTCHA Enterprise API
                project_id = app.config.get('RECAPTCHA_PROJECT_ID', 'silentcanary')
                recaptcha_api_key = app.config.get('RECAPTCHA_API_KEY', app.config['RECAPTCHA_SECRET_KEY'])
                
                # Prepare the request for reCAPTCHA Enterprise
                url = f"https://recaptchaenterprise.googleapis.com/v1/projects/{project_id}/assessments?key={recaptcha_api_key}"
                
                payload = {
                    "event": {
                        "token": recaptcha_response,
                        "expectedAction": "REGISTER",
                        "siteKey": app.config['RECAPTCHA_SITE_KEY']
                    }
                }
                
                headers = {
                    'Content-Type': 'application/json'
                }
                
                r = requests.post(url, json=payload, headers=headers)
                result = r.json()
                
                # Check if the assessment was successful
                if 'riskAnalysis' in result and result['riskAnalysis'].get('score', 0) >= 0.5:
                    # Valid reCAPTCHA with good score
                    pass
                elif 'tokenProperties' in result and result['tokenProperties'].get('valid', False):
                    # Valid token but potentially low score - we'll allow it
                    pass
                else:
                    # Log detailed error information
                    error_codes = result.get('error', {}).get('code', 'unknown')
                    app.logger.warning(f"reCAPTCHA Enterprise failed - IP: {client_ip}, Email: {form.email.data}, Error: {error_codes}")
                    
                    # Fall back to standard reCAPTCHA verification
                    app.logger.info("Falling back to standard reCAPTCHA verification")
                    fallback_data = {
                        'secret': app.config['RECAPTCHA_SECRET_KEY'],
                        'response': recaptcha_response,
                        'remoteip': request.remote_addr
                    }
                    
                    fallback_response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=fallback_data)
                    fallback_result = fallback_response.json()
                    
                    if not fallback_result.get('success', False):
                        app.logger.warning(f"Standard reCAPTCHA also failed - IP: {client_ip}, Email: {form.email.data}")
                        flash('reCAPTCHA verification failed. Please try again.', 'error')
                        return render_template('register.html', form=form)
                    
            except Exception as e:
                app.logger.error(f"reCAPTCHA Enterprise API error - IP: {client_ip}, Error: {str(e)}")
                # Fall back to standard reCAPTCHA verification
                try:
                    fallback_data = {
                        'secret': app.config['RECAPTCHA_SECRET_KEY'],
                        'response': recaptcha_response,
                        'remoteip': request.remote_addr
                    }
                    
                    fallback_response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=fallback_data)
                    fallback_result = fallback_response.json()
                    
                    if not fallback_result.get('success', False):
                        flash('reCAPTCHA verification failed. Please try again.', 'error')
                        return render_template('register.html', form=form)
                        
                except Exception as fallback_error:
                    app.logger.error(f"Both reCAPTCHA verification methods failed - IP: {client_ip}, Error: {str(fallback_error)}")
                    flash('reCAPTCHA verification error. Please try again.', 'error')
                    return render_template('register.html', form=form)
        
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
            # No subscription needed - unlimited free service
            
            # Send verification email automatically
            try:
                serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
                token = serializer.dumps({'user_id': user.user_id}, salt='email-verification')
                # Build verification link manually to avoid SERVER_NAME issues
                verification_link = f"https://silentcanary.com/verify_email/{token}"
                
                app.logger.info(f"Attempting to send verification email to {user.email} for user {user.username}")
                
                # Send welcome email using template
                email_sent = send_templated_email(
                    recipients=user.email,
                    subject='Welcome to SilentCanary - Please verify your email',
                    template_name='welcome_verify',
                    username=user.username,
                    verification_link=verification_link
                )
                
                if email_sent:
                    app.logger.info(f"Verification email sent successfully to {user.email}")
                    flash('Registration successful! Please check your email to verify your account.')
                else:
                    app.logger.error(f"Failed to send verification email to {user.email}")
                    flash('Registration successful! Please log in. Note: verification email could not be sent.')
                    
            except Exception as e:
                app.logger.error(f"Registration email exception: {str(e)}")
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
            # Security fix: Prevent open redirect attacks
            if next_page and next_page.startswith('/') and not next_page.startswith('//'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
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
                # Send password reset email using template
                send_templated_email(
                    recipients=user.email,
                    subject='SilentCanary - Password Reset Request',
                    template_name='password_reset',
                    username=user.username,
                    reset_link=reset_link
                )
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
    # No subscription limits - unlimited canaries
    
    # Get filter parameters
    tag_filter = request.args.get('tag')
    status_filter = request.args.get('status')
    
    # Get all user's canaries
    canaries = Canary.get_by_user_id(current_user.user_id)
    
    # Add smart alert information to each canary
    for canary in canaries:
        smart_alert = SmartAlert.get_by_canary_id(canary.canary_id)
        canary.smart_alert_enabled = smart_alert and smart_alert.is_enabled
        
        # Add smart alert tag if enabled
        if canary.smart_alert_enabled:
            if not canary.tags:
                canary.tags = []
            if 'Smart Alerts' not in canary.tags:
                canary.tags.append('Smart Alerts')
    
    # Apply filters
    filtered_canaries = canaries
    if tag_filter:
        filtered_canaries = [c for c in canaries if c.tags and tag_filter in c.tags]
    if status_filter:
        filtered_canaries = [c for c in filtered_canaries if c.status == status_filter]
    
    # Get all unique tags for filter dropdown
    all_tags = set()
    for canary in canaries:
        if canary.tags:
            all_tags.update(canary.tags)
    
    # Count canaries by tag
    tag_counts = {}
    for tag in all_tags:
        tag_counts[tag] = len([c for c in canaries if c.tags and tag in c.tags])
    
    # Count canaries by status
    status_counts = {}
    for canary in canaries:
        status = canary.status
        status_counts[status] = status_counts.get(status, 0) + 1
    
    return render_template('dashboard.html', 
                         canaries=filtered_canaries,
                         all_canaries=canaries,
                         all_tags=sorted(all_tags),
                         tag_counts=tag_counts,
                         status_counts=status_counts,
                         current_tag_filter=tag_filter,
                         current_status_filter=status_filter)

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
        
        # Enhanced email validation
        import re
        from email_validator import validate_email, EmailNotValidError
        try:
            # Use email-validator library for thorough validation
            validated_email = validate_email(new_email)
            new_email = validated_email.email  # Use normalized form
        except (EmailNotValidError, ImportError):
            # Fallback to more robust regex if email-validator is not available
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
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

@app.route('/admin/contact-requests')
@login_required
@admin_required
def admin_contact_requests():
    """Admin panel for managing contact requests"""
    try:
        # Get status filter
        status_filter = request.args.get('status', 'all')
        
        # Get contact requests
        if status_filter == 'all':
            contact_requests = ContactRequest.get_all(limit=200)
        else:
            contact_requests = ContactRequest.get_all(limit=200, status=status_filter)
        
        # Get statistics
        stats = ContactRequest.get_stats()
        
        return render_template('admin/contact_requests.html', 
                             contact_requests=contact_requests, 
                             stats=stats, 
                             status_filter=status_filter)
        
    except Exception as e:
        flash(f'Error loading contact requests: {e}', 'error')
        return redirect(url_for('admin'))

@app.route('/admin/contact-requests/<request_id>')
@login_required
@admin_required
def admin_view_contact_request(request_id):
    """View individual contact request"""
    try:
        contact_request = ContactRequest.get_by_id(request_id)
        if not contact_request:
            flash('Contact request not found', 'error')
            return redirect(url_for('admin_contact_requests'))
        
        return render_template('admin/view_contact_request.html', request=contact_request)
        
    except Exception as e:
        flash(f'Error loading contact request: {e}', 'error')
        return redirect(url_for('admin_contact_requests'))

@app.route('/admin/contact-requests/<request_id>/reply', methods=['POST'])
@login_required
@admin_required
def admin_reply_contact_request(request_id):
    """Reply to a contact request via email"""
    try:
        contact_request = ContactRequest.get_by_id(request_id)
        if not contact_request:
            flash('Contact request not found', 'error')
            return redirect(url_for('admin_contact_requests'))
        
        reply_message = request.form.get('reply_message', '').strip()
        if not reply_message:
            flash('Reply message is required', 'error')
            return redirect(url_for('admin_view_contact_request', request_id=request_id))
        
        # Send reply email from reza@silentcanary.com (QA setting)
        admin_email = 'reza@silentcanary.com'  # QA specific email
        
        try:
            # Send reply email to user
            send_templated_email(
                recipients=contact_request.email,
                subject=f'Re: {contact_request.subject}',
                template_name='contact_reply',
                user_name=contact_request.name,
                original_subject=contact_request.subject,
                original_message=contact_request.message,
                admin_reply=reply_message,
                admin_email=admin_email
            )
            
            # Mark request as replied
            if contact_request.reply(admin_email, reply_message):
                flash('Reply sent successfully!', 'success')
            else:
                flash('Email sent but failed to update request status', 'warning')
            
        except Exception as e:
            print(f"Error sending reply email: {e}")
            flash('Failed to send reply email', 'error')
        
        return redirect(url_for('admin_view_contact_request', request_id=request_id))
        
    except Exception as e:
        flash(f'Error processing reply: {e}', 'error')
        return redirect(url_for('admin_contact_requests'))

@app.route('/admin/contact-requests/<request_id>/close', methods=['POST'])
@login_required
@admin_required
def admin_close_contact_request(request_id):
    """Close a contact request"""
    try:
        contact_request = ContactRequest.get_by_id(request_id)
        if not contact_request:
            flash('Contact request not found', 'error')
            return redirect(url_for('admin_contact_requests'))
        
        if contact_request.mark_closed():
            flash('Contact request closed successfully', 'success')
        else:
            flash('Failed to close contact request', 'error')
            
        return redirect(url_for('admin_contact_requests'))
        
    except Exception as e:
        flash(f'Error closing contact request: {e}', 'error')
        return redirect(url_for('admin_contact_requests'))

@app.route('/admin/contact-requests/<request_id>/escalate', methods=['POST'])
@login_required
@admin_required
def admin_escalate_contact_request(request_id):
    """Escalate a contact request to different stage"""
    try:
        contact_request = ContactRequest.get_by_id(request_id)
        if not contact_request:
            flash('Contact request not found', 'error')
            return redirect(url_for('admin_contact_requests'))
        
        escalation_stage = request.form.get('escalation_stage')
        priority = request.form.get('priority')
        admin_email = current_user.email
        
        if escalation_stage:
            if contact_request.escalate(admin_email, escalation_stage, priority):
                flash(f'Request escalated to {escalation_stage.title()} stage', 'success')
            else:
                flash('Failed to escalate request', 'error')
        elif priority:
            if contact_request.set_priority(admin_email, priority):
                flash(f'Priority set to {priority.title()}', 'success')
            else:
                flash('Failed to set priority', 'error')
        
        return redirect(url_for('admin_view_contact_request', request_id=request_id))
        
    except Exception as e:
        flash(f'Error escalating request: {e}', 'error')
        return redirect(url_for('admin_contact_requests'))

@app.route('/admin/contact-requests/<request_id>/mark-progress', methods=['POST'])
@login_required
@admin_required
def admin_mark_progress_contact_request(request_id):
    """Mark contact request as in progress"""
    try:
        contact_request = ContactRequest.get_by_id(request_id)
        if not contact_request:
            flash('Contact request not found', 'error')
            return redirect(url_for('admin_contact_requests'))
        
        if contact_request.mark_in_progress(current_user.email):
            flash('Request marked as in progress', 'success')
        else:
            flash('Failed to update request status', 'error')
            
        return redirect(url_for('admin_view_contact_request', request_id=request_id))
        
    except Exception as e:
        flash(f'Error updating request: {e}', 'error')
        return redirect(url_for('admin_contact_requests'))

# Subscription functionality with Stripe integration

# Subscription and payment functionality with Stripe

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact form"""
    form = ContactForm()
    
    if form.validate_on_submit():
        try:
            # Save contact request to database
            contact_request = ContactRequest(
                name=form.name.data,
                email=form.email.data,
                subject=form.subject.data,
                category=form.category.data,
                message=form.message.data,
                status='new'
            )
            
            if contact_request.save():
                print(f"✅ Contact request saved to database: {contact_request.request_id}")
            else:
                print(f"❌ Failed to save contact request to database")
            
            # Send email notification to support team
            send_templated_email(
                recipients='support@silentcanary.com',
                subject=f'[SilentCanary Contact] {form.category.data.title()}: {form.subject.data}',
                template_name='contact_form',
                name=form.name.data,
                email=form.email.data,
                form_subject=form.subject.data,
                message=form.message.data,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            )
            
            # Send confirmation to user
            send_templated_email(
                recipients=form.email.data,
                subject='Your SilentCanary support request has been received',
                template_name='contact_confirmation',
                name=form.name.data,
                form_subject=form.subject.data,
                message=form.message.data
            )
            
            flash('✅ Message sent successfully! We\'ll get back to you soon.', 'success')
            return redirect(url_for('contact'))
            
        except Exception as e:
            print(f"Error processing contact form: {e}")
            flash('⚠️ There was an error sending your message. Please try again or email us directly at support@silentcanary.com', 'error')
    
    return render_template('contact.html', form=form)

@app.route('/pricing')
def subscription_plans():
    """Subscription plans page"""
    # Get user's current subscription and usage if logged in
    subscription = None
    usage = None
    
    if current_user.is_authenticated:
        try:
            from models import Subscription
            subscription = Subscription.get_by_user_id(current_user.user_id)
            
            # Calculate usage statistics
            if subscription:
                from models import Canary
                canaries = Canary.get_by_user_id(current_user.user_id)
                canaries_used = len(canaries) if canaries else 0
                
                # Define limits based on plan
                limits = {
                    'free': 1,
                    'startup': 5,
                    'growth': 25,
                    'enterprise': 100
                }
                
                canary_limit = limits.get(subscription.plan_name, 1)
                usage_percentage = min((canaries_used / canary_limit) * 100, 100) if canary_limit > 0 else 0
                
                usage = {
                    'canaries_used': canaries_used,
                    'canary_limit': canary_limit,
                    'usage_percentage': usage_percentage
                }
        except Exception as e:
            print(f"Error getting subscription info: {e}")
    
    return render_template('subscription_plans.html', subscription=subscription, usage=usage)

@app.route('/terms-of-service')
def terms_of_service():
    """Terms of Service page"""
    return render_template('terms_of_service.html')

@app.route('/privacy-policy')
def privacy_policy():
    """Privacy Policy page"""
    return render_template('privacy_policy.html')

@app.route('/cookie-policy')
def cookie_policy():
    """Cookie Policy page"""
    return render_template('cookie_policy.html')

@app.route('/sla')
def sla():
    """Service Level Agreement page"""
    return render_template('sla.html')

@app.route('/status')
def status():
    """Status page for all services"""
    return render_template('status.html')

@app.route('/resources/smart-alerts')
def resources_smart_alerts():
    """Resources: Smart Alerts page"""
    return render_template('help/smart_alerts.html')

@app.route('/resources/integrations')
def resources_integrations():
    """Resources: Integrations page"""
    return render_template('help/cicd_integration.html')

@app.route('/resources/api')
def resources_api():
    """Resources: API Reference page"""
    return render_template('help/api.html')

@app.route('/resources/examples')
def resources_examples():
    """Resources: Examples page"""
    return render_template('help/examples.html')

# Stripe webhooks for subscription management
import stripe
import hmac
import hashlib

stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhook events for subscription management"""
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
    
    try:
        # Verify webhook signature
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError:
        print("❌ Invalid payload")
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        print("❌ Invalid signature")
        return jsonify({'error': 'Invalid signature'}), 400
    
    # Handle the event
    if event['type'] == 'customer.subscription.created':
        handle_subscription_created(event['data']['object'])
    elif event['type'] == 'customer.subscription.updated':
        handle_subscription_updated(event['data']['object'])
    elif event['type'] == 'customer.subscription.deleted':
        handle_subscription_deleted(event['data']['object'])
    elif event['type'] == 'invoice.payment_succeeded':
        handle_payment_succeeded(event['data']['object'])
    elif event['type'] == 'invoice.payment_failed':
        handle_payment_failed(event['data']['object'])
    else:
        print(f"Unhandled event type: {event['type']}")
    
    return jsonify({'status': 'success'}), 200

def handle_subscription_created(subscription):
    """Handle new subscription creation"""
    try:
        customer_id = subscription['customer']
        customer = stripe.Customer.retrieve(customer_id)
        user_email = customer['email']
        
        # Find user by email
        user = User.get_by_email(user_email)
        if not user:
            print(f"❌ User not found for email: {user_email}")
            return
        
        # Get price to determine plan
        price_id = subscription['items']['data'][0]['price']['id']
        plan_name = get_plan_name_from_price_id(price_id)
        
        # Create or update subscription record
        sub = Subscription(
            user_id=user.user_id,
            plan_name=plan_name,
            stripe_customer_id=customer_id,
            stripe_subscription_id=subscription['id'],
            status='active',
            current_period_start=datetime.fromtimestamp(subscription['current_period_start'], tz=timezone.utc),
            current_period_end=datetime.fromtimestamp(subscription['current_period_end'], tz=timezone.utc)
        )
        
        if sub.save():
            print(f"✅ Subscription created for user {user_email}: {plan_name}")
        else:
            print(f"❌ Failed to save subscription for user {user_email}")
            
    except Exception as e:
        print(f"❌ Error handling subscription creation: {e}")

def handle_subscription_updated(subscription):
    """Handle subscription updates (plan changes, renewals, etc.)"""
    try:
        stripe_subscription_id = subscription['id']
        existing_sub = Subscription.get_by_stripe_subscription_id(stripe_subscription_id)
        
        if not existing_sub:
            print(f"❌ Subscription not found: {stripe_subscription_id}")
            return
        
        # Update subscription details
        price_id = subscription['items']['data'][0]['price']['id']
        plan_name = get_plan_name_from_price_id(price_id)
        
        existing_sub.plan_name = plan_name
        existing_sub.status = subscription['status']
        existing_sub.current_period_start = datetime.fromtimestamp(subscription['current_period_start'], tz=timezone.utc)
        existing_sub.current_period_end = datetime.fromtimestamp(subscription['current_period_end'], tz=timezone.utc)
        
        if existing_sub.save():
            print(f"✅ Subscription updated: {stripe_subscription_id}")
        else:
            print(f"❌ Failed to update subscription: {stripe_subscription_id}")
            
    except Exception as e:
        print(f"❌ Error handling subscription update: {e}")

def handle_subscription_deleted(subscription):
    """Handle subscription cancellation"""
    try:
        stripe_subscription_id = subscription['id']
        existing_sub = Subscription.get_by_stripe_subscription_id(stripe_subscription_id)
        
        if not existing_sub:
            print(f"❌ Subscription not found: {stripe_subscription_id}")
            return
        
        # Update subscription status to canceled
        existing_sub.status = 'canceled'
        existing_sub.plan_name = 'free'  # Revert to free plan
        
        if existing_sub.save():
            print(f"✅ Subscription canceled: {stripe_subscription_id}")
        else:
            print(f"❌ Failed to cancel subscription: {stripe_subscription_id}")
            
    except Exception as e:
        print(f"❌ Error handling subscription deletion: {e}")

def handle_payment_succeeded(invoice):
    """Handle successful payment"""
    try:
        customer_id = invoice['customer']
        subscription_id = invoice['subscription']
        
        print(f"✅ Payment succeeded for customer {customer_id}, subscription {subscription_id}")
        
        # You can add additional logic here like sending confirmation emails
        
    except Exception as e:
        print(f"❌ Error handling payment success: {e}")

def handle_payment_failed(invoice):
    """Handle failed payment"""
    try:
        customer_id = invoice['customer']
        subscription_id = invoice['subscription']
        
        print(f"❌ Payment failed for customer {customer_id}, subscription {subscription_id}")
        
        # You can add logic here to notify the user or handle dunning
        
    except Exception as e:
        print(f"❌ Error handling payment failure: {e}")

def get_plan_name_from_price_id(price_id):
    """Map Stripe price ID to internal plan name"""
    # You'll need to configure these price IDs in your Stripe dashboard
    price_to_plan = {
        # Monthly plans
        os.environ.get('STRIPE_STARTUP_MONTHLY_PRICE_ID', 'price_startup_monthly'): 'startup',
        os.environ.get('STRIPE_GROWTH_MONTHLY_PRICE_ID', 'price_growth_monthly'): 'growth',
        os.environ.get('STRIPE_ENTERPRISE_MONTHLY_PRICE_ID', 'price_enterprise_monthly'): 'enterprise',
        
        # Annual plans
        os.environ.get('STRIPE_STARTUP_ANNUAL_PRICE_ID', 'price_startup_annual'): 'startup',
        os.environ.get('STRIPE_GROWTH_ANNUAL_PRICE_ID', 'price_growth_annual'): 'growth',
        os.environ.get('STRIPE_ENTERPRISE_ANNUAL_PRICE_ID', 'price_enterprise_annual'): 'enterprise',
    }
    
    return price_to_plan.get(price_id, 'free')

@app.route('/create_canary', methods=['GET', 'POST'])
@login_required
def create_canary():
    # Check subscription limits based on user's plan
    
    form = CanaryForm()
    if form.validate_on_submit():
        # Process tags - split by comma and clean up whitespace
        tags = []
        if form.tags.data:
            tags = [tag.strip() for tag in form.tags.data.split(',') if tag.strip()]
        
        # Check if custom alert email is different from user's email
        alert_email = form.alert_email.data if form.alert_email.data else None
        needs_email_verification = (
            alert_email and 
            alert_email.strip().lower() != current_user.email.lower() and
            form.alert_type.data == 'email'
        )
        
        canary = Canary(
            name=form.name.data,
            user_id=current_user.user_id,
            interval_minutes=form.interval_minutes.data,
            grace_minutes=form.grace_minutes.data,
            alert_type=form.alert_type.data,
            alert_email=alert_email,
            slack_webhook=form.slack_webhook.data if form.slack_webhook.data else None,
            sla_threshold=form.sla_threshold.data,
            status='pending_verification' if needs_email_verification else 'waiting',
            tags=tags
        )
        
        if canary.save():
            # Handle Smart Alert creation if enabled
            if request.form.get('enable_smart_alerts'):
                # Map sensitivity threshold to decimal value
                from decimal import Decimal
                sensitivity_map = {
                    'high': Decimal('0.3'),    # More sensitive, catches more anomalies
                    'medium': Decimal('0.6'),  # Balanced detection
                    'low': Decimal('0.8')      # Less sensitive, only major anomalies
                }
                
                # Check if advanced sensitivity slider was used (overrides dropdown)
                sensitivity_value_input = request.form.get('sensitivity_value')
                if sensitivity_value_input:
                    sensitivity_value = Decimal(str(sensitivity_value_input))
                else:
                    # Fall back to dropdown selection
                    sensitivity_threshold = request.form.get('sensitivity_threshold', 'medium')
                    sensitivity_value = sensitivity_map.get(sensitivity_threshold, Decimal('0.6'))
                
                # Get learning period from form (defaults to 7 days)
                learning_period = int(request.form.get('learning_period', 7))
                
                smart_alert = SmartAlert(
                    canary_id=canary.canary_id,
                    user_id=current_user.user_id,
                    name=f"Smart Alert for {canary.name}",
                    sensitivity=sensitivity_value,
                    learning_period_days=learning_period,
                    is_enabled=True
                )
                
                if smart_alert.save():
                    app.logger.info(f"Smart Alert created for canary {canary.canary_id} with sensitivity {sensitivity_value}")
                else:
                    app.logger.warning(f"Failed to create Smart Alert for canary {canary.canary_id}")
            
            if needs_email_verification:
                # Create email verification record
                from models import EmailVerification
                verification = EmailVerification(
                    canary_id=canary.canary_id,
                    user_id=current_user.user_id,
                    email=alert_email
                )
                
                if verification.save():
                    # Send verification email
                    if send_verification_email(verification, canary):
                        flash(f'Canary "{canary.name}" created! A verification email has been sent to {alert_email}. Please verify your email to activate the canary.', 'warning')
                    else:
                        flash(f'Canary created but failed to send verification email. Please contact support.', 'warning')
                else:
                    flash(f'Canary created but email verification setup failed. Please contact support.', 'error')
            else:
                flash(f'Canary "{canary.name}" created successfully!')
            
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to create canary. Please try again.')
    
    return render_template('create_canary.html', form=form)

def send_verification_email(verification, canary):
    """Send email verification email for canary alert email"""
    try:
        verification_url = f'https://silentcanary.com/verify-email/{verification.verification_id}'
        
        # Use templated email instead of hardcoded HTML
        success = send_templated_email(
            recipients=verification.email,
            subject='Verify Your Email for SilentCanary Alert',
            template_name='canary_verification',
            canary_name=canary.name,
            verification_code=verification.verification_code,
            verification_url=verification_url
        )
        
        if not success:
            raise Exception("Failed to send canary verification email")
        print(f"📧 Verification email sent to {verification.email} for canary {canary.name}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to send verification email: {e}")
        return False

@app.route('/verify-email/<verification_id>')
def verify_canary_email(verification_id):
    """Handle email verification link clicks"""
    try:
        from models import EmailVerification, Canary
        
        verification = EmailVerification.get_by_verification_id(verification_id)
        if not verification:
            flash('Invalid or expired verification link.', 'error')
            return redirect(url_for('index'))
        
        # Verify the email
        success, message = verification.verify(verification.verification_code)
        
        if success:
            # Activate the canary
            canary = Canary.get_by_id(verification.canary_id)
            if canary:
                canary.status = 'waiting'
                canary.save()
                
                flash(f'✅ Email verified successfully! Your canary "{canary.name}" is now active and will send alerts to {verification.email}.', 'success')
            else:
                flash('Email verified but canary not found. Please contact support.', 'warning')
        else:
            flash(f'Email verification failed: {message}', 'error')
    
    except Exception as e:
        print(f"Error in email verification: {e}")
        flash('An error occurred during verification. Please try again.', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/verify-email-code', methods=['POST'])
@login_required
def verify_email_code():
    """Handle manual verification code entry"""
    try:
        data = request.get_json()
        if not data or 'canary_id' not in data or 'code' not in data:
            return jsonify({'success': False, 'error': 'Missing canary_id or verification code'}), 400
        
        from models import EmailVerification, Canary
        
        verification = EmailVerification.get_by_canary_id(data['canary_id'])
        if not verification:
            return jsonify({'success': False, 'error': 'No verification found for this canary'}), 404
        
        # Check if user owns this canary
        canary = Canary.get_by_id(data['canary_id'])
        if not canary or canary.user_id != current_user.user_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        # Verify the code
        success, message = verification.verify(data['code'].strip())
        
        if success:
            # Activate the canary
            canary.status = 'waiting'
            canary.save()
            
            return jsonify({
                'success': True, 
                'message': f'Email verified successfully! Your canary "{canary.name}" is now active.'
            })
        else:
            return jsonify({'success': False, 'error': message})
    
    except Exception as e:
        print(f"Error in manual verification: {e}")
        return jsonify({'success': False, 'error': 'An error occurred during verification'}), 500

@app.route('/resend-verification', methods=['POST'])
@login_required
def resend_verification():
    """Resend verification email for a canary"""
    try:
        data = request.get_json()
        if not data or 'canary_id' not in data:
            return jsonify({'success': False, 'error': 'Missing canary_id'}), 400
        
        from models import EmailVerification, Canary
        
        # Check if user owns this canary
        canary = Canary.get_by_id(data['canary_id'])
        if not canary or canary.user_id != current_user.user_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        if canary.status != 'pending_verification':
            return jsonify({'success': False, 'error': 'This canary is not pending verification'}), 400
        
        # Get existing verification
        verification = EmailVerification.get_by_canary_id(data['canary_id'])
        if not verification:
            return jsonify({'success': False, 'error': 'No verification found for this canary'}), 404
        
        # Check if not already verified
        if verification.is_verified:
            return jsonify({'success': False, 'error': 'Email is already verified'}), 400
        
        # Generate new verification code and extend expiration
        from datetime import datetime, timezone, timedelta
        verification.verification_code = verification._generate_verification_code()
        verification.expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        
        if verification.save():
            # Send new verification email
            if send_verification_email(verification, canary):
                return jsonify({
                    'success': True, 
                    'message': f'New verification email sent to {verification.email}'
                })
            else:
                return jsonify({'success': False, 'error': 'Failed to send verification email'}), 500
        else:
            return jsonify({'success': False, 'error': 'Failed to update verification'}), 500
    
    except Exception as e:
        print(f"Error in resend verification: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

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
    
    # Debug logging removed for security - Phase 4
    
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
        if request.form.get('create_api_key'):
            from models import APIKey
            api_key_name = request.form.get('api_key_name', 'API Key').strip()
            if not api_key_name:
                api_key_name = f"API Key {len(APIKey.get_by_user_id(current_user.user_id)) + 1}"
            
            # Generate new API key
            key_value = APIKey.generate_key_value(current_user.user_id)
            api_key = APIKey(
                user_id=current_user.user_id,
                name=api_key_name,
                key_value=key_value,
                is_active=True
            )
            
            if api_key.save():
                flash(f'API key "{api_key_name}" created successfully!', 'success')
            else:
                flash('Failed to create API key. Please try again.', 'error')
            return redirect(url_for('settings'))
            
        elif 'delete_api_key' in request.form:
            from models import APIKey
            api_key_id = request.form.get('api_key_id')
            if api_key_id:
                api_key = APIKey.get_by_id(api_key_id)
                if api_key and api_key.user_id == current_user.user_id:
                    if api_key.delete():
                        flash(f'API key "{api_key.name}" deleted successfully.', 'warning')
                    else:
                        flash('Failed to delete API key. Please try again.', 'error')
                else:
                    flash('API key not found or access denied.', 'error')
            return redirect(url_for('settings'))
            
        elif request.form.get('toggle_api_key'):
            from models import APIKey
            api_key_id = request.form.get('api_key_id')
            if api_key_id:
                api_key = APIKey.get_by_id(api_key_id)
                if api_key and api_key.user_id == current_user.user_id:
                    api_key.is_active = not api_key.is_active
                    if api_key.save():
                        status = 'activated' if api_key.is_active else 'deactivated'
                        flash(f'API key "{api_key.name}" {status} successfully.', 'success')
                    else:
                        flash('Failed to update API key. Please try again.', 'error')
                else:
                    flash('API key not found or access denied.', 'error')
            return redirect(url_for('settings'))
    
    if form.validate_on_submit():
        # Handle verify email button
        if form.verify_email.data:
            # Generate verification token
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            token = serializer.dumps({'user_id': current_user.user_id}, salt='email-verification')
            
            # Send verification email
            try:
                # Build verification link manually to avoid SERVER_NAME issues
                verification_link = f"https://silentcanary.com/verify_email/{token}"
                # Send email verification using template
                send_templated_email(
                    recipients=current_user.email,
                    subject='SilentCanary - Verify Your Email Address',
                    template_name='email_verification',
                    username=current_user.username,
                    verification_link=verification_link
                )
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
            
            # Update Anthropic API key with validation
            new_api_key = form.anthropic_api_key.data.strip() if form.anthropic_api_key.data else None
            api_key_validated = False
            
            # Validate API key if provided and changed
            if new_api_key and new_api_key != current_user.anthropic_api_key:
                is_valid, message = validate_anthropic_api_key(new_api_key)
                if is_valid:
                    current_user.anthropic_api_key = new_api_key
                    flash(f'Settings updated successfully! {message}', 'success')
                    api_key_validated = True
                else:
                    flash(f'API key validation failed: {message}', 'error')
                    return render_template('settings.html', form=form)
            elif new_api_key is None and current_user.anthropic_api_key:
                # User is clearing the key
                current_user.anthropic_api_key = None
                flash('Settings updated successfully! AI features disabled.', 'info')
                api_key_validated = True
            
            # Save changes
            if current_user.save():
                # Only show generic success if we haven't shown a specific API key message
                if not api_key_validated:
                    flash('Settings updated successfully!')
            else:
                flash('Failed to update settings.')
            return redirect(url_for('settings'))
    
    # Always populate form data (for both GET and failed POST requests)
    form.username.data = current_user.username
    form.email.data = current_user.email
    if not form.timezone.data:
        form.timezone.data = current_user.timezone or 'UTC'
    if not form.anthropic_api_key.data:
        form.anthropic_api_key.data = current_user.anthropic_api_key or ''
    
    # Get user's API keys
    from models import APIKey
    api_keys = APIKey.get_by_user_id(current_user.user_id)
    
    # Get user's subscription information
    subscription = None
    usage = None
    upgrade_options = None
    
    try:
        from models import Subscription, Canary
        subscription = Subscription.get_by_user_id(current_user.user_id)
        
        # If no subscription exists, create a default Solo (free) plan
        if not subscription:
            subscription = Subscription(
                user_id=current_user.user_id,
                plan_name='free',
                status='active',
                canary_limit=1,
                current_period_start=datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(),
                current_period_end=None  # Free plan doesn't expire
            )
            subscription.save()
            print(f"✅ Created default Solo subscription for user {current_user.email}")
        
        if subscription:
            # Calculate current usage
            canaries = Canary.get_by_user_id(current_user.user_id)
            canaries_used = len(canaries) if canaries else 0
            
            # Define plan limits and pricing
            plan_config = {
                'free': {'limit': 1, 'price': 0, 'next_plan': 'startup'},
                'startup': {'limit': 5, 'price': 7, 'next_plan': 'growth'},
                'growth': {'limit': 25, 'price': 25, 'next_plan': 'enterprise'},
                'enterprise': {'limit': 100, 'price': 75, 'next_plan': None}
            }
            
            current_plan = plan_config.get(subscription.plan_name, plan_config['free'])
            usage_percentage = min((canaries_used / current_plan['limit']) * 100, 100) if current_plan['limit'] > 0 else 0
            
            usage = {
                'canaries_used': canaries_used,
                'canary_limit': current_plan['limit'],
                'usage_percentage': usage_percentage,
                'plan_name': subscription.plan_name,
                'plan_price': current_plan['price'],
                'status': subscription.status
            }
            
            # Determine upgrade options
            if current_plan['next_plan']:
                next_plan_config = plan_config[current_plan['next_plan']]
                upgrade_options = {
                    'next_plan': current_plan['next_plan'],
                    'next_plan_limit': next_plan_config['limit'],
                    'next_plan_price': next_plan_config['price'],
                    'additional_canaries': next_plan_config['limit'] - current_plan['limit']
                }
                
    except Exception as e:
        print(f"❌ Error getting subscription info in settings: {e}")
        import traceback
        print(f"❌ Settings traceback: {traceback.format_exc()}")
    
    return render_template('settings.html', form=form, api_keys=api_keys, 
                         subscription=subscription, usage=usage, upgrade_options=upgrade_options)

@app.route('/account')
@login_required
def account_management():
    """Account management dashboard showing subscription, usage, and billing information"""
    print(f"🎯 Starting account_management for user: {current_user.email}")
    try:
        # Get current subscription
        subscription = Subscription.get_by_user_id(current_user.user_id)
        print(f"🔍 Found subscription: {subscription}")
        
        # If no subscription exists, create a default Solo (free) plan
        if not subscription:
            subscription = Subscription(
                user_id=current_user.user_id,
                plan_name='free',
                status='active',
                canary_limit=1,
                current_period_start=datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(),
                current_period_end=None  # Free plan doesn't expire
            )
            result = subscription.save()
            print(f"✅ Created default Solo subscription for user {current_user.email}, save result: {result}")
        
        # Get usage information
        usage = None
        if subscription:
            usage = subscription.get_usage()
        
        # Get billing history (if available)
        billing_history = []
        stripe_customer_id = None
        
        if subscription and subscription.stripe_customer_id:
            stripe_customer_id = subscription.stripe_customer_id
            
            # Try to get billing history from Stripe
            import stripe
            stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
            
            if stripe.api_key:
                try:
                    # Get recent invoices
                    invoices = stripe.Invoice.list(
                        customer=stripe_customer_id,
                        limit=10
                    )
                    
                    for invoice in invoices.data:
                        billing_history.append({
                            'id': invoice.id,
                            'date': datetime.fromtimestamp(invoice.created).strftime('%Y-%m-%d'),
                            'amount': invoice.amount_paid / 100,  # Convert from cents
                            'currency': invoice.currency.upper(),
                            'status': invoice.status,
                            'invoice_pdf': invoice.invoice_pdf,
                            'description': f"{subscription.plan_name.title()} Plan"
                        })
                except Exception as e:
                    print(f"Error fetching billing history: {e}")
        
        # Get plan features for current plan
        plan_features = {
            'free': {
                'canary_limit': 1,
                'features': ['1 Canary', 'Complete Feature Set', 'Email Alerts', 'Web Dashboard', 'API Access', 'Smart Alerts (AI)', 'Advanced Analytics', 'Custom Webhooks', 'Email Support']
            },
            'startup': {
                'canary_limit': 5,
                'features': ['5 Canaries', 'Complete Feature Set', 'Email Alerts', 'Web Dashboard', 'API Access', 'Smart Alerts (AI)', 'Advanced Analytics', 'Custom Webhooks', 'Email Support']
            },
            'growth': {
                'canary_limit': 25,
                'features': ['25 Canaries', 'Complete Feature Set', 'Email Alerts', 'Web Dashboard', 'API Access', 'Smart Alerts (AI)', 'Advanced Analytics', 'Custom Webhooks', 'Priority Support']
            },
            'enterprise': {
                'canary_limit': 100,
                'features': ['100 Canaries', 'Complete Feature Set', 'Email Alerts', 'Web Dashboard', 'API Access', 'Smart Alerts (AI)', 'Advanced Analytics', 'Custom Webhooks', 'White-glove Support']
            }
        }
        
        current_plan_features = plan_features.get(subscription.plan_name if subscription else 'free', plan_features['free'])
        
        # Get billing frequency from Stripe if available
        billing_frequency = 'monthly'  # default
        current_price = None
        if subscription and subscription.stripe_subscription_id and subscription.plan_name != 'free':
            import stripe
            stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
            if stripe.api_key:
                try:
                    stripe_subscription = stripe.Subscription.retrieve(subscription.stripe_subscription_id)
                    if stripe_subscription.items and len(stripe_subscription.items.data) > 0:
                        current_price = stripe_subscription.items.data[0].price
                        if current_price and current_price.recurring:
                            billing_frequency = current_price.recurring.interval
                            print(f"🔄 Current billing frequency: {billing_frequency}")
                except Exception as e:
                    print(f"⚠️ Could not retrieve billing frequency from Stripe: {e}")
        
        # Convert ISO string dates back to datetime objects for template formatting
        if subscription:
            from datetime import datetime
            if subscription.current_period_start and isinstance(subscription.current_period_start, str):
                try:
                    subscription.current_period_start = datetime.fromisoformat(subscription.current_period_start.replace('Z', '+00:00'))
                except:
                    pass
            if subscription.current_period_end and isinstance(subscription.current_period_end, str):
                try:
                    subscription.current_period_end = datetime.fromisoformat(subscription.current_period_end.replace('Z', '+00:00'))
                except:
                    pass
        
        print(f"🎯 Template variables: billing_frequency={billing_frequency}, plan_name={subscription.plan_name if subscription else 'None'}")
        return render_template('account.html', 
                             subscription=subscription, 
                             usage=usage,
                             billing_history=billing_history,
                             current_plan_features=current_plan_features,
                             billing_frequency=billing_frequency,
                             current_price=current_price)
                             
    except Exception as e:
        print(f"❌ Error in account management: {e}")
        import traceback
        print(f"❌ Account management traceback: {traceback.format_exc()}")
        flash('Error loading account information. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/upgrade_plan/<plan>')
@login_required
def upgrade_plan(plan):
    """Create Stripe checkout session for plan upgrade"""
    # Check if Stripe is configured
    stripe_secret_key = os.environ.get('STRIPE_SECRET_KEY')
    if not stripe_secret_key:
        print("❌ STRIPE_SECRET_KEY not configured")
        flash('Payment system is not configured. Please contact support to upgrade your plan.', 'error')
        return redirect(url_for('contact'))
    
    try:
        print(f"🚀 Starting upgrade process for plan: {plan}, user: {current_user.username}")
        
        # Define plan configurations with Stripe price IDs
        plan_config = {
            'startup': {
                'monthly_price_id': os.environ.get('STRIPE_STARTUP_MONTHLY_PRICE_ID', 'price_startup_monthly'),
                'annual_price_id': os.environ.get('STRIPE_STARTUP_ANNUAL_PRICE_ID', 'price_startup_annual'),
                'name': 'Startup',
                'monthly_price': 7,
                'annual_price': 70
            },
            'growth': {
                'monthly_price_id': os.environ.get('STRIPE_GROWTH_MONTHLY_PRICE_ID', 'price_growth_monthly'),
                'annual_price_id': os.environ.get('STRIPE_GROWTH_ANNUAL_PRICE_ID', 'price_growth_annual'),
                'name': 'Growth',
                'monthly_price': 25,
                'annual_price': 250
            },
            'enterprise': {
                'monthly_price_id': os.environ.get('STRIPE_ENTERPRISE_MONTHLY_PRICE_ID', 'price_enterprise_monthly'),
                'annual_price_id': os.environ.get('STRIPE_ENTERPRISE_ANNUAL_PRICE_ID', 'price_enterprise_annual'),
                'name': 'Enterprise',
                'monthly_price': 75,
                'annual_price': 750
            }
        }
        
        if plan not in plan_config:
            print(f"❌ Invalid plan selected: {plan}")
            flash('Invalid plan selected', 'error')
            return redirect(url_for('subscription_plans'))
        
        # Get billing period from query params (default to monthly)
        billing_period = request.args.get('billing', 'monthly')
        print(f"💰 Billing period: {billing_period}")
        
        # Select the appropriate price ID
        config = plan_config[plan]
        if billing_period == 'annual':
            price_id = config['annual_price_id']
            display_price = f"${config['annual_price']}/year"
        else:
            price_id = config['monthly_price_id']
            display_price = f"${config['monthly_price']}/month"
        
        print(f"💳 Using price ID: {price_id} for {display_price}")
        
        # Create Stripe checkout session
        import stripe
        stripe.api_key = stripe_secret_key
        
        try:
            print(f"👤 Getting or creating Stripe customer for user: {current_user.email}")
            # Get or create Stripe customer
            customer_id = get_or_create_stripe_customer(current_user)
            print(f"✅ Stripe customer ID: {customer_id}")
            
            print(f"🛒 Creating checkout session...")
            checkout_session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=request.host_url + 'checkout/success?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=request.host_url + 'pricing',
                metadata={
                    'user_id': current_user.user_id,
                    'plan': plan,
                    'billing_period': billing_period
                }
            )
            
            print(f"✅ Checkout session created: {checkout_session.id}")
            print(f"🔗 Redirecting to: {checkout_session.url}")
            return redirect(checkout_session.url, code=303)
            
        except stripe.error.InvalidRequestError as e:
            print(f"❌ Stripe Invalid Request Error: {e}")
            if 'price' in str(e).lower():
                flash('The selected plan is not available. Please contact support.', 'error')
            else:
                flash(f'Invalid request: {e}', 'error')
            return redirect(url_for('subscription_plans'))
        except stripe.error.AuthenticationError as e:
            print(f"❌ Stripe Authentication Error: {e}")
            flash('Payment system configuration error. Please contact support.', 'error')
            return redirect(url_for('contact'))
        except stripe.error.StripeError as e:
            print(f"❌ Stripe error creating checkout session: {e}")
            flash(f'Payment system error. Please try again or contact support.', 'error')
            return redirect(url_for('subscription_plans'))
            
    except Exception as e:
        print(f"❌ Error in upgrade_plan: {e}")
        import traceback
        print(f"❌ Traceback: {traceback.format_exc()}")
        flash('An unexpected error occurred. Please try again.', 'error')
        return redirect(url_for('subscription_plans'))

@app.route('/cancel_subscription', methods=['POST'])
@login_required  
def cancel_subscription():
    """Cancel user's current subscription"""
    try:
        # Get user's current subscription
        subscription = Subscription.get_by_user_id(current_user.user_id)
        
        if not subscription:
            flash('No active subscription found.', 'error')
            return redirect(url_for('account_management'))
        
        if subscription.plan_name == 'free':
            flash('You are already on the free plan.', 'info')
            return redirect(url_for('account_management'))
            
        # Check if Stripe is configured
        stripe_secret_key = os.environ.get('STRIPE_SECRET_KEY')
        if not stripe_secret_key:
            flash('Payment system is not configured. Please contact support to cancel your subscription.', 'error')
            return redirect(url_for('contact'))
        
        import stripe
        stripe.api_key = stripe_secret_key
        
        try:
            # Cancel the subscription in Stripe
            if subscription.stripe_subscription_id:
                stripe_subscription = stripe.Subscription.retrieve(subscription.stripe_subscription_id)
                
                # Cancel at period end (don't immediately cancel)
                stripe.Subscription.modify(
                    subscription.stripe_subscription_id,
                    cancel_at_period_end=True
                )
                
                print(f"✅ Subscription {subscription.stripe_subscription_id} marked for cancellation at period end")
                
                # Update subscription status in database
                subscription.status = 'canceled'
                if subscription.save():
                    flash('Your subscription has been cancelled. You\'ll continue to have access until the end of your current billing period.', 'success')
                else:
                    flash('Subscription cancelled in Stripe but failed to update local database. Please contact support.', 'warning')
            else:
                # No Stripe subscription ID, just cancel locally
                subscription.status = 'canceled'
                if subscription.save():
                    flash('Your subscription has been cancelled.', 'success')
                else:
                    flash('Failed to cancel subscription. Please try again.', 'error')
                    
        except stripe.error.InvalidRequestError as e:
            print(f"❌ Stripe Invalid Request Error during cancellation: {e}")
            if 'No such subscription' in str(e):
                # Subscription doesn't exist in Stripe, cancel locally
                subscription.status = 'canceled'
                if subscription.save():
                    flash('Subscription cancelled successfully.', 'success')
                else:
                    flash('Failed to cancel subscription. Please contact support.', 'error')
            else:
                flash(f'Error cancelling subscription: {e}', 'error')
                return redirect(url_for('contact'))
        except stripe.error.StripeError as e:
            print(f"❌ Stripe error during cancellation: {e}")
            flash('Error cancelling subscription. Please contact support.', 'error')
            return redirect(url_for('contact'))
            
    except Exception as e:
        print(f"❌ Error in cancel_subscription: {e}")
        flash('An unexpected error occurred. Please try again or contact support.', 'error')
        return redirect(url_for('contact'))
    
    return redirect(url_for('account_management'))

@app.route('/change_plan/<new_plan>')
@login_required
def change_plan(new_plan):
    """Change user's subscription plan (upgrade/downgrade)"""
    try:
        # Get current subscription
        subscription = Subscription.get_by_user_id(current_user.user_id)
        
        if not subscription:
            flash('No current subscription found. Please subscribe to a plan first.', 'error')
            return redirect(url_for('subscription_plans'))
        
        # Define plan configurations
        plan_config = {
            'free': {
                'name': 'Solo',
                'canary_limit': 1,
                'is_free': True
            },
            'startup': {
                'monthly_price_id': os.environ.get('STRIPE_STARTUP_MONTHLY_PRICE_ID'),
                'annual_price_id': os.environ.get('STRIPE_STARTUP_ANNUAL_PRICE_ID'),
                'name': 'Startup',
                'canary_limit': 5,
                'monthly_price': 7,
                'annual_price': 70,
                'is_free': False
            },
            'growth': {
                'monthly_price_id': os.environ.get('STRIPE_GROWTH_MONTHLY_PRICE_ID'),
                'annual_price_id': os.environ.get('STRIPE_GROWTH_ANNUAL_PRICE_ID'),
                'name': 'Growth',
                'canary_limit': 25,
                'monthly_price': 25,
                'annual_price': 250,
                'is_free': False
            },
            'enterprise': {
                'monthly_price_id': os.environ.get('STRIPE_ENTERPRISE_MONTHLY_PRICE_ID'),
                'annual_price_id': os.environ.get('STRIPE_ENTERPRISE_ANNUAL_PRICE_ID'),
                'name': 'Enterprise',
                'canary_limit': 100,
                'monthly_price': 75,
                'annual_price': 750,
                'is_free': False
            }
        }
        
        if new_plan not in plan_config:
            flash('Invalid plan selected.', 'error')
            return redirect(url_for('account_management'))
        
        current_plan = subscription.plan_name
        if current_plan == new_plan:
            flash('You are already on this plan.', 'info')
            return redirect(url_for('account_management'))
        
        new_plan_config = plan_config[new_plan]
        
        # Handle downgrade to free plan
        if new_plan == 'free':
            return redirect(url_for('cancel_subscription'))
        
        # Handle upgrade from free plan (redirect to normal subscription flow)
        if current_plan == 'free':
            return redirect(url_for('upgrade_plan', plan=new_plan))
        
        # Determine if this is an upgrade or downgrade
        plan_hierarchy = {'free': 0, 'startup': 1, 'growth': 2, 'enterprise': 3}
        current_level = plan_hierarchy.get(current_plan, 0)
        new_level = plan_hierarchy.get(new_plan, 0)
        
        # For upgrades (higher cost plans), redirect to checkout for payment confirmation
        if new_level > current_level:
            print(f"🚀 Upgrade detected: {current_plan} -> {new_plan}, redirecting to checkout for payment confirmation")
            return redirect(url_for('upgrade_plan', plan=new_plan))
        
        # Handle plan changes between paid plans (downgrades and same-level changes)
        stripe_secret_key = os.environ.get('STRIPE_SECRET_KEY')
        if not stripe_secret_key:
            flash('Payment system not configured. Please contact support.', 'error')
            return redirect(url_for('contact'))
        
        if not subscription.stripe_subscription_id:
            flash('No active Stripe subscription found. Please contact support.', 'error')
            return redirect(url_for('contact'))
        
        # Get billing period from query params (default to current period or monthly)
        billing_period = request.args.get('billing', 'monthly')
        
        # Select the appropriate price ID
        if billing_period == 'annual':
            new_price_id = new_plan_config['annual_price_id']
            display_price = f"${new_plan_config['annual_price']}/year"
        else:
            new_price_id = new_plan_config['monthly_price_id']
            display_price = f"${new_plan_config['monthly_price']}/month"
        
        if not new_price_id:
            flash('Plan pricing not configured. Please contact support.', 'error')
            return redirect(url_for('contact'))
        
        print(f"🔄 Changing plan from {current_plan} to {new_plan} ({display_price}) - downgrade or same level")
        
        import stripe
        stripe.api_key = stripe_secret_key
        
        try:
            # Get current subscription from Stripe
            stripe_subscription = stripe.Subscription.retrieve(subscription.stripe_subscription_id)
            
            # Modify the subscription to change the plan
            updated_subscription = stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                items=[{
                    'id': stripe_subscription['items']['data'][0].id,
                    'price': new_price_id,
                }],
                proration_behavior='create_prorations'  # Create prorations for immediate change
            )
            
            # Update local database
            subscription.plan_name = new_plan
            subscription.canary_limit = new_plan_config['canary_limit']
            subscription.status = 'active'
            
            if subscription.save():
                print(f"✅ Plan changed successfully to {new_plan}")
                
                if new_level < current_level:
                    flash(f'Successfully downgraded to {new_plan_config["name"]} plan. Changes are effective immediately.', 'success')
                else:
                    flash(f'Successfully changed to {new_plan_config["name"]} plan. Changes are effective immediately.', 'success')
            else:
                flash('Plan changed in Stripe but failed to update local database. Please contact support.', 'warning')
                
        except stripe.error.InvalidRequestError as e:
            print(f"❌ Stripe Invalid Request Error during plan change: {e}")
            flash('Invalid plan change request. Please contact support.', 'error')
            return redirect(url_for('contact'))
        except stripe.error.StripeError as e:
            print(f"❌ Stripe error during plan change: {e}")
            flash('Error changing plan. Please contact support.', 'error')
            return redirect(url_for('contact'))
            
    except Exception as e:
        print(f"❌ Error in change_plan: {e}")
        flash('An unexpected error occurred. Please try again or contact support.', 'error')
        return redirect(url_for('contact'))
    
    return redirect(url_for('account_management'))

@app.route('/change_billing_frequency/<frequency>')
@login_required
def change_billing_frequency(frequency):
    """Change user's billing frequency (monthly <-> annual) for the same plan"""
    try:
        # Validate frequency parameter
        if frequency not in ['monthly', 'annual']:
            flash('Invalid billing frequency specified.', 'error')
            return redirect(url_for('account_management'))
        
        # Get current subscription
        subscription = Subscription.get_by_user_id(current_user.user_id)
        
        if not subscription:
            flash('No current subscription found.', 'error')
            return redirect(url_for('account_management'))
        
        if subscription.plan_name == 'free':
            flash('Billing frequency changes are not available for the Solo plan.', 'info')
            return redirect(url_for('account_management'))
        
        # Define plan configurations
        plan_config = {
            'startup': {
                'monthly_price_id': os.environ.get('STRIPE_STARTUP_MONTHLY_PRICE_ID'),
                'annual_price_id': os.environ.get('STRIPE_STARTUP_ANNUAL_PRICE_ID'),
                'name': 'Startup',
                'monthly_price': 7,
                'annual_price': 70
            },
            'growth': {
                'monthly_price_id': os.environ.get('STRIPE_GROWTH_MONTHLY_PRICE_ID'),
                'annual_price_id': os.environ.get('STRIPE_GROWTH_ANNUAL_PRICE_ID'),
                'name': 'Growth',
                'monthly_price': 25,
                'annual_price': 250
            },
            'enterprise': {
                'monthly_price_id': os.environ.get('STRIPE_ENTERPRISE_MONTHLY_PRICE_ID'),
                'annual_price_id': os.environ.get('STRIPE_ENTERPRISE_ANNUAL_PRICE_ID'),
                'name': 'Enterprise',
                'monthly_price': 75,
                'annual_price': 750
            }
        }
        
        current_plan_config = plan_config.get(subscription.plan_name)
        if not current_plan_config:
            flash('Invalid subscription plan. Please contact support.', 'error')
            return redirect(url_for('contact'))
        
        # Get the new price ID based on frequency
        if frequency == 'annual':
            new_price_id = current_plan_config['annual_price_id']
            display_price = f"${current_plan_config['annual_price']}/year"
            frequency_display = "Annual"
        else:  # monthly
            new_price_id = current_plan_config['monthly_price_id']
            display_price = f"${current_plan_config['monthly_price']}/month"
            frequency_display = "Monthly"
        
        if not new_price_id:
            flash('Billing frequency not configured for this plan. Please contact support.', 'error')
            return redirect(url_for('contact'))
        
        # Check Stripe configuration
        stripe_secret_key = os.environ.get('STRIPE_SECRET_KEY')
        if not stripe_secret_key:
            flash('Payment system not configured. Please contact support.', 'error')
            return redirect(url_for('contact'))
        
        if not subscription.stripe_subscription_id:
            flash('No active Stripe subscription found. Please contact support.', 'error')
            return redirect(url_for('contact'))
        
        print(f"🔄 Changing billing frequency to {frequency} ({display_price}) for user: {current_user.email}")
        
        import stripe
        stripe.api_key = stripe_secret_key
        
        try:
            # Get current subscription from Stripe
            stripe_subscription = stripe.Subscription.retrieve(subscription.stripe_subscription_id)
            
            # Check current billing interval
            current_interval = 'monthly'  # default
            if stripe_subscription.items and len(stripe_subscription.items.data) > 0:
                current_price = stripe_subscription.items.data[0].price
                if current_price and current_price.recurring:
                    current_interval = current_price.recurring.interval
                    if current_interval == 'year':
                        current_interval = 'annual'
            
            # Don't change if it's already the requested frequency
            if (current_interval == 'month' and frequency == 'monthly') or \
               (current_interval == 'year' and frequency == 'annual'):
                flash(f'You are already on {frequency_display.lower()} billing.', 'info')
                return redirect(url_for('account_management'))
            
            # Modify the subscription to change billing frequency
            updated_subscription = stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                items=[{
                    'id': stripe_subscription['items']['data'][0].id,
                    'price': new_price_id,
                }],
                proration_behavior='create_prorations'  # Create prorations for billing change
            )
            
            print(f"✅ Billing frequency changed successfully to {frequency}")
            
            if frequency == 'annual':
                flash(f'Successfully switched to annual billing ({display_price}). You\'ll save money with yearly payments!', 'success')
            else:
                flash(f'Successfully switched to monthly billing ({display_price}). Changes are effective immediately.', 'success')
                
        except stripe.error.InvalidRequestError as e:
            print(f"❌ Stripe Invalid Request Error during billing change: {e}")
            flash('Invalid billing frequency change request. Please contact support.', 'error')
            return redirect(url_for('contact'))
        except stripe.error.StripeError as e:
            print(f"❌ Stripe error during billing frequency change: {e}")
            flash('Error changing billing frequency. Please contact support.', 'error')
            return redirect(url_for('contact'))
            
    except Exception as e:
        print(f"❌ Error in change_billing_frequency: {e}")
        flash('An unexpected error occurred. Please try again or contact support.', 'error')
        return redirect(url_for('contact'))
    
    return redirect(url_for('account_management'))

def get_or_create_stripe_customer(user):
    """Get existing Stripe customer or create new one"""
    import stripe
    
    # Check if user already has a customer ID in subscription
    try:
        from models import Subscription
        subscription = Subscription.get_by_user_id(user.user_id)
        if subscription and subscription.stripe_customer_id:
            print(f"✅ Found existing Stripe customer: {subscription.stripe_customer_id}")
            return subscription.stripe_customer_id
    except Exception as e:
        print(f"⚠️ Could not check existing subscription: {e}")
        pass
    
    # Create new Stripe customer
    try:
        print(f"➕ Creating new Stripe customer for {user.email}")
        customer = stripe.Customer.create(
            email=user.email,
            name=user.username,
            metadata={
                'user_id': user.user_id
            }
        )
        print(f"✅ Created Stripe customer: {customer.id}")
        return customer.id
    except stripe.error.StripeError as e:
        print(f"❌ Error creating Stripe customer: {e}")
        raise

@app.route('/checkout/success')
@login_required
def checkout_success():
    """Handle successful checkout"""
    session_id = request.args.get('session_id')
    
    if not session_id:
        flash('Invalid session', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        import stripe
        stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
        
        # Retrieve the checkout session
        session = stripe.checkout.Session.retrieve(session_id, expand=['subscription'])
        
        print(f"🔍 Checkout session retrieved: {session.id}")
        print(f"💳 Payment status: {session.payment_status}")
        
        try:
            print(f"🔍 About to access session.subscription...")
            subscription_obj = session.subscription
            print(f"🎯 Subscription ID: {subscription_obj}")
            print(f"🔍 Session mode: {getattr(session, 'mode', 'unknown')}")
        except Exception as e:
            print(f"❌ Error accessing session data: {e}")
            import traceback
            traceback.print_exc()
            subscription_obj = None
        
        if session.payment_status == 'paid' and session.subscription:
            try:
                print(f"🔍 Processing subscription...")
                # Handle subscription - could be ID string or full object
                if hasattr(session.subscription, 'id'):
                    # Full subscription object
                    stripe_subscription = session.subscription
                    subscription_id = stripe_subscription.id
                    print(f"🎯 Using expanded subscription object: {subscription_id}")
                else:
                    # Just the subscription ID
                    subscription_id = session.subscription
                    print(f"🔍 Retrieving subscription: {subscription_id}")
                    stripe_subscription = stripe.Subscription.retrieve(subscription_id)
                
                print(f"✅ Subscription ready: {stripe_subscription.id}")
                
                # Get plan details from metadata or subscription
                plan_name = 'startup'  # default
                billing_period = 'monthly'  # default
                
                # Try to get plan info from session metadata
                if session.metadata:
                    plan_name = session.metadata.get('plan', 'startup')
                    billing_period = session.metadata.get('billing_period', 'monthly')
                
                # Get price ID from subscription object directly
                print(f"🔍 Getting plan from subscription...")
                print(f"🔍 Subscription object type: {type(stripe_subscription)}")
                print(f"🔍 Subscription has items attr: {hasattr(stripe_subscription, 'items')}")
                print(f"🔍 Subscription has plan attr: {hasattr(stripe_subscription, 'plan')}")
                
                # Method 1: Try to get from direct items property (expanded object)
                try:
                    print(f"🔍 Trying direct subscription.items from expanded object...")
                    print(f"🔍 Subscription.items type: {type(getattr(stripe_subscription, 'items', None))}")
                    
                    # Check if items attribute exists
                    if hasattr(stripe_subscription, 'items'):
                        items_obj = stripe_subscription.items
                        print(f"🔍 Items object: {items_obj}")
                        print(f"🔍 Items has data attr: {hasattr(items_obj, 'data')}")
                        
                        if hasattr(items_obj, 'data'):
                            items_data = items_obj.data
                            print(f"🔍 Items data: {items_data}")
                            print(f"🔍 Items data type: {type(items_data)}")
                            print(f"🔍 Items data length: {len(items_data) if items_data else 0}")
                            
                            if items_data and len(items_data) > 0:
                                print(f"✅ Found items data with {len(items_data)} items")
                                first_item = items_data[0]
                                print(f"🔍 First item: {first_item}")
                                price_id = first_item.price.id
                                print(f"💰 Extracted price_id: {price_id}")
                                plan_name = get_plan_name_from_price_id(price_id)
                                print(f"📋 Plan from expanded subscription.items: {plan_name}")
                            else:
                                print(f"❌ Items data is empty or None")
                                raise Exception("Empty items data in expanded subscription")
                        else:
                            print(f"❌ Items object has no data attribute")
                            raise Exception("No data attribute in items object")
                    else:
                        print(f"❌ No items attribute in subscription")
                        raise Exception("No items attribute in subscription")
                except Exception as e:
                    print(f"⚠️ Direct subscription.items failed: {e}")
                    import traceback
                    traceback.print_exc()
                    
                    # Method 2: Try using subscription ID to retrieve items
                    try:
                        print(f"🔍 Trying to list subscription items by ID...")
                        items = stripe.SubscriptionItem.list(subscription=stripe_subscription.id)
                        if items.data:
                            price_id = items.data[0].price.id
                            print(f"💰 Extracted price_id from API call: {price_id}")
                            plan_name = get_plan_name_from_price_id(price_id)
                            print(f"📋 Plan from SubscriptionItem.list(): {plan_name}")
                    except Exception as e2:
                        print(f"⚠️ SubscriptionItem.list() failed: {e2}")
                        import traceback
                        traceback.print_exc()
                        
                        # Method 3: Use the plan object directly (legacy format)
                        try:
                            print(f"🔍 Trying subscription.plan...")
                            if hasattr(stripe_subscription, 'plan') and stripe_subscription.plan:
                                price_id = stripe_subscription.plan.id
                                print(f"💰 Extracted price_id from plan: {price_id}")
                                plan_name = get_plan_name_from_price_id(price_id)
                                print(f"📋 Plan from subscription.plan: {plan_name}")
                        except Exception as e3:
                            print(f"⚠️ subscription.plan failed: {e3}")
                            print(f"⚠️ Using default plan name: {plan_name}")
                            import traceback
                            traceback.print_exc()
                    
            except Exception as e:
                print(f"❌ Error processing subscription: {e}")
                import traceback
                traceback.print_exc()
                flash('Payment completed but there was an error updating your account. Please contact support.', 'error')
                return redirect(url_for('settings'))
            
            print(f"📋 Creating subscription: plan={plan_name}, user={current_user.email}")
            
            # Create or update subscription in database
            existing_subscription = Subscription.get_by_user_id(current_user.user_id)
            
            if existing_subscription:
                # Update existing subscription
                print(f"🔄 Updating existing subscription for {current_user.email}")
                existing_subscription.plan_name = plan_name
                existing_subscription.stripe_customer_id = stripe_subscription.customer
                existing_subscription.stripe_subscription_id = stripe_subscription.id
                existing_subscription.status = 'active'
                
                # Safely convert timestamps
                try:
                    print(f"🕐 Converting timestamps - start: {stripe_subscription.current_period_start}, end: {stripe_subscription.current_period_end}")
                    existing_subscription.current_period_start = datetime.fromtimestamp(stripe_subscription.current_period_start, tz=timezone.utc)
                    existing_subscription.current_period_end = datetime.fromtimestamp(stripe_subscription.current_period_end, tz=timezone.utc)
                    print(f"✅ Timestamp conversion successful")
                except Exception as e:
                    print(f"❌ Error converting timestamps: {e}")
                    # Fallback to current time - convert to ISO string for DynamoDB
                    existing_subscription.current_period_start = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
                    existing_subscription.current_period_end = (datetime.utcnow() + timedelta(days=30)).replace(tzinfo=timezone.utc).isoformat()
                
                # Set canary limit based on plan
                plan_limits = {'free': 1, 'startup': 5, 'growth': 25, 'enterprise': 100}
                existing_subscription.canary_limit = plan_limits.get(plan_name, 1)
                
                if existing_subscription.save():
                    print(f"✅ Updated subscription for user {current_user.email}: {plan_name}")
                else:
                    print(f"❌ Failed to update subscription for user {current_user.email}")
            else:
                # Create new subscription
                print(f"🆕 Creating new subscription for {current_user.email}")
                plan_limits = {'free': 1, 'startup': 5, 'growth': 25, 'enterprise': 100}
                
                # Safely convert timestamps
                try:
                    print(f"🕐 Converting timestamps for new subscription - start: {stripe_subscription.current_period_start}, end: {stripe_subscription.current_period_end}")
                    period_start = datetime.fromtimestamp(stripe_subscription.current_period_start, tz=timezone.utc)
                    period_end = datetime.fromtimestamp(stripe_subscription.current_period_end, tz=timezone.utc)
                    print(f"✅ Timestamp conversion successful for new subscription")
                except Exception as e:
                    print(f"❌ Error converting timestamps for new subscription: {e}")
                    # Fallback to current time - convert to ISO string for DynamoDB
                    period_start = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
                    period_end = (datetime.utcnow() + timedelta(days=30)).replace(tzinfo=timezone.utc).isoformat()
                
                new_subscription = Subscription(
                    user_id=current_user.user_id,
                    plan_name=plan_name,
                    stripe_customer_id=stripe_subscription.customer,
                    stripe_subscription_id=stripe_subscription.id,
                    status='active',
                    canary_limit=plan_limits.get(plan_name, 1),
                    current_period_start=period_start,
                    current_period_end=period_end
                )
                
                if new_subscription.save():
                    print(f"✅ Created subscription for user {current_user.email}: {plan_name}")
                else:
                    print(f"❌ Failed to create subscription for user {current_user.email}")
            
            flash(f'🎉 Subscription upgraded successfully! Welcome to your {plan_name.title()} plan!', 'success')
        else:
            print(f"❌ Payment processing failed - Payment status: {session.payment_status}, Subscription: {session.subscription}")
            flash('Payment is being processed. You will receive a confirmation email shortly.', 'info')
            
        return redirect(url_for('account_management'))
        
    except stripe.error.StripeError as e:
        print(f"❌ Stripe error retrieving checkout session: {e}")
        flash('Payment completed but there was an error updating your account. Please contact support.', 'warning')
        return redirect(url_for('account_management'))
    except Exception as e:
        print(f"❌ Error in checkout success: {e}")
        import traceback
        print(f"❌ Traceback: {traceback.format_exc()}")
        flash('An error occurred. Please contact support if your payment was processed.', 'error')
        return redirect(url_for('settings'))

@app.route('/edit_canary/<canary_id>', methods=['GET', 'POST'])
@login_required
def edit_canary(canary_id):
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    form = CanaryForm()
    
    if form.validate_on_submit():
        # Check if alert email has changed and needs verification
        old_alert_email = canary.alert_email
        new_alert_email = form.alert_email.data if form.alert_email.data else None
        needs_email_verification = False
        
        # Check if email verification is needed
        if new_alert_email and new_alert_email != old_alert_email:
            # Email verification is needed if the new email is different from user's email
            if new_alert_email != current_user.email:
                needs_email_verification = True
        
        canary.name = form.name.data
        canary.interval_minutes = form.interval_minutes.data
        canary.grace_minutes = form.grace_minutes.data
        canary.alert_type = form.alert_type.data
        canary.alert_email = new_alert_email
        canary.slack_webhook = form.slack_webhook.data if form.slack_webhook.data else None
        canary.sla_threshold = Decimal(str(form.sla_threshold.data))
        
        # Process tags - split by comma and clean up whitespace
        tags = []
        if form.tags.data:
            tags = [tag.strip() for tag in form.tags.data.split(',') if tag.strip()]
        canary.tags = tags
        
        # If email verification is needed, set status to pending
        if needs_email_verification:
            canary.status = 'pending_verification'
        
        # Recalculate next expected check-in if interval changed
        if canary.last_checkin:
            if isinstance(canary.last_checkin, str):
                last_checkin_dt = datetime.fromisoformat(canary.last_checkin.replace('Z', '+00:00'))
            else:
                last_checkin_dt = canary.last_checkin
            canary.next_expected = (last_checkin_dt + timedelta(minutes=canary.interval_minutes)).isoformat()
        
        if canary.save():
            if needs_email_verification:
                # Create email verification record
                from models import EmailVerification
                verification = EmailVerification(
                    canary_id=canary.canary_id,
                    user_id=current_user.user_id,
                    email=new_alert_email
                )
                
                if verification.save():
                    # Send verification email
                    if send_verification_email(verification, canary):
                        flash(f'Canary "{canary.name}" updated! A verification email has been sent to {new_alert_email}. Please verify your email to reactivate the canary.', 'warning')
                    else:
                        flash(f'Canary updated but failed to send verification email. Please contact support.', 'warning')
                else:
                    flash(f'Canary updated but email verification setup failed. Please contact support.', 'error')
            else:
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

# test_failure_data endpoint removed for security - Phase 4

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
    sensitivity = request.form.get('sensitivity', '0.8')
    learning_period = request.form.get('learning_period', 7)
    
    try:
        from decimal import Decimal
        sensitivity_float = max(0.5, min(1.0, float(sensitivity)))
        sensitivity = Decimal(str(sensitivity_float))
        learning_period = max(1, min(365, int(learning_period)))
    except (ValueError, TypeError):
        flash('Invalid configuration values')
        return redirect(url_for('smart_alert_config', canary_id=canary_id))
    
    # Create or update smart alert
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    if smart_alert:
        smart_alert.is_enabled = True
        smart_alert.sensitivity = sensitivity
        smart_alert.learning_period_days = learning_period
    else:
        smart_alert = SmartAlert(
            canary_id=canary_id,
            user_id=current_user.user_id,
            sensitivity=sensitivity,
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
    print(f"🔄 Re-learn patterns requested by user {current_user.username} for canary {canary_id}")
    
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        print(f"❌ Access denied for re-learn patterns - user {current_user.username}, canary {canary_id}")
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    if smart_alert and smart_alert.is_enabled:
        print(f"🧠 Starting pattern re-learning for canary '{canary.name}' ({canary_id})")
        try:
            if smart_alert.learn_patterns():
                print(f"✅ Pattern re-learning succeeded for canary '{canary.name}'")
                flash(f'Patterns re-learned successfully for "{canary.name}"!', 'success')
            else:
                print(f"⚠️ Pattern re-learning failed - insufficient data for canary '{canary.name}'")
                flash('Insufficient data to learn patterns. More check-ins are needed.', 'warning')
        except Exception as e:
            print(f"❌ Exception during pattern re-learning for canary '{canary.name}': {e}")
            flash('Error occurred while re-learning patterns. Please try again.', 'warning')
    else:
        print(f"❌ Smart alerting not enabled for canary '{canary.name}' ({canary_id})")
        flash('Smart alerting is not enabled for this canary', 'warning')
    
    return redirect(url_for('smart_alert_config', canary_id=canary_id))

@app.route('/delete_pattern_data/<canary_id>', methods=['POST'])
@login_required
def delete_pattern_data(canary_id):
    """Delete pattern data for smart alerting while keeping smart alerts enabled"""
    print(f"🗑️ Delete pattern data requested by user {current_user.username} for canary {canary_id}")
    
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        print(f"❌ Access denied for delete pattern data - user {current_user.username}, canary {canary_id}")
        flash('Access denied', 'warning')
        return redirect(url_for('dashboard'))
    
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    if smart_alert and smart_alert.is_enabled:
        try:
            # Clear pattern data but keep smart alert enabled
            old_pattern_count = smart_alert.pattern_data.get('total_checkins', 0) if smart_alert.pattern_data else 0
            smart_alert.pattern_data = None
            smart_alert.last_analysis = None
            smart_alert.last_alert_sent = None
            
            if smart_alert.save():
                print(f"✅ Pattern data deleted for canary '{canary.name}' ({old_pattern_count} check-ins cleared)")
                flash(f'Pattern data deleted for "{canary.name}". Smart alerts remain enabled and will learn new patterns from future check-ins.', 'success')
            else:
                print(f"❌ Failed to save after deleting pattern data for canary '{canary.name}'")
                flash('Failed to delete pattern data. Please try again.', 'warning')
        except Exception as e:
            print(f"❌ Exception during pattern data deletion for canary '{canary.name}': {e}")
            flash('Error occurred while deleting pattern data. Please try again.', 'warning')
    else:
        print(f"❌ Smart alerting not enabled for canary '{canary.name}' ({canary_id})")
        flash('Smart alerting is not enabled for this canary', 'warning')
    
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
    
    # Check if pattern data exists - if not, return empty state with message
    if not smart_alert.pattern_data or not smart_alert.last_analysis:
        return jsonify({
            'timing_patterns': ['Pattern data has been cleared. Smart alerts will learn new patterns from future check-ins.'],
            'anomaly_indicators': [],
            'next_expected': None,
            'confidence': 0
        })
    
    # Get pattern insights
    insights = {
        'timing_patterns': [],
        'anomaly_indicators': [],
        'next_expected': None,
        'confidence': None
    }
    
    if smart_alert.pattern_data:
        pattern_data = smart_alert.pattern_data
        total_checkins = pattern_data.get('total_checkins', 0)
        
        # Calculate confidence based on available data
        confidence_calculated = False
        
        # Generate timing pattern insights
        if pattern_data.get('avg_interval'):
            avg_interval = float(pattern_data['avg_interval'])
            expected_interval = pattern_data.get('expected_interval', avg_interval)
            std_dev = float(pattern_data.get('interval_std', 0))
            
            insights['timing_patterns'].append(f"You typically check in every {expected_interval:.1f} minutes")
            
            if std_dev > 0:
                insights['timing_patterns'].append(f"Your timing varies by ±{std_dev:.1f} minutes normally")
            
            if total_checkins > 0:
                insights['timing_patterns'].append(f"Analysis based on {total_checkins} check-ins")
            
            # Calculate confidence based on data quality
            if total_checkins >= 3:
                # Base confidence on number of check-ins and consistency
                base_confidence = min(90, 30 + (total_checkins * 8))  # 30% base + up to 60% for data
                
                # Adjust for timing consistency
                if avg_interval > 0 and std_dev >= 0:
                    variability_factor = std_dev / avg_interval
                    consistency_bonus = max(0, 20 - (variability_factor * 20))  # Up to 20% bonus for consistency
                    insights['confidence'] = min(95, int(base_confidence + consistency_bonus))
                else:
                    insights['confidence'] = int(base_confidence)
                confidence_calculated = True
        
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
            except:
                pass
        
        # If we haven't calculated confidence yet, provide a basic estimate
        if not confidence_calculated:
            if total_checkins >= 3:
                insights['confidence'] = min(70, 20 + (total_checkins * 5))
            elif total_checkins > 0:
                insights['confidence'] = 15
            # else confidence remains None for insufficient data
    
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
    
    # Check if pattern data exists - if not, return minimal data
    if not smart_alert.pattern_data or not smart_alert.last_analysis:
        return jsonify({
            'checkins': [],
            'summary': 'Pattern data has been cleared. Check-ins will be analyzed once new patterns are learned.'
        })
    
    # Get recent check-ins
    recent_logs_data = CanaryLog.get_by_canary_id(canary_id, limit=10)
    recent_logs = recent_logs_data.get('logs', [])
    
    timeline_data = {
        'checkins': [],
        'summary': None
    }
    
    if recent_logs:
        pattern_data = smart_alert.pattern_data
        expected_interval = float(pattern_data.get('expected_interval', 60))
        interval_std = float(pattern_data.get('interval_std', 30))
        
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
    
    # Add AI enhancement if user has API key
    if current_user.anthropic_api_key:
        timeline_data = enhance_smart_alert_timeline(timeline_data, canary, smart_alert, current_user.anthropic_api_key)
    
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
        expected_interval = float(pattern_data.get('expected_interval', 60))
        sensitivity = float(smart_alert.sensitivity)
        interval_std = float(pattern_data.get('interval_std', 30))
        
        # Calculate actual alert thresholds using the same logic as is_anomaly method
        avg_interval = float(pattern_data.get('avg_interval', expected_interval))
        sensitivity_factor = sensitivity
        
        if interval_std > 0:
            # Use standard deviations but with minimum buffer (same as is_anomaly)
            threshold_multiplier = max(1.5, 3.0 - sensitivity_factor)  # 1.5 to 2.0 range
            alert_threshold_minutes = avg_interval + (interval_std * threshold_multiplier)
        else:
            # Percentage-based threshold (same as is_anomaly)
            threshold_percentage = max(0.3, 1.0 - (sensitivity_factor * 0.4))  # 0.3 to 0.6 range
            alert_threshold_minutes = avg_interval * (1 + threshold_percentage)
        
        warning_threshold_minutes = alert_threshold_minutes * 0.8  # 80% of alert threshold
        
        logic_data['current_thresholds'] = [
            {
                'condition': 'Critical Alert Threshold',
                'value': f'{alert_threshold_minutes:.1f} minutes since last check-in'
            },
            {
                'condition': 'Warning Threshold',  
                'value': f'{warning_threshold_minutes:.1f} minutes since last check-in'
            },
            {
                'condition': 'Learned Average Interval',
                'value': f'{avg_interval:.1f} minutes'
            },
            {
                'condition': 'Configured Expected Interval',
                'value': f'{expected_interval:.1f} minutes'
            },
            {
                'condition': 'Normal Variance (1 std dev)',
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
        
        threshold_method = "statistical" if interval_std > 0 else "percentage-based"
        if interval_std > 0:
            threshold_multiplier = max(1.5, 3.0 - sensitivity_factor)
            explanation = f"""
            Smart alerts use statistical analysis of your {pattern_data.get('total_checkins', 0)} check-ins over the past 7 days. 
            Your average check-in interval is {avg_interval:.1f} minutes (vs. configured {expected_interval:.1f} minutes).
            With {sensitivity * 100:.0f}% sensitivity, alerts trigger when check-ins exceed {alert_threshold_minutes:.1f} minutes 
            since the last check-in (average + {threshold_multiplier:.1f} standard deviations).
            Normal variance: ±{interval_std:.1f} minutes.
            """
        else:
            threshold_percentage = max(0.3, 1.0 - (sensitivity_factor * 0.4))
            explanation = f"""
            Smart alerts use percentage-based thresholds since your check-in pattern has low variance.
            With {sensitivity * 100:.0f}% sensitivity, alerts trigger when check-ins exceed {alert_threshold_minutes:.1f} minutes
            since the last check-in ({avg_interval:.1f} minutes + {threshold_percentage * 100:.0f}% tolerance).
            """
        
        logic_data['explanation'] = explanation.strip()
    else:
        logic_data['explanation'] = "Alert thresholds will be calculated once sufficient check-in data is collected and patterns are learned."
    
    # Add AI enhancement if user has API key
    if current_user.anthropic_api_key:
        logic_data = enhance_smart_alert_logic(logic_data, canary, smart_alert, current_user.anthropic_api_key)
    
    return jsonify(logic_data)

@app.route('/ai_chat/<canary_id>', methods=['POST'])
@login_required
def ai_chat(canary_id):
    """AI-powered chat interface for monitoring insights"""
    canary = Canary.get_by_id(canary_id)
    if not canary or canary.user_id != current_user.user_id:
        return jsonify({'error': 'Canary not found'}), 404
    
    user = User.get_by_id(current_user.user_id)
    if not user or not user.anthropic_api_key:
        return jsonify({'error': 'AI features require an Anthropic API key. Add one in Settings.'}), 403
    
    message = request.json.get('message', '').strip()
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    
    # Get canary context
    smart_alert = SmartAlert.get_by_canary_id(canary_id)
    recent_logs_data = CanaryLog.get_by_canary_id(canary_id, limit=10)
    recent_logs = recent_logs_data.get('logs', [])
    
    # Build context for AI
    context_lines = [
        f"User question about canary '{canary.name}': {message}",
        f"",
        f"Canary Details:",
        f"- Status: {canary.status}",
        f"- Expected interval: {canary.interval_minutes} minutes",
        f"- Grace period: {canary.grace_minutes} minutes",
        f"- SLA threshold: {canary.sla_threshold}%",
        f"- Last check-in: {canary.last_checkin or 'Never'}",
        f"- Tags: {', '.join(canary.tags) if canary.tags else 'None'}",
        f""
    ]
    
    if smart_alert and smart_alert.pattern_data:
        context_lines.extend([
            f"Smart Alert Learning:",
            f"- Average interval: {smart_alert.pattern_data.get('avg_interval', 'N/A')} minutes",
            f"- Standard deviation: {smart_alert.pattern_data.get('interval_std', 'N/A')} minutes",
            f"- Check-ins analyzed: {smart_alert.pattern_data.get('total_checkins', 0)}",
            f"- Sensitivity: {float(smart_alert.sensitivity) * 100:.0f}%",
            f""
        ])
    
    if recent_logs:
        context_lines.append("Recent Check-ins:")
        for log in recent_logs[:5]:
            context_lines.append(f"- {log.timestamp}: {log.status}")
        context_lines.append("")
    
    context_lines.extend([
        "Instructions:",
        "1. Answer the user's specific question about their monitoring setup",
        "2. Reference the actual data provided above",
        "3. Be helpful and actionable",
        "4. Keep response conversational but informative (2-4 sentences)",
        "5. If suggesting changes, be specific about what to adjust"
    ])
    
    prompt = "\n".join(context_lines)
    
    response, error = call_claude_api(prompt, user.anthropic_api_key, max_tokens=400, feature_used='chat', canary_id=canary_id, user_id=user.user_id)
    
    if response:
        return jsonify({'response': response})
    else:
        error_message = error if error else 'AI analysis temporarily unavailable. Check your API key.'
        return jsonify({'error': error_message}), 500

@app.route('/validate_anthropic_key', methods=['POST'])
@login_required
def validate_anthropic_key():
    """AJAX endpoint to validate Anthropic API key"""
    api_key = request.json.get('api_key', '').strip()
    
    if not api_key:
        return jsonify({'valid': False, 'message': 'Please enter an API key'})
    
    is_valid, message = validate_anthropic_api_key(api_key)
    return jsonify({'valid': is_valid, 'message': message})

@app.route('/api_key_logs', methods=['GET'])
@login_required
def api_key_logs():
    """Get recent API key related logs for debugging"""
    try:
        from models import ApiUsageLog
        
        # Get recent API usage logs for this user
        logs = ApiUsageLog.get_by_user_id(current_user.user_id, limit=50)
        
        # Format logs for display
        formatted_logs = []
        for log in logs:
            timestamp = log.timestamp
            if log.success:
                status = "✅ SUCCESS"
                message = f"{log.feature_used} - {log.model} - {log.total_tokens or 0} tokens - ${log.estimated_cost or 0:.4f}"
            else:
                status = "❌ FAILED"
                message = f"{log.feature_used} - Error: {log.error_message or 'Unknown error'}"
            
            log_line = f"{timestamp} {status} {message}"
            formatted_logs.append(log_line)
        
        # Add some synthetic debug info if no logs exist
        if not formatted_logs:
            formatted_logs = [
                "No API usage logs found for this user yet.",
                "Logs will appear here when you use AI features like:",
                "- Smart Alert explanations",
                "- AI-powered canary analysis", 
                "- Predictive monitoring insights",
                "",
                "To test: Try validating your API key using the 'Test' button."
            ]
        
        return jsonify({
            'success': True,
            'logs': formatted_logs,
            'total_lines': len(formatted_logs)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching API usage logs: {str(e)}'
        })

@app.route('/api_key_usage/<api_key_id>', methods=['GET'])
@login_required  
def get_api_key_usage_logs(api_key_id):
    """Get usage logs for a specific API key"""
    try:
        from models import APIKey, APIKeyUsageLog
        
        # Verify the API key belongs to the current user
        api_key = APIKey.get_by_id(api_key_id)
        if not api_key or api_key.user_id != current_user.user_id:
            return jsonify({
                'success': False,
                'error': 'API key not found or access denied'
            }), 404
        
        # Get usage logs for this API key
        usage_logs = APIKeyUsageLog.get_by_api_key_id(api_key_id, limit=100)
        
        # Format logs for display
        formatted_logs = []
        for log in usage_logs:
            # Parse timestamp for display
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
                formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            except:
                formatted_time = log.timestamp
            
            # Get canary name if canary_id exists
            canary_name = 'N/A'
            if log.canary_id:
                canary = Canary.get_by_id(log.canary_id)
                canary_name = canary.name if canary else f'Canary {log.canary_id[:8]}'
            
            formatted_logs.append({
                'timestamp': formatted_time,
                'endpoint': log.endpoint,
                'ip_address': log.ip_address,
                'status': log.status.title(),
                'canary': canary_name
            })
        
        return jsonify({
            'success': True,
            'logs': formatted_logs,
            'total': len(formatted_logs),
            'api_key_name': api_key.name
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching API key usage logs: {str(e)}'
        })

@app.route('/api_usage_summary', methods=['GET'])
@login_required
def api_usage_summary():
    """Get API usage summary for current user"""
    try:
        from models import ApiUsageLog
        
        days = request.args.get('days', 30, type=int)
        summary = ApiUsageLog.get_user_usage_summary(current_user.user_id, days=days)
        
        return jsonify({
            'success': True,
            'summary': summary
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching usage summary: {str(e)}'
        })

@app.route('/canary_diagnostics/<canary_id>', methods=['GET'])
@login_required
def canary_diagnostics(canary_id):
    """Diagnostic endpoint to analyze canary check-in patterns"""
    try:
        # Get the canary
        canary = Canary.get_by_id(canary_id)
        if not canary or canary.user_id != current_user.user_id:
            return jsonify({'error': 'Canary not found'}), 404
        
        # Get recent check-in logs (last 100)
        from models import CanaryLog
        logs = CanaryLog.get_by_canary_id(canary_id, limit=100)
        
        if not logs:
            return jsonify({
                'error': 'No check-in logs found',
                'suggestion': 'This canary has never checked in'
            })
        
        # Analyze check-in patterns
        analysis = analyze_checkin_patterns(logs, canary)
        
        return jsonify({
            'success': True,
            'canary': {
                'name': canary.name,
                'expected_interval_minutes': canary.interval_minutes,
                'expected_interval_days': round(canary.interval_minutes / 1440, 2),
                'grace_minutes': canary.grace_minutes,
                'status': canary.status,
                'token': canary.token[-8:] + '...'  # Last 8 chars for identification
            },
            'analysis': analysis
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error analyzing canary: {str(e)}'
        })

def analyze_checkin_patterns(logs, canary):
    """Analyze check-in patterns to identify issues"""
    from datetime import datetime, timezone, timedelta
    
    if len(logs) < 2:
        return {
            'issue': 'insufficient_data',
            'message': 'Need at least 2 check-ins to analyze patterns',
            'total_checkins': len(logs)
        }
    
    # Sort logs by timestamp (newest first from DB, reverse for analysis)
    sorted_logs = sorted(logs, key=lambda x: datetime.fromisoformat(x.timestamp.replace('Z', '+00:00')))
    
    # Calculate intervals between check-ins
    intervals = []
    timestamps = []
    sources = []
    
    for i in range(1, len(sorted_logs)):
        current = datetime.fromisoformat(sorted_logs[i].timestamp.replace('Z', '+00:00'))
        previous = datetime.fromisoformat(sorted_logs[i-1].timestamp.replace('Z', '+00:00'))
        
        interval_seconds = (current - previous).total_seconds()
        interval_minutes = interval_seconds / 60
        
        intervals.append(interval_minutes)
        timestamps.append(current.isoformat())
        
        # Try to extract source information
        source_info = {
            'timestamp': current.isoformat(),
            'interval_minutes': round(interval_minutes, 2),
            'interval_readable': format_interval(interval_minutes),
            'user_agent': getattr(sorted_logs[i], 'user_agent', 'Unknown'),
            'ip_address': getattr(sorted_logs[i], 'ip_address', 'Unknown')
        }
        sources.append(source_info)
    
    # Statistical analysis
    avg_interval = sum(intervals) / len(intervals)
    min_interval = min(intervals)
    max_interval = max(intervals)
    
    # Identify issues
    issues = []
    recommendations = []
    
    # Check if intervals are much shorter than expected
    expected_minutes = canary.interval_minutes
    if avg_interval < expected_minutes * 0.01:  # Less than 1% of expected
        issues.append({
            'type': 'too_frequent',
            'severity': 'high',
            'message': f'Check-ins are happening every {format_interval(avg_interval)} instead of every {format_interval(expected_minutes)}'
        })
        recommendations.append('Verify your job is only pinging once per execution cycle')
    
    # Check for very short intervals (potential loops or multiple sources)
    short_intervals = [i for i in intervals if i < 5]  # Less than 5 minutes
    if len(short_intervals) > 0:
        issues.append({
            'type': 'rapid_fire',
            'severity': 'critical',
            'message': f'{len(short_intervals)} check-ins happened within 5 minutes of each other',
            'shortest_interval': f'{min(short_intervals):.2f} minutes'
        })
        recommendations.append('Check if multiple systems are using the same canary token')
        recommendations.append('Look for retry loops or error handling that might cause repeated pings')
    
    # Check for pattern consistency
    if len(intervals) > 5:
        # Look for two distinct patterns (might indicate multiple sources)
        from statistics import stdev
        if stdev(intervals) > avg_interval * 0.5:  # High variation
            issues.append({
                'type': 'inconsistent_pattern',
                'severity': 'medium',
                'message': 'Highly irregular check-in intervals detected'
            })
            recommendations.append('Multiple systems might be using the same token with different schedules')
    
    return {
        'total_checkins': len(logs),
        'analysis_period': f'{len(intervals)} intervals analyzed',
        'expected_interval_minutes': expected_minutes,
        'actual_patterns': {
            'average_interval_minutes': round(avg_interval, 2),
            'average_interval_readable': format_interval(avg_interval),
            'shortest_interval_minutes': round(min_interval, 2),
            'shortest_interval_readable': format_interval(min_interval),
            'longest_interval_minutes': round(max_interval, 2),
            'longest_interval_readable': format_interval(max_interval)
        },
        'recent_checkins': sources[-10:],  # Last 10 intervals
        'issues': issues,
        'recommendations': recommendations,
        'next_steps': [
            'Review the "Recent Check-ins" section to identify patterns',
            'Check if multiple systems are using the same canary token',
            'Verify your job scheduling configuration',
            'Consider creating separate canaries for different monitoring needs'
        ]
    }

def format_interval(minutes):
    """Format interval minutes into readable format"""
    if minutes < 1:
        return f"{minutes * 60:.1f} seconds"
    elif minutes < 60:
        return f"{minutes:.1f} minutes"
    elif minutes < 1440:  # Less than a day
        hours = minutes / 60
        return f"{hours:.1f} hours"
    else:
        days = minutes / 1440
        return f"{days:.1f} days"

@app.route('/api_usage_logs', methods=['GET'])
@login_required
def api_usage_logs():
    """Get detailed API usage logs for current user"""
    try:
        from models import ApiUsageLog
        
        limit = request.args.get('limit', 50, type=int)
        logs = ApiUsageLog.get_by_user_id(current_user.user_id, limit=limit)
        
        # Convert logs to dictionaries for JSON serialization
        logs_data = []
        for log in logs:
            logs_data.append({
                'timestamp': log.timestamp,
                'feature_used': log.feature_used,
                'model': log.model,
                'input_tokens': log.input_tokens,
                'output_tokens': log.output_tokens,
                'total_tokens': log.total_tokens,
                'estimated_cost': log.estimated_cost,
                'success': log.success,
                'error_message': log.error_message,
                'response_time_ms': log.response_time_ms,
                'canary_id': log.canary_id
            })
        
        return jsonify({
            'success': True,
            'logs': logs_data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching usage logs: {str(e)}'
        })

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
            user_id = validate_api_key(api_key, endpoint='deployment_webhook')
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
            
        user_id = validate_api_key(api_key, endpoint='create_canary_from_api')
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
            
        user_id = validate_api_key(api_key, endpoint='update_canary_deployment', canary_id=canary_id)
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
    
    # Skip notifications for canaries pending email verification
    if canary.status == 'pending_verification':
        print(f"⏸️ Skipping notifications for canary {canary.name} - pending email verification")
        return
    
    subject = f'SilentCanary Alert: {canary.name} has failed'
    
    # Get user for email fallback
    user = User.get_by_id(canary.user_id)
    
    # Get additional context for the email template (hardcoded for scheduler compatibility)
    dashboard_link = 'https://silentcanary.com/dashboard'
    canary_logs_link = f'https://silentcanary.com/canary/{canary.canary_id}/logs'
    
    # Check if smart alerts are enabled
    smart_alert = SmartAlert.get_by_canary_id(canary.canary_id)
    smart_alert_enabled = smart_alert and smart_alert.is_enabled
    
    # Slack message with markdown formatting
    slack_message = f"""🚨 *SilentCanary Alert*

Canary "*{canary.name}*" has failed to check in!

• Last check-in: {canary.last_checkin or 'Never'}
• Expected check-in: {canary.next_expected or 'N/A'}
• Grace period: {canary.grace_minutes} minutes
• Check-in interval: {canary.interval_minutes} minutes

Please investigate your monitoring target immediately.

📊 Dashboard: https://silentcanary.com/dashboard"""

    from datetime import datetime, timezone
    
    try:
        # Send email notification
        if canary.alert_type in ['email', 'both']:
            recipient = canary.alert_email or (user.email if user else None)
            if recipient:
                try:
                    # Send canary alert using template
                    success = send_templated_email(
                        recipients=recipient,
                        subject=subject,
                        template_name='canary_alert',
                        canary_name=canary.name,
                        environment=getattr(canary, 'environment', None),
                        service_name=getattr(canary, 'service_name', None),
                        interval_minutes=canary.interval_minutes,
                        last_checkin=canary.last_checkin or 'Never',
                        status=canary.status,
                        dashboard_link=dashboard_link,
                        canary_logs_link=canary_logs_link,
                        smart_alert_enabled=smart_alert_enabled
                    )
                    
                    if success:
                        print(f"📧 Email notification sent to {recipient}")
                        # Log successful email notification
                        if log_entry:
                            log_entry.update_email_notification('sent')
                    else:
                        raise Exception("Template email sending failed")
                        
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
        
        # Send webhook notification
        if canary.alert_type in ['slack', 'both'] and canary.slack_webhook:
            try:
                payload = {"text": slack_message}
                response = requests.post(canary.slack_webhook, json=payload)
                if response.status_code == 200:
                    print(f"💬 Webhook notification sent")
                    
                    # Log successful Slack notification
                    if log_entry:
                        log_entry.update_slack_notification('sent')
                        
                else:
                    print(f"❌ Webhook notification failed: {response.status_code}")
                    # Log failed Slack notification
                    if log_entry:
                        log_entry.update_slack_notification('failed')
                        
            except Exception as e:
                print(f"❌ Webhook notification error: {e}")
                # Log failed Slack notification
                if log_entry:
                    log_entry.update_slack_notification('failed')
        elif canary.alert_type in ['slack', 'both']:
            # Webhook was requested but no webhook available
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

def validate_api_key(api_key, endpoint=None, canary_id=None):
    """Validate API key and return associated user_id, with usage tracking"""
    from models import APIKey
    
    try:
        # First check new APIKey model
        api_key_obj = APIKey.get_by_key_value(api_key)
        if api_key_obj and api_key_obj.is_active:
            # Record usage with context
            api_key_obj.record_usage(
                endpoint=endpoint or request.endpoint,
                ip_address=request.remote_addr,
                canary_id=canary_id,
                status='success'
            )
            return api_key_obj.user_id
        
        # Fallback to old API key format for backwards compatibility
        import base64
        decoded = base64.b64decode(api_key).decode('utf-8')
        if ':' in decoded:
            user_id, secret = decoded.split(':', 1)
            # Check if this matches the old single API key format
            user = User.get_by_id(user_id)
            if user and user.api_key == api_key:
                # Migrate old API key to new system
                migrate_old_api_key(user, api_key)
                return user_id
        return None
    except:
        return None

def migrate_old_api_key(user, old_api_key):
    """Migrate old single API key to new multiple API key system"""
    from models import APIKey
    
    try:
        # Check if migration already done
        existing_keys = APIKey.get_by_user_id(user.user_id)
        if existing_keys:
            return  # Already migrated
        
        # Create new API key entry
        api_key = APIKey(
            user_id=user.user_id,
            name="Legacy API Key",
            key_value=old_api_key,
            is_active=True
        )
        api_key.save()
        
        # Clear old API key from user model
        user.api_key = None
        user.save()
        
        print(f"Migrated old API key for user {user.user_id}")
    except Exception as e:
        print(f"Error migrating API key: {e}")

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
            sensitivity=Decimal('0.6'),  # More conservative default
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
            sensitivity=Decimal('0.6') if data.get('smart_alert_sensitivity') is None else Decimal(str(data.get('smart_alert_sensitivity'))),
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
    
    
    # Send notifications based on alert type
    try:
        # Send email notification
        if canary.alert_type in ['email', 'both']:
            recipient = canary.alert_email or (user.email if user else None)
            if recipient:
                try:
                    # Use same template but with smart alert context
                    success = send_templated_email(
                        recipients=recipient,
                        subject=subject,
                        template_name='canary_alert',
                        canary_name=canary.name,
                        environment=getattr(canary, 'environment', None),
                        service_name=getattr(canary, 'service_name', None),
                        interval_minutes=canary.interval_minutes,
                        last_checkin=canary.last_checkin or 'Never',
                        status='Smart Alert Triggered',
                        dashboard_link=f"https://silentcanary.com/dashboard",
                        canary_logs_link=f"https://silentcanary.com/canary_logs/{canary.canary_id}",
                        smart_alert_link=f"https://silentcanary.com/smart_alert/{canary.canary_id}",
                        smart_alert_enabled=True,
                        avg_interval=smart_alert.pattern_data.get('avg_interval', canary.interval_minutes),
                        expected_interval=smart_alert.pattern_data.get('expected_interval', canary.interval_minutes),
                        sensitivity=f"{float(smart_alert.sensitivity) * 100:.1f}",
                        learning_period_days=smart_alert.learning_period_days
                    )
                    
                    if success:
                        print(f"📧 Smart alert email sent to {recipient}")
                        if log_entry:
                            log_entry.update_email_notification('sent')
                    else:
                        raise Exception("Smart alert template email failed")
                        
                except Exception as e:
                    print(f"❌ Smart alert email failed: {e}")
                    if log_entry:
                        log_entry.update_email_notification('failed', str(e))
        
        # Send webhook notification with ML context
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
                                },
                                {
                                    "title": "Dashboard",
                                    "value": "https://silentcanary.com/dashboard",
                                    "short": False
                                }
                            ],
                            "footer": "SilentCanary Smart Alerts - https://silentcanary.com",
                            "footer_icon": "🧠"
                        }
                    ]
                }
                
                response = requests.post(canary.slack_webhook, json=slack_message, timeout=10)
                if response.status_code == 200:
                    print(f"💬 Smart alert webhook notification sent")
                    if log_entry:
                        log_entry.update_slack_notification('sent')
                else:
                    print(f"❌ Smart alert webhook notification failed: {response.status_code}")
                    if log_entry:
                        log_entry.update_slack_notification('failed', f'HTTP {response.status_code}')
                        
            except Exception as e:
                print(f"❌ Smart alert webhook notification failed: {e}")
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

# AI Integration Functions
def call_claude_api(prompt, user_api_key, max_tokens=1000, feature_used='unknown', canary_id=None, user_id=None):
    """Call Claude API with user's own API key, retry logic, and usage logging"""
    if not user_api_key:
        print("call_claude_api: No API key provided")  # Debug log
        return None, "No API key provided"
    
    print("call_claude_api: Using user-provided API key")  # Debug log
    
    start_time = time.time()
    success = False
    error_message = None
    response_text = None
    input_tokens = None
    output_tokens = None
    total_tokens = None
    estimated_cost = None
    
    # Retry configuration
    max_retries = 3
    base_delay = 1  # Start with 1 second
    
    for attempt in range(max_retries + 1):
        try:
            from anthropic import Anthropic
            
            if attempt > 0:
                delay = base_delay * (2 ** (attempt - 1))  # Exponential backoff: 1s, 2s, 4s
                print(f"call_claude_api: Attempt {attempt + 1}, waiting {delay}s after overload...")
                time.sleep(delay)
            
            client = Anthropic(api_key=user_api_key)
            print("call_claude_api: Client created, making API call...")  # Debug log
            
            response = client.messages.create(
                model="claude-3-5-sonnet-20240620",
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # If we get here, the request succeeded
            break
            
        except Exception as e:
            error_message = str(e)
            print(f"call_claude_api: Attempt {attempt + 1} failed: {e}")
            
            # Check if this is a 529 overload error that we should retry
            is_overload = (hasattr(e, 'status_code') and e.status_code == 529) or \
                         ('overload' in error_message.lower() or '529' in error_message)
            
            # If not the last attempt and it's a retryable error, continue to next attempt
            if attempt < max_retries and is_overload:
                print(f"call_claude_api: Retryable overload error, will retry (attempt {attempt + 1}/{max_retries})")
                continue
            else:
                # Last attempt or non-retryable error, break and handle below
                print(f"call_claude_api: Final attempt failed or non-retryable error")
                break
    else:
        # This only executes if we never broke out of the loop (all retries failed)
        response = None
    
    # Process response if successful
    if 'response' in locals() and response:
        try:
            print(f"call_claude_api: Response received: {response}")  # Debug log
            
            # Extract usage information
            if hasattr(response, 'usage'):
                input_tokens = response.usage.input_tokens
                output_tokens = response.usage.output_tokens
                total_tokens = input_tokens + output_tokens
                
                # Estimate cost for Claude 3.5 Sonnet (approximate pricing)
                # Input: $3.00 per 1M tokens, Output: $15.00 per 1M tokens
                input_cost = (input_tokens / 1_000_000) * 3.00
                output_cost = (output_tokens / 1_000_000) * 15.00
                estimated_cost = input_cost + output_cost
            
            response_text = response.content[0].text
            success = True
            
        except Exception as e:
            print(f"call_claude_api: Error processing response: {e}")
            error_message = f"Error processing API response: {str(e)}"
    
    # Handle final error state (all retries failed)
    if not success and error_message:
        print(f"call_claude_api: All attempts failed with error: {error_message}")
        
        # Provide user-friendly error messages
        if hasattr(locals().get('e'), 'status_code'):
            status_code = locals()['e'].status_code
            if status_code == 401:
                error_message = "Invalid API key"
            elif status_code == 403:
                error_message = "Access denied - check API key permissions"  
            elif status_code == 429:
                error_message = "Rate limited - try again in a moment"
            elif status_code == 529:
                error_message = "Anthropic servers overloaded - retried 3 times, please try again later"
            elif status_code == 404:
                error_message = "API service not found"
        elif "overload" in error_message.lower() or "529" in error_message:
            error_message = "Anthropic servers overloaded - retried 3 times, please try again later"
        elif "authentication" in error_message.lower() or "invalid" in error_message.lower():
            error_message = "Invalid API key"
        elif "rate" in error_message.lower() or "limit" in error_message.lower():
            error_message = "Rate limited - try again in a moment"
        else:
            error_message = f"API error after retries: {str(error_message)[:100]}"
        
        # Log usage for failed requests
        try:
            response_time_ms = int((time.time() - start_time) * 1000)
            from models import ApiUsageLog
            usage_log = ApiUsageLog(
                user_id=user_id,
                api_type='anthropic',
                endpoint='messages',
                model='claude-3-5-sonnet-20240620',
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
                estimated_cost=estimated_cost,
                success=success,
                error_message=error_message,
                response_time_ms=response_time_ms,
                feature_used=feature_used,
                canary_id=canary_id
            )
            usage_log.save()
            print(f"call_claude_api: Usage logged - error case: {error_message}")
        except Exception as log_error:
            print(f"call_claude_api: Failed to log usage: {log_error}")
        
        return None, error_message
    
    # Log usage for successful requests and return
    try:
        response_time_ms = int((time.time() - start_time) * 1000)
        from models import ApiUsageLog
        usage_log = ApiUsageLog(
            user_id=user_id,
            api_type='anthropic',
            endpoint='messages',
            model='claude-3-5-sonnet-20240620',
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            estimated_cost=estimated_cost,
            success=success,
            error_message=error_message,
            response_time_ms=response_time_ms,
            feature_used=feature_used,
            canary_id=canary_id
        )
        usage_log.save()
        print(f"call_claude_api: Usage logged - tokens: {total_tokens}, cost: ${estimated_cost:.4f}" if total_tokens else "call_claude_api: Usage logged - success case")
    except Exception as log_error:
        print(f"call_claude_api: Failed to log usage: {log_error}")
    
    # Return successful response
    if success:
        return response_text, None
    else:
        return None, "Unknown error occurred"

def validate_anthropic_api_key(api_key):
    """Test if Anthropic API key is valid with a simple call"""
    if not api_key:
        return False, "Please enter an API key"
    
    # Clean the API key
    api_key = api_key.strip()
    print("Validating Anthropic API key format")  # Debug log
    
    # Check format - should start with sk-ant-
    if not api_key.startswith('sk-ant-'):
        return False, "Invalid API key format. Anthropic API keys start with 'sk-ant-'"
    
    # Check length - Anthropic keys are typically longer
    if len(api_key) < 40:
        return False, "API key seems too short. Please check your key at console.anthropic.com"
    
    try:
        from anthropic import Anthropic
        
        client = Anthropic(api_key=api_key)
        print("Anthropic client created, making test call...")  # Debug log
        
        # Make a minimal test call
        response = client.messages.create(
            model="claude-3-5-sonnet-20240620",
            max_tokens=5,
            messages=[{"role": "user", "content": "Hi"}]
        )
        
        print(f"Response received: {response}")  # Debug log
        
        if response and response.content and len(response.content) > 0:
            print("API key validation successful!")  # Debug log
            return True, "✅ API key validated successfully! AI features are now available."
        else:
            print("Empty response received")  # Debug log
            return False, "API key validation failed - empty response"
            
    except Exception as e:
        error_msg = str(e)
        print(f"API key validation exception: {e}")  # Debug log
        print(f"Exception type: {type(e)}")  # Debug log
        
        # Handle specific Anthropic error types
        if hasattr(e, 'status_code'):
            print(f"Status code: {e.status_code}")  # Debug log
            if e.status_code == 401:
                return False, "❌ Invalid API key. Get your key at console.anthropic.com"
            elif e.status_code == 403:
                return False, "❌ Access denied. Check your API key permissions at console.anthropic.com"
            elif e.status_code == 429:
                return False, "⏳ Rate limited. Your key is valid but try again in a moment."
            elif e.status_code == 404:
                return False, "❌ Service not found. Please check your API key at console.anthropic.com"
        
        # Handle generic errors
        error_lower = error_msg.lower()
        if "authentication" in error_lower or "invalid" in error_lower or "unauthorized" in error_lower:
            return False, "❌ Invalid API key. Get your key at console.anthropic.com"
        elif "rate" in error_lower or "limit" in error_lower:
            return False, "⏳ Rate limited. Your key is valid but try again in a moment."
        elif "timeout" in error_lower or "timed out" in error_lower:
            return False, "⏰ Validation timed out. Please try again."
        elif "network" in error_lower or "connection" in error_lower:
            return False, "🌐 Network error. Please check your internet connection and try again."
        else:
            print(f"API key validation error: {e}")
            return False, f"❌ Validation failed: {str(e)[:100]}"

def generate_ai_alert_analysis(canary, smart_alert, user_api_key):
    """Generate AI-powered alert analysis if user has API key"""
    if not user_api_key or not smart_alert.pattern_data:
        return None
        
    pattern_data = smart_alert.pattern_data
    
    prompt = f"""
    Analyze this monitoring alert for service '{canary.name}':
    
    Configuration:
    - Expected interval: {canary.interval_minutes} minutes
    - Grace period: {canary.grace_minutes} minutes
    - SLA threshold: {canary.sla_threshold}%
    
    Learned Patterns:
    - Average interval: {pattern_data.get('avg_interval', 'N/A')} minutes
    - Standard deviation: {pattern_data.get('interval_std', 'N/A')} minutes
    - Total check-ins analyzed: {pattern_data.get('total_checkins', 0)}
    - Learning period: {pattern_data.get('learning_start', 'N/A')} to {pattern_data.get('learning_end', 'N/A')}
    
    Current Status:
    - Status: {canary.status}
    - Last check-in: {canary.last_checkin}
    - Tags: {canary.tags}
    
    Provide a brief analysis in 2-3 sentences covering:
    1. What this pattern suggests about the service health
    2. Likely root cause if there's an issue
    3. One specific actionable recommendation
    
    Keep response concise and actionable for DevOps teams.
    """
    
    response, error = call_claude_api(prompt, user_api_key, max_tokens=300, feature_used='smart_alert_analysis', canary_id=canary.canary_id, user_id=canary.user_id)
    return response

def enhance_smart_alert_timeline(timeline_data, canary, smart_alert, user_api_key):
    """Enhance timeline data with AI insights"""
    if not user_api_key or not timeline_data.get('checkins'):
        return timeline_data
        
    # Build context from recent check-ins
    recent_intervals = []
    anomaly_count = 0
    for checkin in timeline_data['checkins']:
        if checkin.get('interval'):
            interval_str = checkin['interval'].replace(' min', '')
            try:
                interval = float(interval_str)
                recent_intervals.append(interval)
                if checkin.get('pattern_match', 100) < 60:
                    anomaly_count += 1
            except:
                pass
    
    if recent_intervals:
        prompt = f"""
        Analyze these recent check-in intervals for '{canary.name}':
        Recent intervals: {recent_intervals} minutes
        Anomalies detected: {anomaly_count} out of {len(timeline_data['checkins'])}
        Service type: {', '.join(canary.tags) if canary.tags else 'Unknown'}
        
        In 1-2 sentences, explain what this pattern indicates about service health and any trends to watch.
        """
        
        ai_insight, error = call_claude_api(prompt, user_api_key, max_tokens=200, feature_used='timeline_insight', canary_id=canary.canary_id, user_id=canary.user_id)
        if ai_insight:
            timeline_data['ai_insight'] = ai_insight
    
    return timeline_data

def enhance_smart_alert_logic(logic_data, canary, smart_alert, user_api_key):
    """Enhance alert logic explanation with AI insights"""
    if not user_api_key:
        return logic_data
        
    thresholds_text = "\n".join([f"- {t['condition']}: {t['value']}" for t in logic_data.get('current_thresholds', [])])
    
    prompt = f"""
    Explain this Smart Alert configuration for '{canary.name}' in simple terms:
    
    {thresholds_text}
    
    Service tags: {', '.join(canary.tags) if canary.tags else 'None'}
    
    In 2-3 sentences, explain:
    1. What these thresholds mean in practical terms
    2. Whether the configuration seems appropriate for this type of service
    3. One optimization suggestion if any
    
    Use clear, non-technical language that any developer would understand.
    """
    
    ai_explanation, error = call_claude_api(prompt, user_api_key, max_tokens=300, feature_used='smart_alert_logic', canary_id=canary.canary_id, user_id=canary.user_id)
    if ai_explanation:
        logic_data['ai_explanation'] = ai_explanation
        
    return logic_data

@app.route('/csrf-token')
def get_csrf_token():
    """Provide a fresh CSRF token for AJAX requests"""
    from flask_wtf.csrf import generate_csrf
    return jsonify({'csrf_token': generate_csrf()})

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
    
    # Debug: Print all registered routes
    print("🔍 FLASK ROUTES REGISTERED:")
    for rule in app.url_map.iter_rules():
        print(f"  {rule.rule} -> {rule.endpoint} [{', '.join(rule.methods)}]")
    
    try:
        app.run(debug=False, port=5000, host='0.0.0.0')
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()