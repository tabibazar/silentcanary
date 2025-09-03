from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import os
import uuid
import pytz

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'asdfkjahc rha384y92834yc cx832b48234918xb487214jhasf')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///silentcanary.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SendGrid Email Configuration
app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'apikey'
app.config['MAIL_PASSWORD'] = os.environ.get('SENDGRID_API_KEY')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'auth@avriz.com')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Initialize scheduler
scheduler = BackgroundScheduler()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_verified = db.Column(db.Boolean, default=False)
    timezone = db.Column(db.String(50), default='UTC')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    canaries = db.relationship('Canary', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def localize_datetime(self, dt):
        """Convert UTC datetime to user's local timezone."""
        if not dt:
            return None
        if dt.tzinfo is None:
            # Assume naive datetime is UTC
            dt = dt.replace(tzinfo=timezone.utc)
        
        user_tz = pytz.timezone(getattr(self, 'timezone', 'UTC'))
        return dt.astimezone(user_tz)

class Canary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    token = db.Column(db.String(36), unique=True, nullable=False)
    interval_minutes = db.Column(db.Integer, nullable=False, default=60)
    grace_minutes = db.Column(db.Integer, nullable=False, default=5)
    alert_type = db.Column(db.String(20), nullable=False, default='email')
    alert_email = db.Column(db.String(120))
    slack_webhook = db.Column(db.String(500))
    is_active = db.Column(db.Boolean, default=True)
    last_checkin = db.Column(db.DateTime)
    next_expected = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='waiting')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, **kwargs):
        super(Canary, self).__init__(**kwargs)
        if not self.token:
            self.token = str(uuid.uuid4())

    def checkin(self):
        now_utc = datetime.now(timezone.utc)
        # Store as naive datetime for SQLite compatibility
        self.last_checkin = now_utc.replace(tzinfo=None)
        self.next_expected = self.last_checkin + timedelta(minutes=self.interval_minutes)
        self.status = 'healthy'
        db.session.commit()

    def is_overdue(self):
        if not self.next_expected:
            return False
        grace_period = timedelta(minutes=self.grace_minutes)
        # Convert next_expected to UTC timezone if it's naive
        if self.next_expected.tzinfo is None:
            next_expected_utc = self.next_expected.replace(tzinfo=timezone.utc)
        else:
            next_expected_utc = self.next_expected
        return datetime.now(timezone.utc) > (next_expected_utc + grace_period)

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except ValueError:
        # Handle case where user_id is a UUID string from previous session
        return None

@app.template_filter('user_timezone')
def user_timezone_filter(dt):
    """Template filter to convert datetime to user's timezone."""
    from flask_login import current_user
    if not current_user.is_authenticated or not dt:
        return dt
    return current_user.localize_datetime(dt)

def init_db():
    """Initialize the database by creating all tables."""
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

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
    interval_minutes = IntegerField('Check-in Interval (minutes)', validators=[DataRequired()], default=60)
    grace_minutes = IntegerField('Grace Period (minutes)', validators=[DataRequired()], default=5)
    alert_type = SelectField('Alert Type', choices=[('email', 'Email'), ('slack', 'Slack'), ('both', 'Email + Slack')], default='email')
    alert_email = StringField('Alert Email', validators=[Optional(), Email()])
    slack_webhook = StringField('Slack Webhook URL', validators=[Optional()])
    submit = SubmitField('Create Canary')

class SettingsForm(FlaskForm):
    username = StringField('Username', render_kw={'readonly': True})
    email = StringField('Email', render_kw={'readonly': True})
    timezone = SelectField('Timezone', choices=[], validators=[DataRequired()])
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[Optional(), EqualTo('new_password')])
    submit = SubmitField('Update Settings')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
    except Exception:
        return False
    return email

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset')

def confirm_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset', max_age=expiration)
    except Exception:
        return False
    return email

def send_slack_notification(webhook_url, message):
    """Send notification to Slack via webhook."""
    if not webhook_url:
        print("❌ No Slack webhook URL provided")
        return False
    
    try:
        import requests
        
        payload = {
            "text": message,
            "username": "SilentCanary",
            "icon_emoji": ":bird:"
        }
        
        response = requests.post(webhook_url, json=payload)
        
        if response.status_code == 200:
            print("✅ Slack notification sent successfully!")
            return True
        else:
            print(f"❌ Slack webhook error: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to send Slack notification: {e}")
        return False

def send_email(to, subject, template):
    """Send email using SendGrid Web API."""
    api_key = os.environ.get('SENDGRID_API_KEY')
    sender_email = app.config['MAIL_DEFAULT_SENDER']
    
    if not api_key:
        print("❌ SENDGRID_API_KEY not configured")
        return False
    
    try:
        import requests
        
        print(f"Sending email to: {to}")
        print(f"Subject: {subject}")
        print(f"Sender: {sender_email}")
        
        payload = {
            "personalizations": [
                {
                    "to": [{"email": to}],
                    "subject": subject
                }
            ],
            "from": {"email": sender_email},
            "content": [
                {
                    "type": "text/html",
                    "value": template
                }
            ]
        }
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            json=payload,
            headers=headers
        )
        
        if response.status_code == 202:
            print("✅ Email sent successfully via SendGrid API!")
            return True
        else:
            print(f"❌ SendGrid API error: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        import traceback
        traceback.print_exc()
        return False

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
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash('Username already taken')
            return redirect(url_for('register'))
        
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        token = generate_confirmation_token(user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = f'Please click the link to confirm your email: <a href="{confirm_url}">Confirm Email</a>'
        
        if send_email(user.email, 'Confirm Your Email', html):
            flash('A confirmation email has been sent to your email address.')
        else:
            flash('Registration successful! Please contact admin to verify your email.')
        
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash('The confirmation link is invalid or has expired.')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first_or_404()
    if user.is_verified:
        flash('Account already confirmed.')
    else:
        user.is_verified = True
        db.session.commit()
        flash('Your account has been confirmed!')
    
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if not user.is_verified:
                flash('Please verify your email before logging in.')
                return redirect(url_for('login'))
            
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
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = generate_reset_token(user.email)
            reset_url = url_for('reset_password', token=token, _external=True)
            html = f'''
            <h2>Password Reset Request</h2>
            <p>Hello {user.username},</p>
            <p>You requested a password reset for your SilentCanary account.</p>
            <p>Click the link below to reset your password:</p>
            <p><a href="{reset_url}">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, please ignore this email.</p>
            '''
            
            if send_email(user.email, 'SilentCanary - Password Reset Request', html):
                flash('A password reset link has been sent to your email address.')
            else:
                flash('Error sending email. Please contact support.')
        else:
            # Don't reveal if email exists or not for security
            flash('If that email address exists, a password reset link has been sent.')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    email = confirm_reset_token(token)
    if not email:
        flash('The password reset link is invalid or has expired.')
        return redirect(url_for('forgot_password'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(form.password.data)
            db.session.commit()
            flash('Your password has been reset successfully!')
            return redirect(url_for('login'))
        else:
            flash('User not found.')
            return redirect(url_for('forgot_password'))
    
    return render_template('reset_password.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    canaries = current_user.canaries
    for canary in canaries:
        if canary.is_overdue() and canary.status != 'failed':
            canary.status = 'failed'
            db.session.commit()
    
    return render_template('dashboard.html', canaries=canaries)

@app.route('/create_canary', methods=['GET', 'POST'])
@login_required
def create_canary():
    form = CanaryForm()
    if form.validate_on_submit():
        canary = Canary(
            name=form.name.data,
            interval_minutes=form.interval_minutes.data,
            grace_minutes=form.grace_minutes.data,
            alert_type=form.alert_type.data,
            alert_email=form.alert_email.data or current_user.email,
            slack_webhook=form.slack_webhook.data,
            user_id=current_user.id
        )
        db.session.add(canary)
        db.session.commit()
        flash(f'Canary "{canary.name}" created successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('create_canary.html', form=form)

@app.route('/checkin/<token>', methods=['POST', 'GET'])
def checkin(token):
    canary = Canary.query.filter_by(token=token).first_or_404()
    canary.checkin()
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
        # Check if user is trying to change password
        if form.new_password.data:
            if not form.current_password.data:
                flash('Current password is required when changing password')
                return render_template('settings.html', form=form)
            if not current_user.check_password(form.current_password.data):
                flash('Current password is incorrect')
                return render_template('settings.html', form=form)
            current_user.set_password(form.new_password.data)
        
        # Update only timezone (username/email are read-only)
        current_user.timezone = form.timezone.data
        
        db.session.commit()
        flash('Settings updated successfully!')
        return redirect(url_for('settings'))
    
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.timezone.data = getattr(current_user, 'timezone', 'UTC')
    
    return render_template('settings.html', form=form)

@app.route('/edit_canary/<int:canary_id>', methods=['GET', 'POST'])
@login_required
def edit_canary(canary_id):
    canary = Canary.query.get_or_404(canary_id)
    if canary.user_id != current_user.id:
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
            canary.next_expected = canary.last_checkin + timedelta(minutes=canary.interval_minutes)
        
        db.session.commit()
        flash(f'Canary "{canary.name}" updated successfully')
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

@app.route('/delete_canary/<int:canary_id>', methods=['POST'])
@login_required
def delete_canary(canary_id):
    canary = Canary.query.get_or_404(canary_id)
    if canary.user_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    db.session.delete(canary)
    db.session.commit()
    flash(f'Canary "{canary.name}" deleted')
    return redirect(url_for('dashboard'))

def send_notifications(canary):
    """Send notifications based on canary alert type."""
    subject = f'SilentCanary Alert: {canary.name} has failed'
    
    # Email message
    html_message = f'''
    <h2>🚨 SilentCanary Alert</h2>
    <p>Your canary "<strong>{canary.name}</strong>" has failed to check in.</p>
    <ul>
        <li><strong>Last check-in:</strong> {canary.last_checkin.strftime('%Y-%m-%d %H:%M UTC') if canary.last_checkin else 'Never'}</li>
        <li><strong>Expected check-in:</strong> {canary.next_expected.strftime('%Y-%m-%d %H:%M UTC') if canary.next_expected else 'N/A'}</li>
        <li><strong>Grace period:</strong> {canary.grace_minutes} minutes</li>
        <li><strong>Check-in interval:</strong> {canary.interval_minutes} minutes</li>
    </ul>
    <p>Please investigate your monitoring target immediately.</p>
    <hr>
    <p><small>This alert was sent by SilentCanary monitoring system.</small></p>
    '''
    
    # Slack message  
    slack_message = f"""🚨 *SilentCanary Alert*
    
Canary "*{canary.name}*" has failed to check in!

• *Last check-in:* {canary.last_checkin.strftime('%Y-%m-%d %H:%M UTC') if canary.last_checkin else 'Never'}
• *Expected check-in:* {canary.next_expected.strftime('%Y-%m-%d %H:%M UTC') if canary.next_expected else 'N/A'}  
• *Grace period:* {canary.grace_minutes} minutes
• *Check-in interval:* {canary.interval_minutes} minutes

Please investigate your monitoring target immediately."""

    success = False
    
    # Send notifications based on alert type
    if canary.alert_type in ['email', 'both']:
        if canary.alert_email:
            email_sent = send_email(canary.alert_email, subject, html_message)
            if email_sent:
                print(f"✅ Email sent to {canary.alert_email}")
                success = True
            else:
                print(f"❌ Failed to send email to {canary.alert_email}")
    
    if canary.alert_type in ['slack', 'both']:
        if canary.slack_webhook:
            slack_sent = send_slack_notification(canary.slack_webhook, slack_message)
            if slack_sent:
                print(f"✅ Slack notification sent")
                success = True
            else:
                print(f"❌ Failed to send Slack notification")
    
    return success

def check_failed_canaries():
    with app.app_context():
        print(f"🔍 Checking for failed canaries at {datetime.now(timezone.utc)}")
        overdue_canaries = Canary.query.filter(
            Canary.is_active == True,
            Canary.status != 'failed'
        ).all()
        
        failed_count = 0
        for canary in overdue_canaries:
            if canary.is_overdue():
                print(f"⚠️ Canary '{canary.name}' is overdue - sending notifications")
                canary.status = 'failed'
                send_notifications(canary)
                failed_count += 1
        
        if failed_count > 0:
            print(f"📧 Processed {failed_count} failed canaries")
        else:
            print("✅ All canaries are healthy")
        
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        scheduler.add_job(
            func=check_failed_canaries,
            trigger="interval",
            minutes=1,
            id='canary_check'
        )
        scheduler.start()
    
    try:
        # Security fix: Control debug mode via environment variable
        debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
        app.run(debug=debug_mode, port=5000, host='127.0.0.1')
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
