from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional
from datetime import datetime, timezone, timedelta
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import os
import uuid
import pytz

# Import our DynamoDB models and Redis config
from models import User, Canary
from redis_config import get_redis_connection, test_redis_connection
from rq import Queue

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

# Redis Queue setup
try:
    redis_conn = get_redis_connection()
    notification_queue = Queue('notifications', connection=redis_conn)
    health_queue = Queue('health-checks', connection=redis_conn)
    print("✅ Redis queues initialized")
except Exception as e:
    print(f"❌ Redis queue initialization failed: {e}")
    redis_conn = None
    notification_queue = None
    health_queue = None

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

@app.template_filter('user_timezone')
def user_timezone_filter(dt):
    """Template filter to convert datetime to user's timezone."""
    if not current_user.is_authenticated or not dt:
        return dt
    return current_user.localize_datetime(dt)

# Forms (same as before)
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

# Routes (same as DynamoDB version)
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
            flash('Registration successful! Please log in.')
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

@app.route('/dashboard')
@login_required
def dashboard():
    canaries = Canary.get_by_user_id(current_user.user_id)
    
    # Add Redis queue status for admin users
    queue_stats = None
    if redis_conn:
        try:
            queue_stats = {
                'redis_connected': True,
                'health_queue_size': len(health_queue.get_jobs()) if health_queue else 0,
                'notification_queue_size': len(notification_queue.get_jobs()) if notification_queue else 0
            }
        except:
            queue_stats = {'redis_connected': False}
    
    return render_template('dashboard.html', canaries=canaries, queue_stats=queue_stats)

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

@app.route('/checkin/<token>')
def checkin(token):
    canary = Canary.get_by_token(token)
    if not canary:
        return jsonify({'status': 'error', 'message': 'Invalid token'}), 404
    
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
        
        # Update timezone
        current_user.timezone = form.timezone.data
        
        if current_user.save():
            flash('Settings updated successfully!')
        else:
            flash('Failed to update settings.')
        return redirect(url_for('settings'))
    
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.timezone.data = current_user.timezone
    
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
            
            # If status changed to failed but not saved yet, we'll show it as failed
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

@app.route('/admin/queues')
@login_required
def admin_queues():
    """Admin endpoint to view Redis queue status"""
    if not redis_conn:
        flash('Redis not available')
        return redirect(url_for('dashboard'))
    
    try:
        stats = {
            'health_checks': {
                'queued': len(health_queue.get_jobs()),
                'failed': len(health_queue.failed_job_registry),
                'finished': len(health_queue.finished_job_registry)
            },
            'notifications': {
                'queued': len(notification_queue.get_jobs()),
                'failed': len(notification_queue.failed_job_registry),
                'finished': len(notification_queue.finished_job_registry)
            }
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Test connections
    print("🔄 Testing connections...")
    
    # Test DynamoDB
    try:
        from models import get_dynamodb_resource
        dynamodb = get_dynamodb_resource()
        print("✅ DynamoDB connection successful")
    except Exception as e:
        print(f"❌ DynamoDB connection failed: {e}")
        exit(1)
    
    # Test Redis
    if not test_redis_connection():
        print("⚠️ Redis connection failed - background jobs will not work!")
        print("💡 Start Redis locally or configure AWS ElastiCache in .env")
    
    try:
        app.run(debug=True, port=5000, host='127.0.0.1')
    except (KeyboardInterrupt, SystemExit):
        print("🛑 Application stopped")
        if redis_conn:
            redis_conn.close()