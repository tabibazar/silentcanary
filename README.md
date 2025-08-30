# SilentCanary

A modern dead man's switch monitoring service built with Flask. SilentCanary helps you monitor your critical processes, cron jobs, and services by providing HTTP endpoints that your systems can "check in" to. If a process fails to check in within the specified time window, you'll receive email alerts.

## Features

- **User Authentication**: Secure registration with email verification
- **Password Reset**: Secure forgot password functionality with email links
- **Dead Man's Switch Monitoring**: Create canaries that monitor your processes
- **Email Alerts**: Get notified when your canaries fail to check in
- **Web Dashboard**: Manage all your canaries from a clean web interface
- **Simple HTTP API**: Easy integration with any system that can make HTTP requests
- **SQLite Database**: Lightweight, file-based database for easy deployment
- **Bootstrap UI**: Clean, responsive interface

## Installation

1. **Clone or download this project**

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the database:**
   ```bash
   python init_db.py
   ```

4. **Configure email:**
   - Copy `.env.example` to `.env`
   - Add your Gmail credentials
   - See "Gmail Setup" section below for details

5. **Run the application:**
   ```bash
   python app.py
   ```
   
   Or use the run script:
   ```bash
   python run.py
   ```

5. **Access the application:**
   - Open your browser to `http://127.0.0.1:5000`
   - Register a new account
   - Verify your email (check your local mail or see console output)
   - Start creating canaries!

## Running in PyCharm

1. Open the project in PyCharm
2. Configure a Python interpreter (preferably in a virtual environment)
3. Install the requirements: `pip install -r requirements.txt`
4. Initialize the database: `python init_db.py`
5. Configure your `.env` file with Gmail credentials
6. Set the run configuration:
   - Script path: `/path/to/your/project/app.py`
   - Working directory: `/path/to/your/project/`
7. Run the application
8. Access it at `http://127.0.0.1:5000`

## Usage

### Creating a Canary

1. Log into your dashboard
2. Click "Create Canary"
3. Fill in the details:
   - **Name**: A descriptive name for your canary
   - **Interval**: How often your process should check in (in minutes)
   - **Grace Period**: Extra time before marking as failed (in minutes)
   - **Alert Email**: Where to send failure notifications

### Integrating with Your Systems

After creating a canary, you'll get a unique check-in URL. Use this URL in your processes:

```bash
# Simple HTTP check-in
curl -X POST http://127.0.0.1:5000/checkin/your-canary-token

# In a cron job
0 */6 * * * curl -X POST http://127.0.0.1:5000/checkin/your-canary-token

# In a Python script
import requests
requests.post('http://127.0.0.1:5000/checkin/your-canary-token')

# In a bash script
#!/bin/bash
# Your actual work here
./backup-database.sh

# Check in after successful completion
curl -X POST http://127.0.0.1:5000/checkin/your-canary-token
```

### How It Works

1. Create a canary with your desired check-in interval (e.g., every 60 minutes)
2. Your process/script calls the check-in URL regularly
3. If SilentCanary doesn't receive a check-in within the interval + grace period, it marks the canary as "failed"
4. A background job runs every minute to check for failed canaries and sends email alerts

## Gmail Setup

SilentCanary uses Gmail SMTP for reliable email delivery. To set up email:

### 1. Enable 2-Factor Authentication
1. Go to https://myaccount.google.com/security
2. Enable 2-Factor Authentication if not already enabled
3. This is required to generate App Passwords

### 2. Generate App Password
1. Go to https://myaccount.google.com/apppasswords
2. Select "Mail" as the app type
3. Copy the generated 16-character password (format: xxxx xxxx xxxx xxxx)

### 3. Configure Environment Variables
1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and set your Gmail credentials:
   ```
   SECRET_KEY=your-random-secret-key-here
   GMAIL_USERNAME=your-email@gmail.com
   GMAIL_APP_PASSWORD=your-16-character-app-password
   ```

### 4. Quick Setup Script
Use the interactive setup script:
```bash
python3 setup_gmail.py
```

This will guide you through the Gmail configuration process.

## File Structure

```
silentcanary/
├── app.py              # Main Flask application
├── init_db.py          # Database initialization script
├── setup_gmail.py      # Gmail configuration helper
├── test_flask_email.py # Email testing script
├── run.py              # Alternative startup script
├── requirements.txt    # Python dependencies
├── README.md          # This file
├── .env                # Environment variables (create from .env.example)
├── .env.example       # Environment variables template
├── templates/         # HTML templates
│   ├── base.html      # Base template
│   ├── index.html     # Landing page
│   ├── login.html     # Login form
│   ├── register.html  # Registration form
│   ├── forgot_password.html # Forgot password form
│   ├── reset_password.html  # Password reset form
│   ├── dashboard.html # Main dashboard
│   ├── create_canary.html # Canary creation form
│   └── settings.html  # User settings
├── static/           # Static files (if needed)
└── instance/         # Flask instance folder
    └── silentcanary.db # SQLite database (created by init_db.py)
```

## Development

The application includes:
- User registration and authentication
- Email verification system
- Password reset functionality with secure tokens
- CSRF protection on forms
- SQLite database with SQLAlchemy ORM
- Background scheduler for monitoring canaries
- Bootstrap-based responsive UI

## Security Notes

- Change the `SECRET_KEY` in production
- Use HTTPS in production
- Consider using a more robust database for production use
- Set up proper email service credentials
- Review and secure the email verification system for production use

## License

This project is open source and available under the MIT License.