# SilentCanary with DynamoDB

This version of SilentCanary uses AWS DynamoDB instead of SQLite for the database backend, making it suitable for cloud deployment with AWS free tier.

## Features

- **Dead Man's Switch Monitoring**: Monitor processes and services with configurable check-in intervals
- **Multi-notification Support**: Email and Slack notifications
- **User Management**: Registration, login, timezone settings
- **Canary Management**: Create, edit, delete monitoring canaries
- **Timezone Awareness**: Browser-detected timezones with global display
- **DynamoDB Backend**: Cloud-ready database with AWS free tier support

## Prerequisites

- Python 3.9+
- AWS Account (for DynamoDB)
- SendGrid API Key (for email notifications)

## Setup Instructions

### 1. Install Dependencies

```bash
pip install flask flask-login flask-wtf flask-mail boto3 pytz python-dotenv apscheduler requests pillow
```

### 2. Configure Environment Variables

Create a `.env` file with:

```env
SECRET_KEY=your-secret-key-here
SENDGRID_API_KEY=your-sendgrid-api-key
MAIL_DEFAULT_SENDER=your-verified-sender@domain.com
AWS_REGION=us-east-1

# AWS Credentials (or use IAM roles/profiles)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# Optional: For local DynamoDB development
# DYNAMODB_LOCAL=true
```

### 3. Set Up AWS Credentials

Choose one of these methods:

**Option A: Environment Variables**
Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in your `.env` file.

**Option B: AWS CLI Profile**
```bash
aws configure
```

**Option C: IAM Roles (for EC2/Lambda deployment)**
No additional configuration needed.

### 4. Create DynamoDB Tables

```bash
python dynamodb_setup.py
```

This creates two tables:
- `SilentCanary_Users`: User accounts with email/username indexes
- `SilentCanary_Canaries`: Monitoring canaries with user and token indexes

### 5. Run the Application

```bash
python app_dynamodb.py
```

The application will run on `http://127.0.0.1:5000`

## Migration from SQLite

If you have existing data in SQLite format:

```bash
python migrate_to_dynamodb.py
```

This will migrate all users and canaries from the SQLite database to DynamoDB.

## DynamoDB Table Structure

### Users Table
- **Primary Key**: `user_id` (String)
- **GSI**: `email-index` on `email`
- **GSI**: `username-index` on `username`
- **Attributes**: username, email, password_hash, is_verified, timezone, created_at

### Canaries Table
- **Primary Key**: `canary_id` (String)
- **GSI**: `user-id-index` on `user_id`
- **GSI**: `token-index` on `token`
- **Attributes**: name, user_id, interval_minutes, grace_minutes, token, status, is_active, alert_type, alert_email, slack_webhook, created_at, last_checkin, next_expected

## AWS Free Tier Usage

DynamoDB free tier includes:
- 25 GB of storage
- 25 provisioned read capacity units
- 25 provisioned write capacity units
- 2.5 million stream read requests

This application uses **on-demand billing** which is ideal for variable workloads and includes:
- 25 WRU and 25 RRU per month free
- Beyond that: $1.25 per million write requests, $0.25 per million read requests

For typical usage (small number of users, regular check-ins), this should stay within free tier limits.

## API Usage

### Check-in Endpoint
```bash
curl -X GET https://your-domain/checkin/your-canary-token
```

### Example Automation
```bash
#!/bin/bash
# Add to crontab: */30 * * * * /path/to/backup_and_checkin.sh

# Your backup/monitoring script here
/usr/local/bin/my-backup-script.sh

# Check in to SilentCanary
curl -X GET "https://your-app.com/checkin/696136bd-5e5f-421b-88e9-d6230bddf066"
```

## Deployment Options

### AWS EC2
1. Launch a t2.micro instance (free tier eligible)
2. Install Python and dependencies
3. Set up IAM role for DynamoDB access
4. Use systemd or supervisor to manage the Flask app
5. Set up nginx as reverse proxy

### AWS Lambda (Serverless)
The application can be adapted for Lambda deployment using frameworks like Zappa or AWS SAM.

### Other Cloud Providers
The DynamoDB models can be adapted to use other NoSQL databases like:
- Google Cloud Firestore
- Azure Cosmos DB
- MongoDB Atlas

## Files Overview

- `app_dynamodb.py`: Main Flask application (DynamoDB version)
- `models.py`: DynamoDB data models and operations
- `dynamodb_setup.py`: Creates DynamoDB tables
- `migrate_to_dynamodb.py`: Migrates data from SQLite to DynamoDB
- `app.py`: Original SQLite version (for reference)

## Monitoring

The application includes:
- Automatic canary health checking every minute
- Detailed logging of check-ins and failures
- Email and Slack notifications for failures
- Timezone-aware datetime display

## Support

For issues with:
- **DynamoDB**: Check AWS credentials and table creation
- **Email**: Verify SendGrid API key and sender verification
- **Slack**: Test webhook URLs and permissions
- **Timezones**: Ensure pytz is installed correctly

## Cost Optimization

To minimize AWS costs:
1. Use on-demand billing for variable workloads
2. Monitor usage in AWS Console
3. Set up billing alerts
4. Consider reserved capacity for predictable workloads
5. Use local DynamoDB for development (`DYNAMODB_LOCAL=true`)

## Security Notes

- Never commit AWS credentials to version control
- Use IAM roles with minimal required permissions
- Enable CloudTrail for DynamoDB API logging
- Consider VPC endpoints for secure DynamoDB access
- Rotate API keys regularly