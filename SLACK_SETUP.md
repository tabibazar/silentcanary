# Slack Webhook Setup for SilentCanary

## How to Create a Slack Webhook

1. **Go to your Slack workspace**
   - Visit https://api.slack.com/apps
   - Click "Create New App"

2. **Create the App**
   - Choose "From scratch"
   - Name: "SilentCanary"
   - Select your workspace

3. **Enable Incoming Webhooks**
   - Go to "Incoming Webhooks" in the sidebar
   - Turn on "Activate Incoming Webhooks"
   - Click "Add New Webhook to Workspace"

4. **Choose Channel**
   - Select the channel where you want alerts
   - Click "Allow"

5. **Copy Webhook URL**
   - Copy the webhook URL (starts with `https://hooks.slack.com/services/...`)
   - This is what you'll paste into SilentCanary

## Using in SilentCanary

1. **Create a new canary**
2. **Set Alert Type** to:
   - "Slack" - Slack notifications only
   - "Email + Slack" - Both email and Slack
3. **Paste your webhook URL** in the "Slack Webhook URL" field
4. **Save the canary**

## Example Slack Message

When a canary fails, you'll get a message like:

```
🚨 SilentCanary Alert

Canary "Database Backup Job" has failed to check in!

• Last check-in: 2025-08-29 10:30 UTC
• Expected check-in: 2025-08-29 11:30 UTC  
• Grace period: 5 minutes
• Check-in interval: 60 minutes

Please investigate your monitoring target immediately.
```

## Testing

You can test your webhook by creating a short-interval canary (e.g., 1 minute) and letting it fail to verify notifications work correctly.