# 🔧 SilentCanary Environment Variables Setup Guide

## 📋 Complete Environment Configuration

After running the deployment script, you need to configure your environment variables. Here's exactly what you need:

### 1. Copy the Production Environment Template

```bash
cd /opt/silentcanary
cp .env.production .env
nano .env
```

## 🔑 Required Environment Variables

### **Flask Application**
```bash
SECRET_KEY=generate_a_random_32_character_string_here
```
**How to generate**: `python3 -c "import secrets; print(secrets.token_hex(32))"`

### **AWS DynamoDB**
```bash
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
AWS_DEFAULT_REGION=ca-central-1
```

### **Stripe Payment Processing**
```bash
# Get these from https://dashboard.stripe.com/apikeys
STRIPE_PUBLISHABLE_KEY=pk_live_your_actual_publishable_key
STRIPE_SECRET_KEY=sk_live_your_actual_secret_key

# Webhook secret from https://dashboard.stripe.com/webhooks
STRIPE_WEBHOOK_SECRET=whsec_your_actual_webhook_secret
```

### **SendGrid Email Service**
```bash
# Get this from https://app.sendgrid.com/settings/api_keys
SENDGRID_API_KEY=SG.your_actual_sendgrid_api_key
```

### **reCAPTCHA Protection**
```bash
# Get these from https://www.google.com/recaptcha/admin
RECAPTCHA_SITE_KEY=your_actual_site_key
RECAPTCHA_SECRET_KEY=your_actual_secret_key
```

### **Anthropic AI (Optional)**
```bash
# Get this from https://console.anthropic.com/
ANTHROPIC_API_KEY=your_actual_anthropic_api_key
```

## 🚀 Quick Start Commands

### **1. Run the Complete Deployment Script**
```bash
# SSH into your server
ssh -i your-key.pem ubuntu@15.223.77.246

# Download and run the deployment script
curl -sSL https://raw.githubusercontent.com/tabibazar/silentcanary/main/complete-deployment.sh | bash
```

### **2. Configure Environment**
```bash
cd /opt/silentcanary
cp .env.production .env

# Generate a secret key
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env

# Edit with your actual API keys
nano .env
```

### **3. Start Services**
```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### **4. Setup SSL (Recommended)**
```bash
# Make sure your domain points to this server first
./setup-ssl.sh
```

## 🔍 Verification Steps

### **Check Services are Running**
```bash
docker-compose ps
```
Should show all services as "Up":
- silentcanary-app
- silentcanary-worker
- silentcanary-scheduler
- silentcanary-redis
- silentcanary-nginx

### **Test Application**
```bash
# Test health endpoint
curl http://localhost/health

# Test external access (replace with your IP)
curl http://15.223.77.246/health
```

### **Check Logs**
```bash
# Application logs
docker-compose logs app

# All services logs
docker-compose logs
```

## 🛠 Troubleshooting

### **Services Won't Start**
```bash
# Check configuration
docker-compose config

# Check individual service
docker-compose logs app
```

### **Database Connection Issues**
```bash
# Test AWS credentials
aws sts get-caller-identity

# Check DynamoDB tables
aws dynamodb list-tables --region ca-central-1
```

### **SSL Issues**
```bash
# Check certificate files
ls -la ssl/

# Restart nginx
docker-compose restart nginx
```

## 📊 Monitoring

### **System Resources**
```bash
# System overview
htop

# Docker resources
docker stats

# Disk usage
df -h
```

### **Application Health**
```bash
# Health check
curl https://silentcanary.com/health

# Application status
systemctl status silentcanary
```

## 🔒 Security Checklist

- [ ] Changed default SECRET_KEY
- [ ] Configured SSL certificates
- [ ] Firewall allows only ports 22, 80, 443
- [ ] SSH key-based authentication only
- [ ] All API keys are production keys
- [ ] Regular system updates scheduled

---

**🎉 Your SilentCanary application should now be running on https://silentcanary.com!**