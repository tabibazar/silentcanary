# 🚀 SilentCanary EC2 Deployment

## Quick Start

### 1. Launch EC2 Instance
- **Instance Type**: `t4g.medium` (Graviton ARM64)
- **AMI**: Ubuntu 22.04 LTS ARM64
- **Security Group**: Allow ports 22, 80, 443

### 2. Connect and Setup
```bash
# Connect to your instance
ssh -i your-key.pem ubuntu@your-instance-ip

# Download the repository
git clone https://github.com/tabibazar/silentcanary.git
cd silentcanary

# Run quick setup
./quick-setup.sh

# Log out and back in for Docker permissions
exit
ssh -i your-key.pem ubuntu@your-instance-ip
cd silentcanary
```

### 3. Configure Environment
```bash
# Copy environment template
cp .env.template .env

# Edit with your credentials
nano .env
```

### 4. Setup SSL (Optional but Recommended)
```bash
# Make sure your domain points to this instance first
./setup-ssl.sh
```

### 5. Start Application
```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

## Environment Variables Required

```bash
# AWS (for DynamoDB)
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key

# Stripe
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# SendGrid
SENDGRID_API_KEY=SG....

# reCAPTCHA
RECAPTCHA_SITE_KEY=your_site_key
RECAPTCHA_SECRET_KEY=your_secret_key

# Flask
SECRET_KEY=your-random-secret-key
```

## Service Management

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# Restart a specific service
docker-compose restart app

# View logs
docker-compose logs -f app

# Update application
git pull
docker-compose build
docker-compose up -d
```

## Monitoring

```bash
# Check application health
curl http://localhost/health

# Monitor resources
htop
docker stats

# Check logs
docker-compose logs app
```

## Troubleshooting

### Services won't start
```bash
# Check Docker Compose config
docker-compose config

# Check individual service logs
docker-compose logs app
docker-compose logs redis
docker-compose logs nginx
```

### SSL Issues
```bash
# Check certificate files
ls -la ssl/

# Restart nginx after SSL setup
docker-compose restart nginx
```

### Database Connection Issues
```bash
# Test AWS credentials
aws sts get-caller-identity

# Check environment variables
docker-compose exec app env | grep AWS
```

## Cost Estimate
- **t4g.medium**: ~$15/month
- **Storage**: ~$2/month
- **Total**: ~$17/month (vs $120+/month for EKS)

---

*This deployment is production-ready and significantly more cost-effective than the previous EKS setup.*