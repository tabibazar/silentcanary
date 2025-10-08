# 🚀 SilentCanary EC2 Graviton Migration Guide

## Overview

This guide walks through migrating SilentCanary from EKS (Kubernetes) to a single AWS Graviton EC2 instance using Docker Compose. This approach is simpler, more cost-effective, and easier to manage.

## Benefits of EC2 Migration

- **Cost Reduction**: Single instance vs multiple EKS resources
- **Simplicity**: Docker Compose vs Kubernetes complexity
- **Performance**: Graviton processors for ARM64 optimization
- **Easier Debugging**: Direct access to logs and processes
- **Reduced Overhead**: No Kubernetes management overhead

---

## Migration Steps

### 1. Launch EC2 Graviton Instance

**Instance Specifications:**
- **Instance Type**: `t4g.medium` or `t4g.large` (Graviton ARM64)
- **AMI**: Ubuntu 22.04 LTS ARM64
- **Storage**: 20GB+ EBS GP3
- **Security Group**:
  - Port 22 (SSH)
  - Port 80 (HTTP)
  - Port 443 (HTTPS)

**Launch Command:**
```bash
aws ec2 run-instances \
    --image-id ami-0d70546e43a941d70 \
    --instance-type t4g.medium \
    --key-name your-key-pair \
    --security-group-ids sg-your-security-group \
    --subnet-id subnet-your-subnet \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=SilentCanary-Production}]'
```

### 2. Connect and Setup Instance

```bash
# Connect to instance
ssh -i your-key.pem ubuntu@your-instance-ip

# Download and run deployment script
curl -sSL https://raw.githubusercontent.com/tabibazar/silentcanary/main/deploy-to-ec2.sh | bash
```

### 3. Configure Application

```bash
# Switch to application directory
cd /opt/silentcanary

# Clone repository
sudo -u silentcanary git clone https://github.com/tabibazar/silentcanary.git app

# Setup environment
cd app && sudo ./setup-environment.sh

# Configure environment variables
sudo -u silentcanary cp .env.template .env
sudo -u silentcanary nano .env  # Fill in your credentials
```

### 4. Setup SSL Certificates

```bash
# Run SSL setup script
sudo ./setup-ssl.sh
```

### 5. Start Application

```bash
# Start all services
sudo systemctl start silentcanary

# Check status
sudo systemctl status silentcanary

# View logs
docker-compose logs -f
```

---

## Service Architecture

### Docker Compose Services

1. **App**: Main Flask application (Gunicorn + Gevent)
2. **Worker**: Background task processor
3. **Scheduler**: Cron-like job scheduler
4. **Redis**: In-memory cache and message broker
5. **Nginx**: Reverse proxy with SSL termination

### Service Management

```bash
# Start all services
sudo systemctl start silentcanary

# Stop all services
sudo systemctl stop silentcanary

# Restart services
sudo systemctl restart silentcanary

# View logs
docker-compose -f /opt/silentcanary/docker-compose.yml logs -f [service_name]

# Scale services (if needed)
docker-compose -f /opt/silentcanary/docker-compose.yml up -d --scale worker=2
```

---

## Configuration Files

### Environment Variables (.env)
```bash
# Production environment configuration
FLASK_ENV=production
SECRET_KEY=your-secret-key
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
STRIPE_SECRET_KEY=sk_live_...
SENDGRID_API_KEY=SG....
```

### Nginx Configuration
- SSL termination
- Rate limiting
- Static file serving
- Proxy to application

### SystemD Service
- Auto-start on boot
- Service management
- Restart on failure

---

## Monitoring and Maintenance

### Health Checks

```bash
# Application health
curl https://silentcanary.com/health

# Service status
sudo systemctl status silentcanary

# Docker container status
docker-compose ps

# Resource usage
htop
docker stats
```

### Log Management

```bash
# Application logs
docker-compose logs app

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# System logs
sudo journalctl -u silentcanary -f
```

### Backup Strategy

```bash
# Database backup (DynamoDB is managed by AWS)
# Application code backup
sudo tar -czf /backup/silentcanary-$(date +%Y%m%d).tar.gz /opt/silentcanary

# Environment backup
sudo cp /opt/silentcanary/.env /backup/.env-$(date +%Y%m%d)
```

---

## Deployment Workflow

### Code Deployment

```bash
# Pull latest code
cd /opt/silentcanary/app
sudo -u silentcanary git pull

# Restart application
sudo systemctl restart silentcanary

# Check deployment
curl https://silentcanary.com/health
```

### Rolling Updates

```bash
# Build new image
docker-compose build

# Update services one by one
docker-compose up -d --no-deps app
docker-compose up -d --no-deps worker
docker-compose up -d --no-deps scheduler
```

---

## Troubleshooting

### Common Issues

1. **Permission Issues**
   ```bash
   sudo chown -R silentcanary:silentcanary /opt/silentcanary
   ```

2. **SSL Certificate Issues**
   ```bash
   sudo ./setup-ssl.sh
   docker-compose restart nginx
   ```

3. **Database Connection Issues**
   ```bash
   # Check AWS credentials
   aws sts get-caller-identity

   # Test DynamoDB access
   aws dynamodb list-tables --region ca-central-1
   ```

4. **Service Not Starting**
   ```bash
   # Check logs
   sudo journalctl -u silentcanary -n 50

   # Check Docker Compose
   docker-compose config
   docker-compose ps
   ```

### Performance Tuning

```bash
# Adjust worker processes in docker-compose.yml
# Monitor with htop and docker stats
# Scale Redis if needed
# Optimize Nginx worker processes
```

---

## Security Considerations

- **Firewall**: Only expose ports 22, 80, 443
- **SSH**: Use key-based authentication only
- **SSL**: Let's Encrypt with auto-renewal
- **Updates**: Regular system updates via cron
- **Backup**: Regular application and data backups
- **Monitoring**: CloudWatch for instance monitoring

---

## Cost Estimation

**Monthly Cost Breakdown:**
- t4g.medium instance: ~$15/month
- EBS storage (20GB): ~$2/month
- Data transfer: ~$5/month
- **Total**: ~$22/month

**Compared to EKS:**
- EKS cluster: $72/month
- Worker nodes: $30+/month
- Load balancer: $18/month
- **Previous Total**: $120+/month

**Savings**: ~$100/month (80% reduction)

---

## Migration Checklist

- [ ] Launch Graviton EC2 instance
- [ ] Run deployment script
- [ ] Configure environment variables
- [ ] Setup SSL certificates
- [ ] Test application functionality
- [ ] Update DNS to point to new instance
- [ ] Monitor for 24 hours
- [ ] Decommission EKS cluster
- [ ] Update documentation and runbooks

---

*This migration provides significant cost savings while maintaining all functionality and improving operational simplicity.*