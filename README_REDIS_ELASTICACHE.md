# SilentCanary with Redis/ElastiCache Backend

This version of SilentCanary uses Redis Queue (RQ) with AWS ElastiCache for scalable background job processing, replacing the single-threaded APScheduler.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Flask Web     │    │   Redis Queue   │    │   RQ Workers    │
│   Application   │───▶│   (ElastiCache) │◀───│   (Background   │
│                 │    │                 │    │    Processes)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   DynamoDB      │    │   Job Queues:   │    │   Notifications │
│   (User/Canary  │    │   - health      │    │   - Email       │
│    Storage)     │    │   - notifications│   │   - Slack       │
└─────────────────┘    │   - scheduler   │    │                 │
                       └─────────────────┘    └─────────────────┘
```

## Features

- **Distributed Background Jobs**: Redis Queue for scalable job processing
- **AWS ElastiCache Integration**: Production-ready Redis managed service
- **Separate Worker Processes**: Health checks and notifications run independently
- **Job Scheduling**: Redis-based scheduler replaces APScheduler
- **Fault Tolerance**: Failed jobs are retried and logged
- **Monitoring**: Queue status and job metrics via admin endpoints

## Prerequisites

- Python 3.9+
- Redis server (local) or AWS ElastiCache
- AWS Account (for DynamoDB + ElastiCache)
- SendGrid API Key

## Setup Instructions

### 1. Install Dependencies

```bash
pip install flask flask-login flask-wtf flask-mail boto3 pytz python-dotenv redis rq requests pillow
```

### 2. Configure Environment Variables

Create a `.env` file with:

```env
# Flask & Email
SECRET_KEY=your-secret-key-here
SENDGRID_API_KEY=your-sendgrid-api-key
MAIL_DEFAULT_SENDER=your-verified-sender@domain.com

# AWS DynamoDB
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# Redis Configuration
# For local development:
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# For AWS ElastiCache (production):
REDIS_ENDPOINT=your-cluster.abc123.cache.amazonaws.com
REDIS_PORT=6379
REDIS_PASSWORD=your_auth_token_if_required
REDIS_SSL=true
```

### 3. Set Up AWS ElastiCache (Production)

1. **Create ElastiCache Cluster**:
   ```bash
   aws elasticache create-cache-cluster \
     --cache-cluster-id silentcanary-redis \
     --cache-node-type cache.t3.micro \
     --engine redis \
     --num-cache-nodes 1 \
     --security-group-ids sg-xxxxxxxxx \
     --subnet-group-name default
   ```

2. **Configure Security Groups**:
   - Allow port 6379 from your application servers
   - Restrict access to your VPC/subnets only

3. **Update .env**:
   ```env
   REDIS_ENDPOINT=silentcanary-redis.abc123.cache.amazonaws.com
   REDIS_PORT=6379
   REDIS_SSL=true
   ```

### 4. Create DynamoDB Tables

```bash
python dynamodb_setup.py
```

### 5. Test Connections

```bash
python redis_config.py    # Test Redis connection
```

### 6. Run the Application

**Terminal 1: Web Application**
```bash
python app_redis.py
```

**Terminal 2: Worker Process**
```bash
python worker.py
```

**Terminal 3: Health Check Scheduler**
```bash
python scheduler.py
```

## Redis Queue Architecture

### Queues

1. **health-checks** (High Priority)
   - Runs canary health checks every minute
   - Identifies failed canaries
   - Updates canary status

2. **notifications** (Medium Priority) 
   - Sends email notifications via SendGrid
   - Sends Slack notifications via webhooks
   - Handles notification retries

3. **scheduler** (Low Priority)
   - Schedules recurring health checks
   - Manages job cleanup

### Job Flow

```
Scheduler ──┐
            ├─► health-checks queue ──► Worker ──┐
            │                                   │
            └─► scheduler queue                 │
                                               │
User Action ────► notifications queue ─────────┤
                                               │
                                               ▼
                                        Job Processing
                                        (Email/Slack)
```

## Scaling Considerations

### Worker Scaling

**Single Server**:
```bash
# Run multiple workers for better throughput
python worker.py &    # Worker 1
python worker.py &    # Worker 2  
python worker.py &    # Worker 3
```

**Multiple Servers**:
- Deploy worker.py on multiple EC2 instances
- All workers connect to the same ElastiCache cluster
- Automatically load balances jobs across workers

### ElastiCache Scaling

**Development**: `cache.t3.micro` (Free tier eligible)
**Production**: `cache.r7g.large` or higher based on load

**Monitoring**:
- CPU utilization
- Memory usage
- Connection count
- Cache hit ratio

### Cost Optimization

**ElastiCache Pricing** (us-east-1):
- `cache.t3.micro`: ~$15/month (covered by free tier for 12 months)
- `cache.t3.small`: ~$30/month
- `cache.r7g.large`: ~$150/month

**Free Tier Benefits**:
- 750 hours/month of cache.t3.micro
- No data transfer charges within same AZ

## Deployment Options

### AWS EC2 + ElastiCache

```bash
# Install Redis CLI for debugging
sudo yum install redis-tools

# Test ElastiCache connection
redis-cli -h your-cluster.abc123.cache.amazonaws.com -p 6379 ping
```

### Docker Deployment

```dockerfile
# Dockerfile.worker
FROM python:3.9-slim
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "worker.py"]

# Dockerfile.scheduler  
FROM python:3.9-slim
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "scheduler.py"]
```

**Docker Compose**:
```yaml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "5000:5000"
    environment:
      - REDIS_ENDPOINT=prod-cluster.cache.amazonaws.com
    command: python app_redis.py

  worker:
    build: 
      dockerfile: Dockerfile.worker
    environment:
      - REDIS_ENDPOINT=prod-cluster.cache.amazonaws.com
    deploy:
      replicas: 3

  scheduler:
    build:
      dockerfile: Dockerfile.scheduler  
    environment:
      - REDIS_ENDPOINT=prod-cluster.cache.amazonaws.com
```

## Monitoring & Debugging

### Admin Endpoints

- `GET /admin/queues` - View queue statistics
- Jobs can be monitored via Redis CLI or RQ Dashboard

### Redis CLI Commands

```bash
# Connect to ElastiCache
redis-cli -h your-cluster.abc123.cache.amazonaws.com -p 6379

# View queues
KEYS rq:queue:*

# View jobs in queue
LRANGE rq:queue:health-checks 0 -1

# Monitor real-time commands
MONITOR
```

### RQ Dashboard (Optional)

```bash
pip install rq-dashboard
rq-dashboard --redis-url redis://localhost:6379
```

Access dashboard at `http://localhost:9181`

## Error Handling

### Failed Jobs
- Automatically retry failed jobs (configurable)
- Failed jobs stored in failed job registry
- Manual retry available through RQ Dashboard

### Worker Recovery
- Workers automatically reconnect to Redis
- Graceful shutdown on SIGTERM
- Health check scheduling continues if scheduler restarts

### ElastiCache Failover
- Use Redis Cluster for automatic failover
- Configure multiple availability zones
- Application automatically reconnects

## Security Best Practices

### ElastiCache Security
- Enable encryption in transit and at rest
- Use Auth tokens for authentication
- Restrict security groups to application subnets
- Enable VPC-only access

### Network Security
```bash
# Security group rules
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --protocol tcp \
  --port 6379 \
  --source-group sg-yyyyyyyyy  # Web app security group
```

### Redis Configuration
```env
# Production settings
REDIS_SSL=true
REDIS_PASSWORD=your-strong-auth-token
REDIS_SOCKET_TIMEOUT=5
REDIS_RETRY_ON_TIMEOUT=true
```

## Troubleshooting

### Common Issues

**Connection Timeout**:
```bash
# Check security groups and network ACLs
# Verify ElastiCache cluster status
aws elasticache describe-cache-clusters --cache-cluster-id silentcanary-redis
```

**Memory Issues**:
```bash
# Monitor Redis memory usage
redis-cli -h your-cluster.cache.amazonaws.com INFO memory
```

**Worker Not Processing Jobs**:
```bash
# Check worker logs
python worker.py --verbose

# Verify queue contents
redis-cli -h your-cluster.cache.amazonaws.com LLEN rq:queue:health-checks
```

## Migration from APScheduler

The Redis version maintains the same functionality as the APScheduler version but with improved scalability:

- **Before**: Single process handles web + background jobs
- **After**: Separate processes for web, workers, and scheduler
- **Benefits**: Better fault tolerance, horizontal scaling, job persistence

All existing canaries and users are preserved during migration.