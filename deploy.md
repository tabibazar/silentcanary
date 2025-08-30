# SilentCanary Deployment Guide

Complete guide to deploy SilentCanary to AWS EKS in ca-central-1 region using GitHub Actions.

## 📋 Prerequisites

### Local Setup
- AWS CLI configured
- kubectl installed
- Docker installed (for local testing)
- Terraform installed

### AWS Requirements
- AWS Account with appropriate permissions
- SendGrid API key for email notifications

## 🚀 Deployment Steps

### Step 1: Clone and Prepare Repository
```bash
git clone <your-repo-url>
cd silentcanary
```

### Step 2: Set up AWS Infrastructure

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

This creates:
- EKS cluster with 2 nodes in ca-central-1
- VPC with public/private subnets
- ECR repository for container images
- IAM roles and security groups

### Step 3: Configure GitHub Secrets

Go to your GitHub repository → Settings → Secrets and add:

| Secret Name | Description | Example |
|------------|-------------|---------|
| `AWS_ACCESS_KEY_ID` | AWS Access Key | `AKIAIOSFODNN7EXAMPLE` |
| `AWS_SECRET_ACCESS_KEY` | AWS Secret Key | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| `AWS_ACCOUNT_ID` | Your AWS Account ID | `123456789012` |
| `SENDGRID_API_KEY` | SendGrid API Key | `SG.xxx` |
| `SENDGRID_DEFAULT_SENDER` | Default email sender | `alerts@yourdomain.com` |
| `FLASK_SECRET_KEY` | Flask secret key | `your-super-secret-key-here` |

### Step 4: Create DynamoDB Tables

```bash
# Users table
aws dynamodb create-table \
    --table-name SilentCanary_Users \
    --attribute-definitions \
        AttributeName=user_id,AttributeType=S \
        AttributeName=email,AttributeType=S \
        AttributeName=username,AttributeType=S \
    --key-schema \
        AttributeName=user_id,KeyType=HASH \
    --global-secondary-indexes \
        IndexName=email-index,KeySchema=[{AttributeName=email,KeyType=HASH}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5} \
        IndexName=username-index,KeySchema=[{AttributeName=username,KeyType=HASH}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5} \
    --provisioned-throughput \
        ReadCapacityUnits=5,WriteCapacityUnits=5 \
    --region ca-central-1

# Canaries table  
aws dynamodb create-table \
    --table-name SilentCanary_Canaries \
    --attribute-definitions \
        AttributeName=canary_id,AttributeType=S \
        AttributeName=user_id,AttributeType=S \
        AttributeName=token,AttributeType=S \
    --key-schema \
        AttributeName=canary_id,KeyType=HASH \
    --global-secondary-indexes \
        IndexName=user-id-index,KeySchema=[{AttributeName=user_id,KeyType=HASH}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5} \
        IndexName=token-index,KeySchema=[{AttributeName=token,KeyType=HASH}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5} \
    --provisioned-throughput \
        ReadCapacityUnits=5,WriteCapacityUnits=5 \
    --region ca-central-1
```

### Step 5: Configure kubectl

```bash
aws eks --region ca-central-1 update-kubeconfig --name silentcanary-cluster
kubectl get nodes
```

### Step 6: Deploy Application

Push your code to the main branch to trigger the GitHub Actions deployment:

```bash
git add .
git commit -m "Deploy SilentCanary to EKS"
git push origin main
```

The GitHub Actions workflow will:
1. Build Docker image
2. Push to ECR
3. Deploy to EKS
4. Run health checks

### Step 7: Verify Deployment

```bash
# Check pods
kubectl get pods -n silentcanary

# Check services
kubectl get svc -n silentcanary

# Check application logs
kubectl logs -n silentcanary deployment/silentcanary-app

# Test health endpoint
kubectl port-forward -n silentcanary svc/silentcanary-service 8080:80
curl http://localhost:8080/health
```

## 🔧 Configuration

### Environment Variables
The application uses these environment variables in production:

- `FLASK_ENV=production`
- `AWS_DEFAULT_REGION=ca-central-1`
- `SENDGRID_API_KEY` (from secret)
- `SENDGRID_DEFAULT_SENDER` (from secret)
- `SECRET_KEY` (from secret)

### Resource Limits
Each pod has:
- **Requests**: 256Mi memory, 250m CPU
- **Limits**: 512Mi memory, 500m CPU

### Auto-scaling
- **Min replicas**: 2
- **Max replicas**: 10
- **CPU threshold**: 70%
- **Memory threshold**: 80%

## 🌐 Accessing the Application

### Option 1: Load Balancer (Recommended)
Uncomment the ingress section in the GitHub Actions workflow to create an ALB:

```bash
# In .github/workflows/deploy.yml, uncomment:
kubectl apply -f k8s/ingress.yaml
```

### Option 2: Port Forward (Testing)
```bash
kubectl port-forward -n silentcanary svc/silentcanary-service 8080:80
# Access at http://localhost:8080
```

### Option 3: NodePort Service
```bash
kubectl patch svc silentcanary-service -n silentcanary -p '{"spec":{"type":"NodePort"}}'
kubectl get svc -n silentcanary
```

## 📊 Monitoring

### Application Health
- Health endpoint: `/health`
- Kubernetes probes configured for liveness, readiness, and startup

### Logs
```bash
# Application logs
kubectl logs -n silentcanary -l app=silentcanary

# Follow logs
kubectl logs -n silentcanary -l app=silentcanary -f
```

### Scaling
```bash
# Check HPA status
kubectl get hpa -n silentcanary

# Manual scaling
kubectl scale deployment silentcanary-app -n silentcanary --replicas=3
```

## 🔒 Security

### Network Security
- Private subnets for worker nodes
- Security groups with minimal required access
- NAT gateways for outbound internet access

### RBAC
- Service account with minimal required permissions
- IAM roles for DynamoDB access
- Secrets stored in Kubernetes secrets

### Container Security
- Non-root user in container
- Health checks configured
- Resource limits enforced

## 💰 Cost Optimization

### Estimated Monthly Costs (CAD)
- **EKS Control Plane**: ~$73
- **2x t3.medium nodes**: ~$76
- **NAT Gateways**: ~$75
- **DynamoDB**: ~$10 (low usage)
- **ECR**: ~$1
- **Total**: ~$235/month

### Cost Reduction Tips
1. Use Spot instances for non-production
2. Scale down during off-hours
3. Use cheaper instance types if sufficient
4. Consider DynamoDB on-demand pricing

## 🚨 Troubleshooting

### Common Issues

1. **Pod stuck in Pending**
   ```bash
   kubectl describe pod <pod-name> -n silentcanary
   # Check node capacity and resource requests
   ```

2. **ImagePullBackOff**
   ```bash
   # Check ECR permissions and image URL
   kubectl describe pod <pod-name> -n silentcanary
   ```

3. **Health check failures**
   ```bash
   kubectl logs -n silentcanary deployment/silentcanary-app
   # Check DynamoDB connectivity and SendGrid configuration
   ```

4. **GitHub Actions failing**
   - Verify all secrets are set correctly
   - Check AWS permissions
   - Review workflow logs

### Useful Commands

```bash
# Restart deployment
kubectl rollout restart deployment/silentcanary-app -n silentcanary

# Check resource usage
kubectl top pods -n silentcanary
kubectl top nodes

# Debug networking
kubectl run -it --rm debug --image=busybox --restart=Never -- /bin/sh
```

## 🔄 Updates and Maintenance

### Application Updates
Simply push to the main branch - GitHub Actions will handle:
1. Building new image
2. Pushing to ECR
3. Rolling update deployment
4. Health check verification

### Infrastructure Updates
```bash
cd terraform
terraform plan
terraform apply
```

### Backup Strategy
- DynamoDB: Enable point-in-time recovery
- Configuration: Store in git repository
- Secrets: Backup to secure location

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section
2. Review application and infrastructure logs
3. Verify all prerequisites are met
4. Check AWS service status in ca-central-1