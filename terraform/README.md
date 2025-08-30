# SilentCanary EKS Infrastructure

This Terraform configuration creates an EKS cluster in `ca-central-1` (Canada Central) region with 2 worker nodes.

## Prerequisites

1. **AWS CLI configured** with appropriate credentials
2. **Terraform installed** (>= 1.0)
3. **kubectl installed** 

## Quick Start

### 1. Initialize Terraform
```bash
cd terraform
terraform init
```

### 2. Plan the deployment
```bash
terraform plan
```

### 3. Deploy the infrastructure
```bash
terraform apply
```

### 4. Configure kubectl
```bash
aws eks --region ca-central-1 update-kubeconfig --name silentcanary-cluster
```

### 5. Verify the cluster
```bash
kubectl get nodes
kubectl get pods --all-namespaces
```

## What gets created

- **VPC** with public/private subnets across 2 AZs
- **EKS Cluster** (v1.28) with managed node group
- **2 Worker Nodes** (t3.medium instances)
- **ECR Repository** for container images
- **IAM Roles** with necessary policies
- **Security Groups** for cluster communication
- **NAT Gateways** for private subnet internet access

## Configuration

### Variables
You can customize the deployment by creating a `terraform.tfvars` file:

```hcl
aws_region = "ca-central-1"
environment = "production"
cluster_version = "1.28"
node_instance_types = ["t3.medium"]
node_desired_capacity = 2
node_max_capacity = 4
node_min_capacity = 2
```

### Resource Costs (Approximate CAD pricing)
- **EKS Control Plane**: ~$0.10/hour (~$73/month)
- **2x t3.medium nodes**: ~$0.0526/hour each (~$76/month total)
- **NAT Gateways**: ~$0.052/hour each (~$75/month total)
- **Total**: ~$224/month CAD

## Post-Deployment Steps

### 1. Create DynamoDB Tables
```bash
# You'll need to create the DynamoDB tables separately
aws dynamodb create-table \
    --table-name SilentCanary_Users \
    --region ca-central-1 \
    # ... (add your DynamoDB table definitions)
```

### 2. Set up GitHub Secrets
Add these secrets to your GitHub repository:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_ACCOUNT_ID`
- `SENDGRID_API_KEY`
- `SENDGRID_DEFAULT_SENDER`
- `FLASK_SECRET_KEY`

### 3. Deploy the application
```bash
kubectl apply -f ../k8s/
```

## Cleanup

To destroy all resources:
```bash
terraform destroy
```

**⚠️ Warning**: This will permanently delete all resources and data!

## Monitoring and Maintenance

- **Cluster logs** are sent to CloudWatch
- **Node scaling** is configured with HPA
- **ECR lifecycle policies** automatically clean up old images
- **Security group rules** allow necessary traffic only

## Troubleshooting

### Common Issues
1. **Insufficient IAM permissions** - Ensure your AWS credentials have EKS admin access
2. **VPC limits** - Check your account's VPC and subnet limits
3. **Instance limits** - Verify t3.medium instance limits in ca-central-1

### Useful Commands
```bash
# Check cluster status
aws eks describe-cluster --name silentcanary-cluster --region ca-central-1

# View node group
aws eks describe-nodegroup --cluster-name silentcanary-cluster --nodegroup-name silentcanary-cluster-workers --region ca-central-1

# Get cluster info
kubectl cluster-info
kubectl get nodes -o wide
```