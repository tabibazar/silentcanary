#!/bin/bash

# SilentCanary CI/CD Integration Example
# This script demonstrates how to integrate SilentCanary with your CI/CD pipeline

set -e

# Configuration
SILENTCANARY_URL="${SILENTCANARY_URL:-https://silentcanary.com}"
SERVICE_NAME="${SERVICE_NAME:-my-service}"
ENVIRONMENT="${ENVIRONMENT:-production}"
DEPLOYMENT_ID="${DEPLOYMENT_ID:-$(date +%s)}"
TEMPLATE="${TEMPLATE:-default}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
log() {
    echo -e "${BLUE}[SilentCanary]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check required environment variables
check_requirements() {
    log "Checking requirements..."
    
    if [ -z "$SILENTCANARY_API_KEY" ]; then
        error "SILENTCANARY_API_KEY environment variable is required"
        echo ""
        echo "To generate your API key:"
        echo "1. Find your user_id from SilentCanary dashboard"
        echo "2. Run: python generate_api_key.py <your_user_id>"
        echo "3. Set SILENTCANARY_API_KEY in your CI/CD environment"
        exit 1
    fi
    
    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        error "curl is required but not installed"
        exit 1
    fi
    
    # Check if jq is available (optional but recommended)
    if ! command -v jq &> /dev/null; then
        warn "jq not found - install for better JSON formatting"
    fi
    
    success "Requirements check passed"
}

# Create or update canary via webhook
create_canary() {
    log "Creating/updating canary for $SERVICE_NAME in $ENVIRONMENT..."
    
    # Prepare JSON payload
    PAYLOAD=$(cat <<EOF
{
  "service_name": "$SERVICE_NAME",
  "environment": "$ENVIRONMENT",
  "deployment_id": "$DEPLOYMENT_ID",
  "commit_sha": "${GIT_COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo 'unknown')}",
  "branch": "${GIT_BRANCH:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')}",
  "pipeline_url": "${BUILD_URL:-}",
  "template": "$TEMPLATE",
  "interval_minutes": ${INTERVAL_MINUTES:-30},
  "alert_type": "${ALERT_TYPE:-both}",
  "email": "${ALERT_EMAIL:-}",
  "slack_webhook": "${SLACK_WEBHOOK:-}",
  "enable_smart_alerts": ${ENABLE_SMART_ALERTS:-true}
}
EOF
    )
    
    log "Sending webhook request..."
    
    # Make the API call
    if command -v jq &> /dev/null; then
        RESPONSE=$(curl -s -w "\n%{http_code}" \
            -X POST "$SILENTCANARY_URL/api/v1/deployment/webhook" \
            -H "X-API-Key: $SILENTCANARY_API_KEY" \
            -H "Content-Type: application/json" \
            -d "$PAYLOAD")
        
        HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
        BODY=$(echo "$RESPONSE" | sed '$d')
        
        if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 201 ]; then
            success "Canary webhook successful (HTTP $HTTP_CODE)"
            
            # Parse response
            STATUS=$(echo "$BODY" | jq -r '.status // "unknown"')
            CANARY_ID=$(echo "$BODY" | jq -r '.canary_id // "unknown"')
            MESSAGE=$(echo "$BODY" | jq -r '.message // "No message"')
            CANARY_URL=$(echo "$BODY" | jq -r '.canary_url // ""')
            CHECKIN_URL=$(echo "$BODY" | jq -r '.check_in_url // ""')
            
            echo ""
            echo "📊 Canary Details:"
            echo "   Status: $STATUS"
            echo "   ID: $CANARY_ID"
            echo "   Message: $MESSAGE"
            
            if [ "$CANARY_URL" != "null" ] && [ "$CANARY_URL" != "" ]; then
                echo "   Dashboard: $CANARY_URL"
            fi
            
            if [ "$CHECKIN_URL" != "null" ] && [ "$CHECKIN_URL" != "" ]; then
                echo "   Check-in URL: $CHECKIN_URL"
                echo ""
                warn "Save the check-in URL for your application to use!"
                echo "   Add this to your app's environment:"
                echo "   SILENTCANARY_TOKEN=$(basename $CHECKIN_URL)"
            fi
            
        else
            error "Webhook failed (HTTP $HTTP_CODE)"
            echo "Response: $BODY" | jq '.' 2>/dev/null || echo "$BODY"
            exit 1
        fi
    else
        # Fallback without jq
        curl -X POST "$SILENTCANARY_URL/api/v1/deployment/webhook" \
            -H "X-API-Key: $SILENTCANARY_API_KEY" \
            -H "Content-Type: application/json" \
            -d "$PAYLOAD" \
            -w "\nHTTP Status: %{http_code}\n" \
            || (error "Webhook request failed" && exit 1)
    fi
}

# Test check-in (if canary was created)
test_checkin() {
    if [ -n "$CHECKIN_URL" ] && [ "$CHECKIN_URL" != "null" ]; then
        log "Testing check-in..."
        
        TEST_RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null \
            "$CHECKIN_URL?message=CI/CD+test+check-in")
        
        if [ "$TEST_RESPONSE" -eq 200 ]; then
            success "Test check-in successful"
        else
            warn "Test check-in failed (HTTP $TEST_RESPONSE)"
        fi
    fi
}

# Main execution
main() {
    echo ""
    log "SilentCanary CI/CD Integration"
    echo "Service: $SERVICE_NAME"
    echo "Environment: $ENVIRONMENT"
    echo "Deployment ID: $DEPLOYMENT_ID"
    echo "Template: $TEMPLATE"
    echo ""
    
    check_requirements
    create_canary
    test_checkin
    
    echo ""
    success "SilentCanary integration complete!"
    
    if [ -n "$CHECKIN_URL" ] && [ "$CHECKIN_URL" != "null" ]; then
        echo ""
        echo "🚀 Next Steps:"
        echo "1. Add regular check-ins to your application code"
        echo "2. Monitor the canary dashboard for health status"
        echo "3. Configure alert settings if needed"
        echo ""
        echo "📖 For integration examples, visit:"
        echo "   $SILENTCANARY_URL/help/cicd-integration"
    fi
}

# Handle help flag
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "SilentCanary CI/CD Integration Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Environment Variables:"
    echo "  SILENTCANARY_API_KEY    Required API key for authentication"
    echo "  SERVICE_NAME           Service name (default: my-service)"
    echo "  ENVIRONMENT           Environment name (default: production)"
    echo "  DEPLOYMENT_ID         Deployment ID (default: timestamp)"
    echo "  TEMPLATE              Canary template (default: default)"
    echo "  INTERVAL_MINUTES      Check-in interval (default: 30)"
    echo "  ALERT_TYPE            Alert type: email, slack, both (default: both)"
    echo "  ALERT_EMAIL           Alert email address"
    echo "  SLACK_WEBHOOK         Slack webhook URL"
    echo "  ENABLE_SMART_ALERTS   Enable smart alerts (default: true)"
    echo ""
    echo "Examples:"
    echo "  # Basic usage"
    echo "  export SILENTCANARY_API_KEY='your-api-key'"
    echo "  export SERVICE_NAME='my-api'"
    echo "  export ENVIRONMENT='production'"
    echo "  $0"
    echo ""
    echo "  # With custom settings"
    echo "  export TEMPLATE='microservice'"
    echo "  export INTERVAL_MINUTES=15"
    echo "  export ALERT_TYPE='slack'"
    echo "  $0"
    exit 0
fi

# Run main function
main "$@"