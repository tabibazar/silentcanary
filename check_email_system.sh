#!/bin/bash
# Check email system status on production server

echo "================================"
echo "SilentCanary Email System Check"
echo "================================"
echo ""

echo "1. Checking Docker containers status..."
docker ps --filter "name=silentcanary" --format "table {{.Names}}\t{{.Status}}\t{{.State}}"

echo ""
echo "2. Checking Scheduler logs (last 50 lines)..."
echo "-------------------------------------------"
docker logs --tail 50 silentcanary-scheduler 2>&1

echo ""
echo "3. Checking Worker logs (last 50 lines)..."
echo "-------------------------------------------"
docker logs --tail 50 silentcanary-worker 2>&1

echo ""
echo "4. Checking App logs for email-related errors (last 30 lines)..."
echo "-------------------------------------------"
docker logs --tail 30 silentcanary-app 2>&1 | grep -i "email\|mail\|sendgrid\|notification" || echo "No email-related logs found"

echo ""
echo "5. Checking Redis connectivity..."
echo "-------------------------------------------"
docker exec silentcanary-worker python3 -c "from redis_config import get_redis_connection; r = get_redis_connection(); print('Redis ping:', r.ping()); print('Redis info:', r.info('server')['redis_version'])" 2>&1

echo ""
echo "6. Checking RQ Queue status..."
echo "-------------------------------------------"
docker exec silentcanary-worker python3 -c "
from redis_config import get_redis_connection
from rq import Queue, Worker
redis_conn = get_redis_connection()

# Check queues
health_queue = Queue('health-checks', connection=redis_conn)
notifications_queue = Queue('notifications', connection=redis_conn)
scheduler_queue = Queue('scheduler', connection=redis_conn)

print('Health Checks Queue:', len(health_queue.get_jobs()), 'jobs')
print('Notifications Queue:', len(notifications_queue.get_jobs()), 'jobs')
print('Scheduler Queue:', len(scheduler_queue.get_jobs()), 'jobs')

# Check workers
workers = Worker.all(connection=redis_conn)
print('Active Workers:', len(workers))
for worker in workers:
    print(f'  - {worker.name}: {worker.get_state()}')
" 2>&1

echo ""
echo "7. Testing email configuration..."
echo "-------------------------------------------"
docker exec silentcanary-app python3 -c "
from app import app
with app.app_context():
    print('MAIL_SERVER:', app.config.get('MAIL_SERVER'))
    print('MAIL_PORT:', app.config.get('MAIL_PORT'))
    print('MAIL_USE_TLS:', app.config.get('MAIL_USE_TLS'))
    print('MAIL_USERNAME:', app.config.get('MAIL_USERNAME'))
    print('MAIL_DEFAULT_SENDER:', app.config.get('MAIL_DEFAULT_SENDER'))
    import os
    sendgrid_key = os.environ.get('SENDGRID_API_KEY', '')
    print('SENDGRID_API_KEY:', 'SET' if sendgrid_key else 'NOT SET', f'({len(sendgrid_key)} chars)' if sendgrid_key else '')
" 2>&1

echo ""
echo "8. Checking for overdue canaries..."
echo "-------------------------------------------"
docker exec silentcanary-worker python3 -c "
from models import Canary
from datetime import datetime, timezone

canaries = Canary.get_active_canaries()
overdue_count = 0
for canary in canaries:
    if canary.is_overdue():
        overdue_count += 1
        print(f'OVERDUE: {canary.name} (ID: {canary.canary_id})')
        print(f'  Status: {canary.status}')
        print(f'  Last Check-in: {canary.last_checkin}')
        print(f'  Next Expected: {canary.next_expected}')
        print(f'  Alert Type: {canary.alert_type}')
        print()

if overdue_count == 0:
    print('No overdue canaries found')
else:
    print(f'Total overdue canaries: {overdue_count}')
" 2>&1

echo ""
echo "================================"
echo "Check complete"
echo "================================"
