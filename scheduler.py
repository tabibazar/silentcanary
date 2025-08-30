#!/usr/bin/env python3
"""
Redis-based scheduler for SilentCanary
Runs health checks every minute using Redis Queue
"""

import time
import signal
import sys
from datetime import datetime, timezone
from rq import Queue
from rq.job import Job
from redis_config import get_redis_connection
from worker import check_canary_health
from dotenv import load_dotenv

load_dotenv()

class CanaryScheduler:
    def __init__(self):
        self.running = False
        self.redis_conn = get_redis_connection()
        self.health_queue = Queue('health-checks', connection=self.redis_conn)
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n📡 Received signal {signum}, shutting down scheduler...")
        self.running = False
    
    def schedule_health_check(self):
        """Schedule a single health check job"""
        try:
            # Check if there's already a pending health check job
            jobs = self.health_queue.get_jobs()
            pending_jobs = [job for job in jobs if job.get_status() in ['queued', 'started']]
            
            if pending_jobs:
                print(f"⏳ Health check already queued/running (job: {pending_jobs[0].id})")
                return pending_jobs[0]
            
            # Enqueue new health check
            job = self.health_queue.enqueue(
                check_canary_health,
                job_id=f"health-check-{int(time.time())}",
                job_timeout=300,  # 5 minutes timeout
                retry=2
            )
            
            print(f"✅ Health check scheduled (job: {job.id})")
            return job
            
        except Exception as e:
            print(f"❌ Error scheduling health check: {e}")
            return None
    
    def get_queue_stats(self):
        """Get Redis queue statistics"""
        try:
            stats = {
                'health_checks': {
                    'queued': len(self.health_queue.get_jobs()),
                    'failed': len(self.health_queue.failed_job_registry),
                    'finished': len(self.health_queue.finished_job_registry)
                }
            }
            return stats
        except Exception as e:
            print(f"❌ Error getting queue stats: {e}")
            return {}
    
    def cleanup_old_jobs(self):
        """Clean up old completed and failed jobs"""
        try:
            # Clean up finished jobs older than 1 hour
            finished_registry = self.health_queue.finished_job_registry
            failed_registry = self.health_queue.failed_job_registry
            
            finished_registry.cleanup(3600)  # 1 hour
            failed_registry.cleanup(3600)    # 1 hour
            
            print("🧹 Cleaned up old jobs")
            
        except Exception as e:
            print(f"❌ Error cleaning up jobs: {e}")
    
    def run(self):
        """Main scheduler loop"""
        print("🚀 Starting SilentCanary scheduler...")
        print("⏰ Health checks will run every 60 seconds")
        
        # Test Redis connection
        try:
            self.redis_conn.ping()
            print("✅ Redis connection verified")
        except Exception as e:
            print(f"❌ Redis connection failed: {e}")
            return False
        
        self.running = True
        last_cleanup = time.time()
        
        # Schedule initial health check
        self.schedule_health_check()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Schedule health check every minute (60 seconds)
                self.schedule_health_check()
                
                # Clean up old jobs every 15 minutes
                if current_time - last_cleanup > 900:  # 15 minutes
                    self.cleanup_old_jobs()
                    last_cleanup = current_time
                
                # Show stats every 5 minutes
                if int(current_time) % 300 == 0:  # Every 5 minutes
                    stats = self.get_queue_stats()
                    print(f"📊 Queue stats: {stats}")
                
                # Wait 60 seconds before next cycle
                for i in range(60):
                    if not self.running:
                        break
                    time.sleep(1)
                
            except KeyboardInterrupt:
                print("\n⚠️ Interrupted by user")
                break
            except Exception as e:
                print(f"❌ Scheduler error: {e}")
                time.sleep(5)  # Wait 5 seconds before retrying
        
        print("🛑 Scheduler stopped")
        return True

def main():
    """Main entry point"""
    scheduler = CanaryScheduler()
    
    try:
        success = scheduler.run()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Fatal scheduler error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()