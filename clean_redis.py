#!/usr/bin/env python3
"""
Clean corrupted Redis data that's preventing scheduler from working
"""

from redis_config import get_redis_connection
from rq import Queue
from dotenv import load_dotenv

load_dotenv()

def clean_redis():
    """Clean all RQ queues and registries"""
    print("🧹 Cleaning Redis queues...")

    try:
        redis_conn = get_redis_connection()

        # Test connection
        redis_conn.ping()
        print("✅ Connected to Redis")

        # Get all RQ queues
        queue_names = ['health-checks', 'notifications', 'scheduler']

        for queue_name in queue_names:
            print(f"\n📋 Cleaning queue: {queue_name}")
            queue = Queue(queue_name, connection=redis_conn)

            # Empty the queue
            queue.empty()
            print(f"   ✅ Emptied queue")

            # Clean registries
            queue.started_job_registry.cleanup()
            queue.finished_job_registry.cleanup()
            queue.failed_job_registry.cleanup()
            queue.deferred_job_registry.cleanup()
            queue.scheduled_job_registry.cleanup()
            queue.canceled_job_registry.cleanup()

            print(f"   ✅ Cleaned all registries")

        # Clean alert cooldown keys (these might have corrupted data)
        print(f"\n🧹 Cleaning alert cooldown keys...")
        alert_keys = redis_conn.keys("last_alert:*")
        if alert_keys:
            redis_conn.delete(*alert_keys)
            print(f"   ✅ Deleted {len(alert_keys)} alert cooldown keys")
        else:
            print(f"   ℹ️  No alert cooldown keys found")

        print("\n✅ Redis cleaning complete!")
        print("\nNext steps:")
        print("1. Restart scheduler: docker-compose restart scheduler")
        print("2. Restart worker: docker-compose restart worker")
        print("3. Monitor logs: docker logs -f silentcanary-scheduler")

        return True

    except Exception as e:
        print(f"❌ Error cleaning Redis: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = clean_redis()
    exit(0 if success else 1)
