"""
Redis configuration for SilentCanary
Supports both local Redis and AWS ElastiCache
"""

import redis
import os
from dotenv import load_dotenv

load_dotenv()

def get_redis_connection():
    """Get Redis connection - local or AWS ElastiCache based on environment"""
    
    # Check for AWS ElastiCache configuration
    redis_endpoint = os.getenv('REDIS_ENDPOINT')  # e.g., 'my-cluster.abc123.cache.amazonaws.com'
    redis_port = int(os.getenv('REDIS_PORT', '6379'))
    redis_password = os.getenv('REDIS_PASSWORD')  # Optional for ElastiCache Auth
    
    if redis_endpoint:
        # AWS ElastiCache connection
        print(f"🔗 Connecting to AWS ElastiCache: {redis_endpoint}:{redis_port}")
        
        connection_kwargs = {
            'host': redis_endpoint,
            'port': redis_port,
            'decode_responses': True,
            'socket_connect_timeout': 5,
            'socket_timeout': 5,
            'retry_on_timeout': True,
            'health_check_interval': 30
        }
        
        # Add password if provided (for AUTH-enabled clusters)
        if redis_password:
            connection_kwargs['password'] = redis_password
        
        # For SSL/TLS connection (recommended for production)
        if os.getenv('REDIS_SSL', 'false').lower() == 'true':
            connection_kwargs['ssl'] = True
            connection_kwargs['ssl_cert_reqs'] = None
        
        return redis.Redis(**connection_kwargs)
    
    else:
        # Local Redis connection (for development)
        redis_host = os.getenv('REDIS_HOST', 'localhost')
        redis_port = int(os.getenv('REDIS_PORT', '6379'))
        redis_db = int(os.getenv('REDIS_DB', '0'))
        
        print(f"🔗 Connecting to local Redis: {redis_host}:{redis_port}")
        
        return redis.Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True
        )

def test_redis_connection():
    """Test Redis connection and return status"""
    try:
        r = get_redis_connection()
        # Test with ping
        r.ping()
        print("✅ Redis connection successful")
        
        # Test basic operations
        r.set('test_key', 'test_value', ex=60)  # Expires in 60 seconds
        value = r.get('test_key')
        
        if value == 'test_value':
            print("✅ Redis read/write test successful")
            r.delete('test_key')
            return True
        else:
            print("❌ Redis read/write test failed")
            return False
            
    except redis.ConnectionError as e:
        print(f"❌ Redis connection failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Redis test failed: {e}")
        return False

if __name__ == '__main__':
    test_redis_connection()