import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=== LogSentinel Startup Diagnostic ===")
print(f"Python version: {sys.version}")
print(f"Working directory: {os.getcwd()}")

# Test 1: Basic imports
print("\n1. Testing basic imports...")
try:
    import flask
    print(f"✅ Flask {flask.__version__} imported")
except Exception as e:
    print(f"❌ Flask import failed: {e}")
    sys.exit(1)

# Test 2: Database module
print("\n2. Testing database module...")
try:
    import db
    print("✅ Database module imported")
    db.init_db()
    print("✅ Database initialized")
except Exception as e:
    print(f"❌ Database error: {e}")

# Test 3: Parser module
print("\n3. Testing parser module...")
try:
    import parser
    result = parser.is_suspicious("test log entry")
    print(f"✅ Parser module working (test result: {result})")
except Exception as e:
    print(f"❌ Parser error: {e}")

# Test 4: Notifications (detailed)
print("\n4. Testing notifications module...")
try:
    import notifications
    print("✅ Notifications module imported")
    
    config = notifications.NotificationConfig()
    print("✅ NotificationConfig created")
    
    manager = notifications.NotificationManager(config)
    print("✅ NotificationManager created")
    
except Exception as e:
    print(f"❌ Notifications error: {e}")
    import traceback
    traceback.print_exc()

# Test 5: Monitor module (without starting)
print("\n5. Testing monitor module...")
try:
    import monitor
    print("✅ Monitor module imported")
    
    status = monitor.get_monitoring_status()
    print(f"✅ Monitor status check: {status}")
    
except Exception as e:
    print(f"❌ Monitor error: {e}")
    import traceback
    traceback.print_exc()

print("\n=== Diagnostic Complete ===")
print("If all tests passed, the app should work!")
