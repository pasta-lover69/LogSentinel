import sys
import traceback

try:
    print("Testing app startup...")
    import app
    print("App imported successfully!")
    
    # Try to access the app object
    if hasattr(app, 'app'):
        print("Flask app object found!")
        
    # Try to create notification manager
    print("Testing notification manager...")
    from notifications import NotificationConfig, NotificationManager
    config = NotificationConfig()
    manager = NotificationManager(config)
    print("Notification manager created successfully!")
    
    print("✅ All tests passed!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    traceback.print_exc()
    sys.exit(1)
