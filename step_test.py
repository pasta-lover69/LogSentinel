#!/usr/bin/env python3

print("Step 1: Testing basic imports...")
try:
    from flask import Flask
    print("✅ Flask import successful")
except Exception as e:
    print(f"❌ Flask import failed: {e}")
    exit(1)

print("\nStep 2: Testing notification imports...")
try:
    from notifications import NotificationConfig, NotificationManager
    print("✅ Notification imports successful")
except Exception as e:
    print(f"❌ Notification import failed: {e}")
    exit(1)

print("\nStep 3: Testing NotificationConfig creation...")
try:
    config = NotificationConfig()
    print("✅ NotificationConfig created")
except Exception as e:
    print(f"❌ NotificationConfig creation failed: {e}")
    exit(1)

print("\nStep 4: Testing NotificationManager creation...")
try:
    manager = NotificationManager(config)
    print("✅ NotificationManager created")
except Exception as e:
    print(f"❌ NotificationManager creation failed: {e}")
    exit(1)

print("\nStep 5: Testing database imports...")
try:
    from db import init_db
    print("✅ Database imports successful")
except Exception as e:
    print(f"❌ Database import failed: {e}")
    exit(1)

print("\nStep 6: Testing Flask app creation...")
try:
    app = Flask(__name__)
    app.secret_key = 'test'
    print("✅ Flask app created")
except Exception as e:
    print(f"❌ Flask app creation failed: {e}")
    exit(1)

print("\n🎉 All basic components work! The issue might be elsewhere.")
