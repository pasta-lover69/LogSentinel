#!/usr/bin/env python3

"""
Test script to verify notification system integration
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from notifications import NotificationConfig, NotificationManager
    print("✓ Notification modules imported successfully")
    
    # Test configuration creation
    config = NotificationConfig()
    print("✓ NotificationConfig created successfully")
    
    # Test notification manager
    manager = NotificationManager(config)
    print("✓ NotificationManager created successfully")
    
    # Test configuration file operations
    test_file = 'test_config.json'
    config.save_to_file(test_file)
    print("✓ Configuration saved to file")
    
    loaded_config = NotificationConfig.load_from_file(test_file)
    print("✓ Configuration loaded from file")
    
    # Cleanup test file
    if os.path.exists(test_file):
        os.remove(test_file)
        print("✓ Test cleanup completed")
    
    print("\n🎉 All notification system tests passed!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
