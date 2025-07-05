#!/usr/bin/env python3
"""
Test script for real-time monitoring
This script simulates adding suspicious log entries to test the monitoring functionality
"""

import time
import os
from datetime import datetime

def simulate_log_entries():
    """Simulate new suspicious log entries being written to a log file"""
    
    test_log_file = "logs/test_realtime.log"
    
    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    # Sample suspicious log entries to simulate
    suspicious_entries = [
        "Jun 18 01:22:13 myhost sshd[1993]: Failed password for invalid user admin from 192.168.0.101 port 53742 ssh2",
        "Jun 18 01:22:15 myhost sshd[1994]: Failed password for root from 192.168.0.102 port 53743 ssh2", 
        "Jun 18 01:22:17 myhost sshd[1995]: Invalid user test from 192.168.0.103",
        "Jun 18 01:22:19 myhost sshd[1996]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.0.104",
        "Jun 18 01:22:21 myhost sshd[1997]: Failed password for invalid user guest from 192.168.0.105 port 53744 ssh2"
    ]
    
    print(f"[TEST] Starting real-time monitoring simulation...")
    print(f"[TEST] Writing to: {os.path.abspath(test_log_file)}")
    print(f"[TEST] Make sure real-time monitoring is enabled in the web dashboard!")
    print("[TEST] You should see these entries appear in real-time...")
    print()
    
    with open(test_log_file, "w") as f:
        f.write("# Test log file for real-time monitoring\n")
        f.write(f"# Started at {datetime.now()}\n")
        f.flush()
        
        for i, entry in enumerate(suspicious_entries, 1):
            print(f"[TEST] Adding suspicious entry {i}/5...")
            
            # Add timestamp to make it current
            current_time = datetime.now().strftime("%b %d %H:%M:%S")
            timestamped_entry = entry.replace("Jun 18 01:22:", current_time[:12])
            
            f.write(f"{timestamped_entry}\n")
            f.flush()  # Force write to disk
            
            print(f"[TEST] Added: {timestamped_entry}")
            
            # Wait between entries to simulate real-time activity
            time.sleep(3)
    
    print()
    print("[TEST] Simulation complete!")
    print("[TEST] Check the web dashboard for real-time alerts!")
    print(f"[TEST] Test file created: {test_log_file}")

if __name__ == "__main__":
    try:
        simulate_log_entries()
    except KeyboardInterrupt:
        print("\n[TEST] Simulation stopped by user")
    except Exception as e:
        print(f"[ERROR] Simulation failed: {e}")
