"""
Real-time log monitoring with file watchers
Automatically detects and processes new suspicious log entries as they're written to files
"""

import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from parser import is_suspicious
from db import save_suspicious_log
import threading
import sys

class LogEventHandler(FileSystemEventHandler):
    """Handler for file system events on log files"""
    
    def __init__(self, callback=None):
        super().__init__()
        self.callback = callback
        self.file_positions = {}  # Track file positions to avoid re-reading
        
    def on_modified(self, event):
        """Called when a file is modified"""
        if event.is_directory:
            return
            
        # Only monitor .log files
        if not event.src_path.endswith('.log'):
            return
            
        self.process_file_changes(event.src_path)
    
    def on_created(self, event):
        """Called when a new file is created"""
        if event.is_directory:
            return
            
        if event.src_path.endswith('.log'):
            print(f"[WATCHER] New log file detected: {event.src_path}")
            self.process_file_changes(event.src_path)
    
    def process_file_changes(self, file_path):
        """Process new lines added to a log file"""
        try:
            if not os.path.exists(file_path):
                return
                
            # Get current file size
            current_size = os.path.getsize(file_path)
            
            # Get the last known position for this file
            last_position = self.file_positions.get(file_path, 0)
            
            # If file is smaller than last position, it might have been rotated
            if current_size < last_position:
                last_position = 0
                
            # Read only new content
            if current_size > last_position:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    
                # Update position
                self.file_positions[file_path] = f.tell()
                
                # Process each new line
                for line in new_lines:
                    line = line.strip()
                    if line and is_suspicious(line):
                        print(f"[REAL-TIME] Suspicious activity detected: {line}")
                        save_suspicious_log(line)
                        
                        # Call callback if provided (for web notifications)
                        if self.callback:
                            try:
                                self.callback(line)
                            except Exception as e:
                                print(f"[ERROR] Callback error: {e}")
                            
        except Exception as e:
            print(f"[ERROR] Error processing {file_path}: {e}")

class LogMonitor:
    """Real-time log monitoring manager"""
    
    def __init__(self, watch_directory="logs", callback=None):
        self.watch_directory = os.path.abspath(watch_directory)
        self.observer = None
        self.event_handler = LogEventHandler(callback)
        self.is_monitoring = False
        
        # Initialize file positions for existing files
        self._initialize_file_positions()
    
    def _initialize_file_positions(self):
        """Initialize file positions for existing log files"""
        if not os.path.exists(self.watch_directory):
            os.makedirs(self.watch_directory)
            return
            
        for filename in os.listdir(self.watch_directory):
            if filename.endswith('.log'):
                file_path = os.path.join(self.watch_directory, filename)
                try:
                    # Set position to end of file to avoid re-processing existing content
                    file_size = os.path.getsize(file_path)
                    self.event_handler.file_positions[file_path] = file_size
                    print(f"[INIT] Monitoring {file_path} from position {file_size}")
                except Exception as e:
                    print(f"[ERROR] Error initializing {file_path}: {e}")
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.is_monitoring:
            print("[WATCHER] Already monitoring")
            return
            
        try:
            # Create new observer for each start to avoid threading issues
            self.observer = Observer()
            self.observer.schedule(self.event_handler, self.watch_directory, recursive=False)
            self.observer.start()
            self.is_monitoring = True
            print(f"[WATCHER] Started monitoring directory: {self.watch_directory}")
            print("[WATCHER] Watching for new suspicious log entries...")
            
        except Exception as e:
            print(f"[ERROR] Failed to start monitoring: {e}")
            self.is_monitoring = False
            if self.observer:
                try:
                    self.observer.stop()
                except:
                    pass
                self.observer = None
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        if not self.is_monitoring:
            return
            
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join(timeout=2)  # Add timeout to prevent hanging
            self.is_monitoring = False
            self.observer = None
            print("[WATCHER] Stopped monitoring")
            
        except Exception as e:
            print(f"[ERROR] Error stopping monitoring: {e}")
            self.is_monitoring = False
            self.observer = None
    
    def get_status(self):
        """Get monitoring status"""
        return {
            'is_monitoring': self.is_monitoring,
            'watch_directory': self.watch_directory,
            'monitored_files': len(self.event_handler.file_positions),
            'file_positions': dict(self.event_handler.file_positions)
        }

# Global monitor instance
_monitor = None

def get_monitor():
    """Get the global monitor instance"""
    global _monitor
    if _monitor is None:
        _monitor = LogMonitor()
    return _monitor

def start_monitoring(callback=None):
    """Start monitoring with optional callback for real-time notifications"""
    monitor = get_monitor()
    if callback:
        monitor.event_handler.callback = callback
    monitor.start_monitoring()
    return monitor

def stop_monitoring():
    """Stop monitoring"""
    monitor = get_monitor()
    monitor.stop_monitoring()

def is_monitoring():
    """Check if monitoring is active"""
    monitor = get_monitor()
    return monitor.is_monitoring

def get_monitoring_status():
    """Get detailed monitoring status"""
    monitor = get_monitor()
    return monitor.get_status()

# CLI interface for testing
if __name__ == "__main__":
    def notification_callback(log_entry):
        print(f"🚨 ALERT: {log_entry}")
    
    monitor = LogMonitor(callback=notification_callback)
    
    try:
        monitor.start_monitoring()
        print("Press Ctrl+C to stop monitoring...")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[WATCHER] Shutting down...")
        monitor.stop_monitoring()
        print("[WATCHER] Monitoring stopped")
