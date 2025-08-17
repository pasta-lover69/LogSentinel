import sqlite3
import os
from datetime import datetime

DATABASE = 'security_logs.db'

def init_db():
    """Initialize the security logs database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create the main logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            log_entry TEXT NOT NULL,
            threat_type TEXT,
            severity TEXT DEFAULT 'medium',
            source_file TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create index for better performance
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_severity ON logs(severity)
    ''')
    
    conn.commit()
    conn.close()
    print(f"[DB] Database initialized: {DATABASE}")

def save_suspicious_log(log_entry, threat_type="unknown", severity="medium", source_file=None):
    """Save a suspicious log entry to the database"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO logs (timestamp, log_entry, threat_type, severity, source_file)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, log_entry, threat_type, severity, source_file))
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        print(f"[DB] Error saving log: {e}")
        return False

def get_all_logs(limit=100):
    """Get all logs from database (with limit for performance)"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, log_entry, threat_type, severity, source_file, created_at
            FROM logs 
            ORDER BY id DESC 
            LIMIT ?
        ''', (limit,))
        
        columns = [description[0] for description in cursor.description]
        logs = []
        
        for row in cursor.fetchall():
            log_dict = dict(zip(columns, row))
            logs.append(log_dict)
        
        conn.close()
        return logs
        
    except Exception as e:
        print(f"[DB] Error getting logs: {e}")
        return []

def get_logs_count():
    """Get total number of logs in database"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM logs')
        count = cursor.fetchone()[0]
        
        conn.close()
        return count
        
    except Exception as e:
        print(f"[DB] Error getting log count: {e}")
        return 0

def delete_log(log_id):
    """Delete a specific log entry by ID"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM logs WHERE id = ?', (log_id,))
        rows_affected = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return rows_affected > 0
        
    except Exception as e:
        print(f"[DB] Error deleting log {log_id}: {e}")
        return False

def clear_all_logs():
    """Clear all logs from the database"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM logs')
        rows_affected = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        print(f"[DB] Cleared {rows_affected} logs from database")
        return True
        
    except Exception as e:
        print(f"[DB] Error clearing logs: {e}")
        return False

def get_logs_by_severity(severity):
    """Get logs filtered by severity level"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, log_entry, threat_type, severity, source_file
            FROM logs 
            WHERE severity = ?
            ORDER BY id DESC
        ''', (severity,))
        
        columns = [description[0] for description in cursor.description]
        logs = []
        
        for row in cursor.fetchall():
            log_dict = dict(zip(columns, row))
            logs.append(log_dict)
        
        conn.close()
        return logs
        
    except Exception as e:
        print(f"[DB] Error getting logs by severity: {e}")
        return []

def get_logs_by_date_range(start_date, end_date):
    """Get logs within a specific date range"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, log_entry, threat_type, severity, source_file
            FROM logs 
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY id DESC
        ''', (start_date, end_date))
        
        columns = [description[0] for description in cursor.description]
        logs = []
        
        for row in cursor.fetchall():
            log_dict = dict(zip(columns, row))
            logs.append(log_dict)
        
        conn.close()
        return logs
        
    except Exception as e:
        print(f"[DB] Error getting logs by date range: {e}")
        return []

def get_database_info():
    """Get database statistics and information"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get total count
        cursor.execute('SELECT COUNT(*) FROM logs')
        total_logs = cursor.fetchone()[0]
        
        # Get count by severity
        cursor.execute('''
            SELECT severity, COUNT(*) 
            FROM logs 
            GROUP BY severity
        ''')
        severity_counts = dict(cursor.fetchall())
        
        # Get latest log timestamp
        cursor.execute('SELECT MAX(timestamp) FROM logs')
        latest_log = cursor.fetchone()[0]
        
        # Get database file size
        db_size = os.path.getsize(DATABASE) if os.path.exists(DATABASE) else 0
        
        conn.close()
        
        return {
            'total_logs': total_logs,
            'severity_counts': severity_counts,
            'latest_log': latest_log,
            'database_size': db_size,
            'database_file': DATABASE
        }
        
    except Exception as e:
        print(f"[DB] Error getting database info: {e}")
        return {}

# Initialize database when module is imported
if __name__ == "__main__":
    init_db()
    print("[DB] Database module loaded successfully")