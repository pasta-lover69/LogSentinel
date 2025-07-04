import sqlite3
from datetime import datetime

DB_NAME = "suspicious_logs.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Create table with basic structure first
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log TEXT
                )''')
    
    # Check if timestamp column exists, if not add it
    c.execute("PRAGMA table_info(logs)")
    columns = [column[1] for column in c.fetchall()]
    
    if 'timestamp' not in columns:
        c.execute('ALTER TABLE logs ADD COLUMN timestamp DATETIME')
        # Update existing rows with current timestamp
        c.execute('UPDATE logs SET timestamp = ? WHERE timestamp IS NULL', (datetime.now().isoformat(),))
    
    conn.commit()
    conn.close()

def save_suspicious_log(log_entry):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    current_time = datetime.now().isoformat()
    c.execute("INSERT INTO logs (log, timestamp) VALUES (?, ?)", (log_entry, current_time))
    conn.commit()
    conn.close()

def get_all_logs():
    """Retrieve all suspicious logs from the database"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Check if timestamp column exists
    c.execute("PRAGMA table_info(logs)")
    columns = [column[1] for column in c.fetchall()]
    
    if 'timestamp' in columns:
        c.execute("SELECT id, log, timestamp FROM logs ORDER BY timestamp DESC")
    else:
        c.execute("SELECT id, log, 'N/A' as timestamp FROM logs ORDER BY id DESC")
    
    logs = c.fetchall()
    conn.close()
    return logs

def get_logs_count():
    """Get the total count of suspicious logs"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM logs")
    count = c.fetchone()[0]
    conn.close()
    return count

def delete_log(log_id):
    """Delete a specific log entry"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM logs WHERE id = ?", (log_id,))
    conn.commit()
    conn.close()

def clear_all_logs():
    """Clear all logs from the database"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM logs")
    conn.commit()
    conn.close()
