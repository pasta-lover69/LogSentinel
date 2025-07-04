import sqlite3

DB_NAME = "suspicious_logs.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

def save_suspicious_log(log_entry):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO logs (log) VALUES (?)", (log_entry,))
    conn.commit()
    conn.close()

def get_all_logs():
    """Retrieve all suspicious logs from the database"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, log, timestamp FROM logs ORDER BY timestamp DESC")
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
