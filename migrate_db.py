"""
Database migration script to add timestamp column to existing logs table
"""
import sqlite3
from datetime import datetime

DB_NAME = "suspicious_logs.db"

def migrate_database():
    """Add timestamp column to existing logs table"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Check if timestamp column exists
    c.execute("PRAGMA table_info(logs)")
    columns = [column[1] for column in c.fetchall()]
    
    if 'timestamp' not in columns:
        print("Adding timestamp column to logs table...")
        
        # Add column without default value first
        c.execute('ALTER TABLE logs ADD COLUMN timestamp DATETIME')
        
        # Update existing rows with current timestamp
        current_time = datetime.now().isoformat()
        c.execute('UPDATE logs SET timestamp = ?', (current_time,))
        
        conn.commit()
        print("Migration completed successfully!")
    else:
        print("Timestamp column already exists. No migration needed.")
    
    conn.close()

if __name__ == "__main__":
    migrate_database()
