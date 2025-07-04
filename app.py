from flask import Flask, render_template, request, redirect, url_for, flash
from db import init_db, get_all_logs, get_logs_count, delete_log, clear_all_logs
from parser import parse_logs
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Change this to a random secret key

def format_timestamp(timestamp_str):
    """Format timestamp to a more readable format"""
    if not timestamp_str or timestamp_str == 'N/A':
        return 'Unknown'
    
    try:
        # Parse the ISO format timestamp
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        
        # Format as readable string
        now = datetime.now()
        diff = now - dt
        
        if diff.days == 0:
            if diff.seconds < 60:
                return "Just now"
            elif diff.seconds < 3600:
                minutes = diff.seconds // 60
                return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
            else:
                hours = diff.seconds // 3600
                return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.days == 1:
            return "Yesterday"
        elif diff.days < 7:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        else:
            return dt.strftime("%B %d, %Y at %I:%M %p")
            
    except (ValueError, AttributeError):
        return timestamp_str

def format_date_only(timestamp_str):
    """Format timestamp to show only date in readable format"""
    if not timestamp_str or timestamp_str == 'N/A':
        return 'Never'
    
    try:
        # Parse the ISO format timestamp
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        
        # Format as readable date
        now = datetime.now()
        diff = now - dt
        
        if diff.days == 0:
            return "Today"
        elif diff.days == 1:
            return "Yesterday"
        elif diff.days < 7:
            return f"{diff.days} days ago"
        else:
            return dt.strftime("%b %d, %Y")
            
    except (ValueError, AttributeError):
        return 'Unknown'

# Make functions available in templates
app.jinja_env.globals.update(format_timestamp=format_timestamp)
app.jinja_env.globals.update(format_date_only=format_date_only)

@app.route('/')
def dashboard():
    """Main dashboard route"""
    logs = get_all_logs()
    total_count = get_logs_count()
    return render_template('dashboard.html', logs=logs, total_count=total_count)

@app.route('/scan')
def scan_logs():
    """Scan logs and detect suspicious activities"""
    from main import main as scan_main
    try:
        scan_main()
        flash('Log scan completed successfully!', 'success')
    except Exception as e:
        flash(f'Error during scan: {str(e)}', 'error')
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:log_id>')
def delete_log_entry(log_id):
    """Delete a specific log entry"""
    try:
        delete_log(log_id)
        flash('Log entry deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting log: {str(e)}', 'error')
    return redirect(url_for('dashboard'))

@app.route('/clear_all', methods=['POST'])
def clear_all():
    """Clear all logs"""
    try:
        clear_all_logs()
        flash('All logs cleared successfully!', 'success')
    except Exception as e:
        flash(f'Error clearing logs: {str(e)}', 'error')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='127.0.0.1', port=5000)
