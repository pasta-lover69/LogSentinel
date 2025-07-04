from flask import Flask, render_template, request, redirect, url_for, flash
from db import init_db, get_all_logs, get_logs_count, delete_log, clear_all_logs
from parser import parse_logs
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Change this to a random secret key

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
