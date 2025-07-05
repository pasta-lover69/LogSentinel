from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from db import init_db, get_all_logs, get_logs_count, delete_log, clear_all_logs
from parser import parse_logs
from monitor import start_monitoring, stop_monitoring, is_monitoring, get_monitoring_status
from datetime import datetime
import os
import atexit

app = Flask(__name__)
app.secret_key = 'LogSentByJeb'

# Real-time notifications storage
recent_alerts = []
MAX_RECENT_ALERTS = 50

def monitoring_callback(log_entry):
    """Callback function for real-time monitoring alerts"""
    global recent_alerts
    alert = {
        'timestamp': datetime.now().isoformat(),
        'log_entry': log_entry,
        'formatted_time': 'Just now'
    }
    recent_alerts.insert(0, alert)  # Add to beginning
    # Keep only recent alerts
    if len(recent_alerts) > MAX_RECENT_ALERTS:
        recent_alerts = recent_alerts[:MAX_RECENT_ALERTS]

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
    monitoring_status = get_monitoring_status()
    return render_template('dashboard.html', 
                         logs=logs, 
                         total_count=total_count,
                         monitoring_status=monitoring_status,
                         recent_alerts=recent_alerts[:10])  # Show last 10 alerts

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

@app.route('/monitoring/start')
def start_monitoring_route():
    """Start real-time monitoring"""
    try:
        if not is_monitoring():
            start_monitoring(callback=monitoring_callback)
            flash('Real-time monitoring started successfully!', 'success')
        else:
            flash('Real-time monitoring is already active.', 'info')
    except Exception as e:
        flash(f'Error starting monitoring: {str(e)}', 'error')
    return redirect(url_for('dashboard'))

@app.route('/monitoring/stop')
def stop_monitoring_route():
    """Stop real-time monitoring"""
    try:
        if is_monitoring():
            stop_monitoring()
            flash('Real-time monitoring stopped.', 'info')
        else:
            flash('Real-time monitoring is not active.', 'info')
    except Exception as e:
        flash(f'Error stopping monitoring: {str(e)}', 'error')
    return redirect(url_for('dashboard'))

@app.route('/monitoring/status')
def monitoring_status():
    """Get monitoring status as JSON"""
    status = get_monitoring_status()
    status['recent_alerts_count'] = len(recent_alerts)
    return jsonify(status)

@app.route('/api/alerts')
def get_recent_alerts():
    """Get recent alerts as JSON for AJAX updates"""
    return jsonify({
        'alerts': recent_alerts[:10],
        'total_count': len(recent_alerts),
        'monitoring_active': is_monitoring()
    })

@app.route('/clear_alerts', methods=['POST'])
def clear_recent_alerts():
    """Clear recent alerts"""
    global recent_alerts
    recent_alerts = []
    flash('Recent alerts cleared!', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    
    # Only start monitoring if not in Flask reloader mode
    import os
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        # This is the main process, not the reloader
        try:
            start_monitoring(callback=monitoring_callback)
            print("[APP] Real-time monitoring started automatically")
        except Exception as e:
            print(f"[APP] Could not start monitoring: {e}")
        
        # Cleanup monitoring on app shutdown
        def cleanup():
            try:
                stop_monitoring()
                print("[APP] Monitoring stopped on shutdown")
            except:
                pass
        
        atexit.register(cleanup)
    
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)
