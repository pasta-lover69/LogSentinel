from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from db import init_db, get_all_logs, get_logs_count, delete_log, clear_all_logs, save_suspicious_log
from parser import parse_logs, is_suspicious
from monitor import start_monitoring, stop_monitoring, is_monitoring, get_monitoring_status
from notifications import NotificationConfig, NotificationManager
from datetime import datetime
import os
import atexit
import json

app = Flask(__name__)
app.secret_key = 'LogSentByJeb'

# Upload configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'log', 'txt', 'out'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Notification configuration file
CONFIG_FILE = 'notification_config.json'

# Initialize notification system
try:
    notification_config = NotificationConfig.load_from_file(CONFIG_FILE)
except FileNotFoundError:
    # Create default configuration if file doesn't exist
    notification_config = NotificationConfig()
    notification_config.save_to_file(CONFIG_FILE)

notification_manager = NotificationManager(notification_config)

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
    
    # Send notifications for this alert
    try:
        notification_manager.send_security_alert(log_entry)
    except Exception as e:
        print(f"[NOTIFICATION] Error sending alert: {e}")

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

@app.route('/settings')
def settings():
    """Notification settings page"""
    return render_template('settings.html', config=notification_config)

@app.route('/update_email_settings', methods=['POST'])
def update_email_settings():
    """Update email notification settings"""
    try:
        # Update email configuration
        notification_config.email.smtp_server = request.form.get('smtp_server', '')
        notification_config.email.smtp_port = int(request.form.get('smtp_port', 587))
        notification_config.email.username = request.form.get('username', '')
        notification_config.email.from_email = request.form.get('from_email', '')
        notification_config.email.use_tls = 'use_tls' in request.form
        notification_config.email.enabled = 'email_enabled' in request.form
        
        # Handle password (only update if provided)
        password = request.form.get('password', '')
        if password:
            notification_config.email.password = password
        
        # Handle to_emails (comma-separated list)
        to_emails = request.form.get('to_emails', '')
        notification_config.email.to_emails = [email.strip() for email in to_emails.split(',') if email.strip()]
        
        # Save configuration
        notification_config.save_to_file(CONFIG_FILE)
        
        # Update notification manager
        global notification_manager
        notification_manager = NotificationManager(notification_config)
        
        flash('Email settings updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating email settings: {str(e)}', 'error')
    
    return redirect(url_for('settings'))

@app.route('/update_slack_settings', methods=['POST'])
def update_slack_settings():
    """Update Slack notification settings"""
    try:
        # Update Slack configuration
        notification_config.slack.webhook_url = request.form.get('webhook_url', '')
        notification_config.slack.channel = request.form.get('channel', '')
        notification_config.slack.username = request.form.get('slack_username', '')
        notification_config.slack.enabled = 'slack_enabled' in request.form
        
        # Save configuration
        notification_config.save_to_file(CONFIG_FILE)
        
        # Update notification manager
        global notification_manager
        notification_manager = NotificationManager(notification_config)
        
        flash('Slack settings updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating Slack settings: {str(e)}', 'error')
    
    return redirect(url_for('settings'))

@app.route('/update_general_settings', methods=['POST'])
def update_general_settings():
    """Update general notification settings"""
    try:
        # Update general settings
        notification_config.alert_settings.min_severity = request.form.get('min_severity', 'medium')
        notification_config.alert_settings.max_alerts_per_hour = int(request.form.get('max_alerts_per_hour', 10))
        notification_config.alert_settings.batch_alerts = 'batch_alerts' in request.form
        
        # Save configuration
        notification_config.save_to_file(CONFIG_FILE)
        
        # Update notification manager
        global notification_manager
        notification_manager = NotificationManager(notification_config)
        
        flash('General settings updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating general settings: {str(e)}', 'error')
    
    return redirect(url_for('settings'))

@app.route('/test_email_config', methods=['POST'])
def test_email_config():
    """Send a test email to verify configuration"""
    try:
        success = notification_manager.send_test_email()
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to send test email'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/test_slack_config', methods=['POST'])
def test_slack_config():
    """Send a test Slack message to verify configuration"""
    try:
        success = notification_manager.send_test_slack()
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to send test Slack message'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

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
            start_monitoring(callback=monitoring_callback, notification_manager=notification_manager)
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

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_uploaded_file(file_path, original_filename):
    """Process uploaded log file and detect suspicious entries"""
    suspicious_count = 0
    total_lines = 0
    errors = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                line = line.strip()
                
                if line and is_suspicious(line):
                    # Add source information to the log entry
                    enhanced_entry = f"[UPLOADED:{original_filename}] {line}"
                    save_suspicious_log(enhanced_entry)
                    suspicious_count += 1
                    
                    # Add to recent alerts for real-time display
                    global recent_alerts
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'log_entry': enhanced_entry,
                        'formatted_time': 'Just now'
                    }
                    recent_alerts.insert(0, alert)
                    if len(recent_alerts) > MAX_RECENT_ALERTS:
                        recent_alerts = recent_alerts[:MAX_RECENT_ALERTS]
                    
                    # Send notification for uploaded file threat
                    try:
                        notification_manager.send_security_alert(enhanced_entry)
                    except Exception as e:
                        print(f"[NOTIFICATION] Error sending upload alert: {e}")
        
        return {
            'success': True,
            'suspicious_count': suspicious_count,
            'total_lines': total_lines,
            'errors': errors
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'suspicious_count': 0,
            'total_lines': 0
        }

# File upload route
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file upload for remote log files"""
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If user does not select file, browser also submits an empty part without filename
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            try:
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{timestamp}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Save the uploaded file
                file.save(file_path)
                
                # Process the uploaded file for suspicious activities
                suspicious_count = process_uploaded_file(file_path, file.filename)
                
                flash(f'File "{file.filename}" uploaded successfully! Found {suspicious_count} suspicious activities.', 'success')
                return redirect(url_for('dashboard'))
                
            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'error')
                return redirect(request.url)
        else:
            flash('Invalid file type. Only .log, .txt, and .out files are allowed.', 'error')
            return redirect(request.url)
    
    return render_template('upload.html')

@app.route('/uploads')
def uploaded_files():
    """Display list of uploaded files"""
    try:
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            files = []
        else:
            files = []
            for filename in os.listdir(upload_folder):
                if os.path.isfile(os.path.join(upload_folder, filename)):
                    file_path = os.path.join(upload_folder, filename)
                    stat = os.stat(file_path)
                    files.append({
                        'name': filename,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
            files.sort(key=lambda x: x['modified'], reverse=True)
        
        return render_template('uploads.html', files=files)
    except Exception as e:
        flash(f'Error loading uploaded files: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete_upload/<filename>', methods=['POST'])
def delete_upload(filename):
    """Delete an uploaded file"""
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
        if os.path.exists(file_path):
            os.remove(file_path)
            flash(f'File "{filename}" deleted successfully!', 'success')
        else:
            flash(f'File "{filename}" not found!', 'error')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'error')
    
    return redirect(url_for('uploaded_files'))

if __name__ == '__main__':
    init_db()
    
    # Only start monitoring if not in Flask reloader mode
    import os
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        # This is the main process, not the reloader
        try:
            start_monitoring(callback=monitoring_callback, notification_manager=notification_manager)
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
