"""
GridShield Web Dashboard & API Server
======================================
Production-grade REST API and real-time WebSocket dashboard for GridShield.

Features:
- Real-time Modbus traffic visualization
- Live alerts and violations
- System status monitoring
- Historical data and statistics
- Remote configuration management
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import json
import logging
from datetime import datetime
import asyncio
from main import GridShieldFirewall

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'gridshield-secret-key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Global state
gridshield_instance = None
firewall_thread = None
running = False

# Statistics storage
stats = {
    'packets_captured': 0,
    'packets_analyzed': 0,
    'violations_detected': 0,
    'commands_blocked': 0,
    'commands_allowed': 0,
    'start_time': None,
    'mode': 'NORMAL',
    'grid_frequency': 60.0
}

# Recent events buffer (last 100 events)
events_buffer = []


@app.route('/')
def index():
    """Serve the main dashboard."""
    return render_template('dashboard.html')


@app.route('/api/status')
def get_status():
    """Get current system status."""
    return jsonify({
        'status': 'running' if running else 'stopped',
        'stats': stats,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })


@app.route('/api/events')
def get_events():
    """Get recent events."""
    return jsonify(events_buffer[-100:])


@app.route('/api/start', methods=['POST'])
def start_system():
    """Start GridShield firewall."""
    global running, gridshield_instance, firewall_thread
    
    if running:
        return jsonify({'error': 'Already running'}), 400
    
    running = True
    stats['start_time'] = datetime.utcnow().isoformat() + 'Z'
    
    # Start in background thread
    firewall_thread = threading.Thread(target=run_firewall, daemon=True)
    firewall_thread.start()
    
    socketio.emit('system_started', {'status': 'started'})
    return jsonify({'message': 'GridShield started successfully'})


@app.route('/api/stop', methods=['POST'])
def stop_system():
    """Stop GridShield firewall."""
    global running
    
    running = False
    socketio.emit('system_stopped', {'status': 'stopped'})
    return jsonify({'message': 'GridShield stopped successfully'})


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration."""
    try:
        with open('config/safety_rules.json', 'r') as f:
            config = json.load(f)
        return jsonify(config)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['POST'])
def update_config():
    """Update configuration."""
    try:
        new_config = request.json
        with open('config/safety_rules.json', 'w') as f:
            json.dump(new_config, f, indent=2)
        
        socketio.emit('config_updated', {'config': new_config})
        return jsonify({'message': 'Configuration updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def run_firewall():
    """Run GridShield firewall in background thread."""
    global gridshield_instance
    
    try:
        gridshield_instance = GridShieldFirewall(
            interface='lo',
            port=502,
            shadow_mode=False
        )
        
        # Monkey patch for asyncio compatibility
        import eventlet
        eventlet.monkey_patch()
        
        asyncio.run(gridshield_instance.start())
    except Exception as e:
        logger.error(f"Firewall error: {e}")
        socketio.emit('error', {'message': str(e)})


def emit_stats():
    """Emit real-time statistics via WebSocket."""
    while running:
        try:
            socketio.emit('stats_update', stats)
            socketio.sleep(1)  # Update every second
        except:
            break


@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    logger.info('Client connected to dashboard')
    emit('initial_data', {
        'stats': stats,
        'events': events_buffer[-50:]
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    logger.info('Client disconnected from dashboard')


def add_event(event_type, severity, message, data=None):
    """Add event to buffer and broadcast to clients."""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'type': event_type,
        'severity': severity,
        'message': message,
        'data': data or {}
    }
    
    events_buffer.append(event)
    
    # Keep only last 100 events
    if len(events_buffer) > 100:
        events_buffer.pop(0)
    
    # Broadcast to all connected clients
    socketio.emit('new_event', event)


if __name__ == '__main__':
    logger.info("Starting GridShield Web Dashboard...")
    logger.info("Dashboard will be available at http://localhost:5000")
    
    # Start stats emitter thread
    stats_thread = threading.Thread(target=emit_stats, daemon=True)
    stats_thread.start()
    
    # Run Flask app
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
