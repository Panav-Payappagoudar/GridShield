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
import random

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'gridshield-secret-key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Global state
running = False
simulator_running = False

# Real-time statistics
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

# Traffic data for chart (last 60 seconds)
traffic_history = {'labels': [], 'allowed': [], 'blocked': []}


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
    """Start GridShield firewall and simulator."""
    global running, simulator_running
    
    if running:
        return jsonify({'error': 'Already running'}), 400
    
    running = True
    simulator_running = True
    stats['start_time'] = datetime.utcnow().isoformat() + 'Z'
    
    # Start simulation thread
    sim_thread = threading.Thread(target=run_simulation, daemon=True)
    sim_thread.start()
    
    socketio.emit('system_started', {'status': 'started'})
    return jsonify({'message': 'GridShield started successfully'})


@app.route('/api/stop', methods=['POST'])
def stop_system():
    """Stop GridShield firewall and simulator."""
    global running, simulator_running
    
    running = False
    simulator_running = False
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


def run_simulation():
    """Run real-time Modbus traffic simulation."""
    global stats, running, simulator_running
    
    logger.info("Starting real-time Modbus simulation...")
    
    scenario = 0
    scenario_duration = 5  # seconds per scenario
    
    while simulator_running and running:
        try:
            scenario = scenario % 4
            
            if scenario == 0:
                # Normal operation
                simulate_normal_traffic()
                add_event('MODBUS_TRAFFIC', 'INFO', 
                         f'Normal operation - Read registers [230V, 60Hz]',
                         {'allowed': True, 'type': 'normal'})
                
            elif scenario == 1:
                # Malicious attack - voltage spike
                voltage = random.randint(600, 700)
                is_blocked = check_violation('voltage', voltage)
                severity = 'CRITICAL' if is_blocked else 'MEDIUM'
                action = 'BLOCKED' if is_blocked else 'ALLOWED (Shadow Mode)'
                
                add_event('MODBUS_VIOLATION', severity,
                         f'Voltage setpoint {voltage}V exceeds 500V limit - {action}',
                         {'allowed': not is_blocked, 'type': 'attack', 'value': voltage})
                
            elif scenario == 2:
                # Grid emergency - frequency drop
                stats['grid_frequency'] = random.uniform(58.5, 59.3)
                stats['mode'] = 'SHADOW'
                
                add_event('GRID_EMERGENCY', 'CRITICAL',
                         f'Grid frequency dropped to {stats["grid_frequency"]:.2f}Hz - FAIL-OPEN ACTIVATED',
                         {'frequency': stats['grid_frequency'], 'mode': 'SHADOW'})
                
            elif scenario == 3:
                # Recovery
                stats['grid_frequency'] = random.uniform(59.8, 60.2)
                stats['mode'] = 'NORMAL'
                
                add_event('GRID_RECOVERY', 'INFO',
                         f'Grid frequency stabilized at {stats["grid_frequency"]:.2f}Hz - NORMAL MODE',
                         {'frequency': stats['grid_frequency'], 'mode': 'NORMAL'})
            
            scenario += 1
            
            # Update chart data
            update_traffic_history()
            
            # Broadcast updates
            socketio.emit('stats_update', stats)
            
            import eventlet
            eventlet.sleep(scenario_duration)
            
        except Exception as e:
            logger.error(f"Simulation error: {e}")
            break
    
    logger.info("Simulation stopped")


def simulate_normal_traffic():
    """Simulate normal Modbus traffic."""
    global stats
    stats['packets_captured'] += random.randint(3, 8)
    stats['packets_analyzed'] += random.randint(3, 8)
    stats['commands_allowed'] += random.randint(2, 5)


def check_violation(param_type, value):
    """Check if value violates safety rules."""
    if param_type == 'voltage':
        return value > 500 or value < 0
    elif param_type == 'frequency':
        return value > 65 or value < 55
    return False


def update_traffic_history():
    """Update traffic history for charts."""
    now = datetime.now().strftime('%H:%M:%S')
    
    # Generate more realistic traffic patterns
    base_allowed = random.randint(3, 8)
    base_blocked = random.randint(0, 3) if stats['mode'] == 'NORMAL' else 0
    
    # Add some variation based on scenario
    if stats['violations_detected'] > 0:
        base_blocked += random.randint(1, 3)
    
    traffic_history['labels'].append(now)
    traffic_history['allowed'].append(base_allowed)
    traffic_history['blocked'].append(base_blocked)
    
    # Keep last 60 data points for better visualization
    if len(traffic_history['labels']) > 60:
        traffic_history['labels'].pop(0)
        traffic_history['allowed'].pop(0)
        traffic_history['blocked'].pop(0)


def emit_stats():
    """Emit real-time statistics via WebSocket."""
    while running:
        try:
            socketio.emit('stats_update', stats)
            import eventlet
            eventlet.sleep(1)  # Update every second
        except:
            break


@app.route('/api/traffic')
def get_traffic():
    """Get traffic history for charts."""
    return jsonify(traffic_history)


@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    logger.info('Client connected to dashboard')
    emit('initial_data', {
        'stats': stats,
        'events': events_buffer[-50:],
        'traffic': traffic_history
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
