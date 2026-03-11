"""
Action Generator for SIEM Integration
======================================
Generates JSON-formatted alerts and logs for Security Information and 
Event Management (SIEM) systems, simulating ELK stack integration.

Key Features:
- Structured JSON logging for all events
- Alert generation for policy violations
- ELK stack compatible format
- Real-time event streaming capability
"""

import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class ActionGenerator:
    """
    Generates structured security events and alerts for SIEM systems.
    
    This class creates JSON-formatted logs compatible with ELK stack 
    (Elasticsearch, Logstash, Kibana) and other SIEM platforms.
    """
    
    def __init__(self, output_mode='log', siem_endpoint=None):
        """
        Initialize the action generator.
        
        Args:
            output_mode (str): Output mode - 'log' for local logging, 
                              'siem' for SIEM integration
            siem_endpoint (str): SIEM webhook/API endpoint URL (optional)
        """
        self.output_mode = output_mode
        self.siem_endpoint = siem_endpoint
        self.event_count = 0
    
    def generate_alert(self, parsed_data: Dict[str, Any], violation_reason: str, 
                      action_taken: str, grid_state: Optional[Dict] = None):
        """
        Generate a security alert for a detected violation.
        
        Args:
            parsed_data (dict): Parsed Modbus packet data
            violation_reason (str): Reason for the violation
            action_taken (str): Action taken by GridShield (BLOCKED/ALLOWED/MONITORED)
            grid_state (dict): Current grid state information
            
        Returns:
            dict: Generated alert in JSON format
        """
        self.event_count += 1
        
        # Build structured alert following CEF (Common Event Format) conventions
        alert = {
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "event_id": f"GS-{self.event_count:06d}",
            "event_type": "MODBUS_VIOLATION",
            "severity": self._calculate_severity(violation_reason, action_taken),
            
            # Source information
            "source": {
                "system": "GridShield",
                "component": "Semantic Firewall",
                "version": "1.0.0"
            },
            
            # Grid state context
            "grid_state": grid_state or {
                "frequency_hz": 60.0,
                "mode": "NORMAL"
            },
            
            # Violation details
            "violation": {
                "reason": violation_reason,
                "action_taken": action_taken,
                "blocked": action_taken == "BLOCKED"
            },
            
            # Modbus packet details
            "modbus_data": {
                "transaction_id": parsed_data.get('transaction_id'),
                "unit_id": parsed_data.get('unit_id'),
                "function_code": parsed_data.get('function_code'),
                "function_name": parsed_data.get('function_name'),
                "register_address": parsed_data.get('register_address'),
                "data_values": parsed_data.get('data_values', []),
                "is_write_operation": parsed_data.get('function_code') in [0x05, 0x06, 0x0F, 0x10]
            },
            
            # SIEM metadata
            "metadata": {
                "facility": "ICS_SECURITY",
                "category": "PROTOCOL_ANOMALY",
                "technology": "MODBUS_TCP"
            }
        }
        
        # Output the alert
        self._output_alert(alert)
        
        return alert
    
    def log_normal_operation(self, parsed_data: Dict[str, Any], allowed: bool = True):
        """
        Log normal Modbus traffic for audit trail.
        
        Args:
            parsed_data (dict): Parsed Modbus packet data
            allowed (bool): Whether the command was allowed
        """
        self.event_count += 1
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "event_id": f"GS-{self.event_count:06d}",
            "event_type": "MODBUS_TRAFFIC",
            "severity": "INFO" if allowed else "LOW",
            
            "source": {
                "system": "GridShield",
                "component": "Traffic Monitor"
            },
            
            "modbus_data": {
                "transaction_id": parsed_data.get('transaction_id'),
                "unit_id": parsed_data.get('unit_id'),
                "function_code": parsed_data.get('function_code'),
                "function_name": parsed_data.get('function_name'),
                "register_address": parsed_data.get('register_address'),
                "data_values": parsed_data.get('data_values', [])
            },
            
            "status": "ALLOWED" if allowed else "MONITORED",
            
            "metadata": {
                "facility": "ICS_MONITORING",
                "category": "NORMAL_OPERATION",
                "technology": "MODBUS_TCP"
            }
        }
        
        logger.info(f"Modbus traffic logged: FC={parsed_data.get('function_code')} - {log_entry['status']}")
    
    def _calculate_severity(self, violation_reason: str, action_taken: str) -> str:
        """
        Calculate alert severity based on violation type and action.
        
        Args:
            violation_reason (str): Reason for violation
            action_taken (str): Action taken
            
        Returns:
            str: Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        """
        # Shadow mode violations are lower severity (monitoring only)
        if "SHADOW_MODE" in violation_reason:
            return "MEDIUM"
        
        # Blocked commands are higher severity
        if action_taken == "BLOCKED":
            if "FUNCTION_CODE" in violation_reason:
                return "HIGH"
            elif "BOUNDS" in violation_reason:
                return "CRITICAL"
            elif "RATE_LIMIT" in violation_reason:
                return "MEDIUM"
        
        return "HIGH"
    
    def _output_alert(self, alert: dict):
        """
        Output the alert via configured channels.
        
        Args:
            alert (dict): Formatted alert dictionary
        """
        # Convert to JSON string
        alert_json = json.dumps(alert, indent=2)
        
        # Log as structured JSON
        if alert['severity'] in ['CRITICAL', 'HIGH']:
            logger.critical(f"SECURITY ALERT: {alert_json}")
        elif alert['severity'] == 'MEDIUM':
            logger.warning(f"SECURITY ALERT: {alert_json}")
        else:
            logger.info(f"SECURITY EVENT: {alert_json}")
        
        # In production, would also send to SIEM endpoint
        if self.output_mode == 'siem' and self.siem_endpoint:
            self._send_to_siem(alert_json)
    
    def _send_to_siem(self, alert_json: str):
        """
        Send alert to SIEM system via HTTP webhook.
        
        Args:
            alert_json (str): JSON-formatted alert
        """
        try:
            # Placeholder for SIEM integration
            # In production, use requests library to POST to SIEM endpoint
            logger.debug(f"Sending to SIEM: {alert_json[:100]}...")
        except Exception as e:
            logger.error(f"Failed to send alert to SIEM: {e}")
    
    def get_statistics(self) -> dict:
        """
        Get alert statistics.
        
        Returns:
            dict: Statistics including total events, alerts, etc.
        """
        return {
            "total_events": self.event_count,
            "output_mode": self.output_mode,
            "siem_configured": bool(self.siem_endpoint)
        }
