"""
Rules Engine for Semantic Validation
=====================================
Contains logic gates for semantic validation of Modbus commands against 
safety invariants defined in safety_rules.json.

Key Features:
- Validates register values against acceptable bounds
- Checks function codes against allowed operations
- Enforces rate limiting on critical commands
- Implements grid frequency-based fail-open logic
"""

import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


class RulesEngine:
    """
    Semantic validation engine for Modbus commands.
    
    This class implements safety invariant checks including:
    - Value bounds checking (voltage, frequency, current)
    - Function code allowlisting/blocklisting
    - Rate limiting on write operations
    - Grid frequency-dependent fail-open mechanism
    """
    
    def __init__(self, rules_file='config/safety_rules.json'):
        """
        Initialize the rules engine with safety rules from JSON config.
        
        Args:
            rules_file (str): Path to JSON file containing safety rules
        """
        self.rules_file = rules_file
        self.safety_rules = self._load_rules()
        
        # Rate limiting state tracking
        self.command_timestamps = defaultdict(list)
        
        # Grid state for fail-open logic
        self.grid_frequency = 60.0  # Default nominal frequency (Hz)
        self.shadow_mode = False  # Fail-open state
        
    def _load_rules(self):
        """
        Load safety rules from JSON configuration file.
        
        Returns:
            dict: Safety rules configuration or default rules if file not found
        """
        try:
            with open(self.rules_file, 'r') as f:
                rules = json.load(f)
                logger.info(f"Loaded safety rules from {self.rules_file}")
                return rules
        except FileNotFoundError:
            logger.warning(f"Rules file not found: {self.rules_file}, using defaults")
            return self._get_default_rules()
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in rules file: {e}")
            return self._get_default_rules()
    
    def _get_default_rules(self):
        """Return default safety rules for grid protection."""
        return {
            "frequency_threshold": 59.5,  # Hz - below this triggers fail-open
            "allowed_function_codes": [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x10],
            "blocked_function_codes": [0x0F],  # Write Multiple Coils blocked by default
            "register_bounds": {
                "voltage": {"min": 0, "max": 500, "unit": "V"},  # Voltage register range
                "frequency": {"min": 55, "max": 65, "unit": "Hz"},  # Frequency range
                "current": {"min": 0, "max": 1000, "unit": "A"},  # Current range
                "power": {"min": 0, "max": 10000, "unit": "kW"}  # Power range
            },
            "rate_limits": {
                "write_commands_per_second": 10,  # Max write commands per second
                "critical_registers_cooldown_ms": 1000  # Cooldown for critical registers
            }
        }
    
    def validate_command(self, parsed_modbus_data):
        """
        Validate a parsed Modbus command against all safety rules.
        
        Args:
            parsed_modbus_data (dict): Parsed Modbus packet from parser
            
        Returns:
            tuple: (is_valid: bool, violation_reason: str or None)
        """
        # Check if we're in shadow mode (fail-open)
        if self.shadow_mode:
            logger.warning("SHADOW MODE: Allowing command that would be blocked")
            return True, "SHADOW_MODE_ALLOW"
        
        function_code = parsed_modbus_data.get('function_code')
        
        # Rule 1: Check if function code is allowed
        if not self._check_function_code_allowed(function_code):
            return False, f"BLOCKED_FUNCTION_CODE: FC={function_code}"
        
        # Rule 2: Check register value bounds
        if not self._check_register_bounds(parsed_modbus_data):
            return False, "REGISTER_BOUNDS_VIOLATION"
        
        # Rule 3: Check rate limiting
        if not self._check_rate_limit(parsed_modbus_data):
            return False, "RATE_LIMIT_EXCEEDED"
        
        # All checks passed
        return True, None
    
    def _check_function_code_allowed(self, function_code):
        """
        Validate function code against allowlist/blocklist.
        
        Args:
            function_code (int): Modbus function code
            
        Returns:
            bool: True if function code is allowed
        """
        if function_code in self.safety_rules.get('blocked_function_codes', []):
            logger.warning(f"Blocked function code detected: {function_code}")
            return False
        
        allowed_codes = self.safety_rules.get('allowed_function_codes', [])
        if allowed_codes and function_code not in allowed_codes:
            logger.warning(f"Function code not in allowlist: {function_code}")
            return False
        
        return True
    
    def _check_register_bounds(self, parsed_data):
        """
        Validate register values against safety bounds.
        
        Args:
            parsed_data (dict): Parsed Modbus data with register addresses and values
            
        Returns:
            bool: True if all values are within bounds
        """
        register_address = parsed_data.get('register_address')
        data_values = parsed_data.get('data_values', [])
        
        if register_address is None or not data_values:
            return True  # No data to validate
        
        # Map register addresses to physical quantities (simplified mapping)
        # In production, this would use actual register map from device documentation
        register_map = {
            0: 'voltage',
            1: 'frequency', 
            2: 'current',
            3: 'power'
        }
        
        quantity_type = register_map.get(register_address)
        if quantity_type and quantity_type in self.safety_rules.get('register_bounds', {}):
            bounds = self.safety_rules['register_bounds'][quantity_type]
            
            for value in data_values:
                if value < bounds['min'] or value > bounds['max']:
                    logger.warning(
                        f"Bounds violation: {quantity_type}={value} "
                        f"(allowed: {bounds['min']}-{bounds['max']} {bounds['unit']})"
                    )
                    return False
        
        return True
    
    def _check_rate_limit(self, parsed_data):
        """
        Enforce rate limiting on write commands.
        
        Args:
            parsed_data (dict): Parsed Modbus data
            
        Returns:
            bool: True if command is within rate limits
        """
        function_code = parsed_data.get('function_code')
        
        # Only rate limit write operations
        write_codes = [0x05, 0x06, 0x0F, 0x10]
        if function_code not in write_codes:
            return True
        
        # Get rate limit configuration
        max_commands = self.safety_rules.get('rate_limits', {}).get('write_commands_per_second', 10)
        
        # Clean old timestamps (older than 1 second)
        now = datetime.now()
        one_second_ago = now - timedelta(seconds=1)
        self.command_timestamps['global'] = [
            ts for ts in self.command_timestamps['global'] 
            if ts > one_second_ago
        ]
        
        # Check if we've exceeded rate limit
        if len(self.command_timestamps['global']) >= max_commands:
            logger.warning(f"Rate limit exceeded: {len(self.command_timestamps['global'])} commands/sec")
            return False
        
        # Record this command
        self.command_timestamps['global'].append(now)
        return True
    
    def update_grid_frequency(self, frequency_hz):
        """
        Update the current grid frequency and check for fail-open condition.
        
        Args:
            frequency_hz (float): Current grid frequency in Hz
        """
        self.grid_frequency = frequency_hz
        
        # Check if frequency is below threshold - trigger fail-open
        threshold = self.safety_rules.get('frequency_threshold', 59.5)
        
        if frequency_hz < threshold:
            if not self.shadow_mode:
                self.shadow_mode = True
                logger.critical(
                    f"FAIL-OPEN ACTIVATED: Grid frequency {frequency_hz} Hz < {threshold} Hz. "
                    f"Entering SHADOW MODE - monitoring only, no blocking"
                )
        else:
            if self.shadow_mode:
                self.shadow_mode = False
                logger.info(
                    f"Grid frequency recovered: {frequency_hz} Hz. "
                    f"Returning to NORMAL MODE with active blocking"
                )
    
    def is_shadow_mode(self):
        """
        Check if the system is currently in shadow mode (fail-open state).
        
        Returns:
            bool: True if in shadow mode
        """
        return self.shadow_mode
    
    def get_system_status(self):
        """
        Get current system status including grid frequency and mode.
        
        Returns:
            dict: System status information
        """
        return {
            'grid_frequency_hz': self.grid_frequency,
            'shadow_mode_active': self.shadow_mode,
            'mode': 'SHADOW' if self.shadow_mode else 'NORMAL',
            'rules_loaded': bool(self.safety_rules),
            'tracked_commands_last_second': len(self.command_timestamps['global'])
        }
