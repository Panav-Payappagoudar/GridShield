"""
Fail-Open Utility for GridShield
=================================
Implements fail-open mechanism to switch between Normal Mode (blocking) 
and Shadow Mode (monitoring only) based on grid health.

Key Features:
- Automatic mode switching based on grid frequency
- Manual override capability
- State persistence and recovery
- Health monitoring and alerts
"""

import logging
from enum import Enum
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class OperationMode(Enum):
    """GridShield operational modes."""
    NORMAL = "NORMAL"  # Active blocking of violations
    SHADOW = "SHADOW"  # Monitoring only, no blocking
    MAINTENANCE = "MAINTENANCE"  # Manual override for maintenance


class FailOpenMechanism:
    """
    Implements fail-open logic for critical grid protection scenarios.
    
    When grid frequency drops below safe thresholds, this mechanism
    automatically switches to Shadow Mode to ensure commands are not
    blocked during emergency conditions (fail-safe behavior).
    """
    
    def __init__(self, frequency_threshold_hz: float = 59.5):
        """
        Initialize the fail-open mechanism.
        
        Args:
            frequency_threshold_hz (float): Frequency threshold below which 
                                          fail-open is triggered
        """
        self.frequency_threshold = frequency_threshold_hz
        self.current_mode = OperationMode.NORMAL
        self.grid_frequency = 60.0
        self.mode_change_callbacks = []
        self.last_frequency_update = None
    
    def update_grid_state(self, frequency_hz: float):
        """
        Update grid state and check if mode change is required.
        
        Args:
            frequency_hz (float): Current grid frequency in Hz
        """
        self.grid_frequency = frequency_hz
        
        previous_mode = self.current_mode
        
        # Check if we need to enter/exit fail-open mode
        if frequency_hz < self.frequency_threshold:
            if self.current_mode == OperationMode.NORMAL:
                self._enter_shadow_mode()
        else:
            # Add hysteresis - require frequency to recover above threshold + 0.2 Hz
            if self.current_mode == OperationMode.SHADOW and frequency_hz >= (self.frequency_threshold + 0.2):
                self._exit_shadow_mode()
        
        # Notify callbacks if mode changed
        if self.current_mode != previous_mode:
            self._notify_mode_change(previous_mode, self.current_mode)
    
    def _enter_shadow_mode(self):
        """Transition to Shadow Mode (fail-open state)."""
        self.current_mode = OperationMode.SHADOW
        logger.critical(
            f"FAIL-OPEN ACTIVATED | Grid Frequency: {self.grid_frequency:.2f} Hz | "
            f"Threshold: {self.frequency_threshold:.2f} Hz | "
            f"Mode: SHADOW (monitoring only, NO BLOCKING)"
        )
    
    def _exit_shadow_mode(self):
        """Return to Normal Mode from Shadow Mode."""
        self.current_mode = OperationMode.NORMAL
        logger.info(
            f"Grid stabilized | Frequency: {self.grid_frequency:.2f} Hz | "
            f"Mode: NORMAL (active protection enabled)"
        )
    
    def _notify_mode_change(self, old_mode: OperationMode, new_mode: OperationMode):
        """Notify all registered callbacks of mode change."""
        for callback in self.mode_change_callbacks:
            try:
                callback(old_mode, new_mode, self.grid_frequency)
            except Exception as e:
                logger.error(f"Error in mode change callback: {e}")
    
    def register_mode_callback(self, callback: Callable):
        """
        Register a callback to be notified on mode changes.
        
        Args:
            callback (Callable): Function with signature callback(old_mode, new_mode, frequency)
        """
        self.mode_change_callbacks.append(callback)
        logger.debug("Mode change callback registered")
    
    def is_blocking_enabled(self) -> bool:
        """
        Check if packet blocking is currently enabled.
        
        Returns:
            bool: True if blocking is active (Normal Mode)
        """
        return self.current_mode == OperationMode.NORMAL
    
    def is_shadow_mode(self) -> bool:
        """
        Check if system is in Shadow Mode.
        
        Returns:
            bool: True if in Shadow Mode
        """
        return self.current_mode == OperationMode.SHADOW
    
    def manual_override(self, mode: str, reason: str = "Manual override"):
        """
        Manually override the operational mode.
        
        Args:
            mode (str): Target mode ('NORMAL', 'SHADOW', or 'MAINTENANCE')
            reason (str): Reason for manual override
        """
        try:
            new_mode = OperationMode[mode.upper()]
            previous_mode = self.current_mode
            self.current_mode = new_mode
            
            logger.warning(
                f"MANUAL OVERRIDE | Mode: {new_mode.value} | "
                f"Previous: {previous_mode.value} | Reason: {reason}"
            )
            
            self._notify_mode_change(previous_mode, new_mode)
            
        except KeyError:
            logger.error(f"Invalid mode for manual override: {mode}")
    
    def get_status(self) -> dict:
        """
        Get current fail-open mechanism status.
        
        Returns:
            dict: Status information including mode, frequency, threshold
        """
        return {
            "mode": self.current_mode.value,
            "grid_frequency_hz": self.grid_frequency,
            "frequency_threshold_hz": self.frequency_threshold,
            "blocking_enabled": self.is_blocking_enabled(),
            "shadow_mode_active": self.is_shadow_mode(),
            "callbacks_registered": len(self.mode_change_callbacks),
            "last_update": self.last_frequency_update
        }
    
    def health_check(self) -> tuple:
        """
        Perform health check on the fail-open mechanism.
        
        Returns:
            tuple: (is_healthy: bool, message: str)
        """
        issues = []
        
        # Check if frequency value is reasonable
        if not (45.0 <= self.grid_frequency <= 70.0):
            issues.append(f"Unusual grid frequency: {self.grid_frequency} Hz")
        
        # Check if we've been in shadow mode too long (potential issue)
        if self.is_shadow_mode():
            issues.append("System operating in SHADOW MODE - verify grid conditions")
        
        is_healthy = len(issues) == 0
        message = "All systems nominal" if is_healthy else "; ".join(issues)
        
        logger.debug(f"Health check: {message}")
        return is_healthy, message
