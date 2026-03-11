"""
GridShield - Semantic Firewall for Power Grid Protection
=========================================================
Main orchestrator that ties together the DPI pipeline using asyncio.

This is the entry point for running GridShield in production or testing mode.

USAGE:
======
Terminal 1 (Run GridShield):
    sudo python3 main.py

Terminal 2 (Generate test traffic):
    sudo python3 simulator/modbus_sim.py

REQUIREMENTS:
=============
- Must run with sudo/root privileges to capture packets on loopback interface
- Python 3.9+
- Scapy, PyModbus installed via requirements.txt

ARCHITECTURE:
=============
Sniffer (port 502) → Parser (extract FC, registers) → Rules Engine (validate) 
→ Action Generator (alert/log) → SIEM Integration (ELK stack)
"""

import asyncio
import signal
import logging
import json
from datetime import datetime

# Import GridShield components
from core.sniffer import ModbusSniffer
from core.parser import ModbusParser
from core.rules_engine import RulesEngine
from core.action import ActionGenerator
from utils.fail_open import FailOpenMechanism

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class GridShieldFirewall:
    """
    Main GridShield semantic firewall orchestrator.
    
    Coordinates all components of the Deep Packet Inspection pipeline:
    1. Packet capture via Scapy
    2. Protocol parsing for Modbus TCP
    3. Semantic validation against safety rules
    4. Alert generation and SIEM integration
    5. Fail-open mechanism for grid emergencies
    """
    
    def __init__(self, interface='lo', port=502, shadow_mode=False):
        """
        Initialize the GridShield firewall.
        
        Args:
            interface (str): Network interface to monitor (default: 'lo')
            port (int): Modbus TCP port to filter (default: 502)
            shadow_mode (bool): Start in monitoring-only mode (no blocking)
        """
        self.interface = interface
        self.port = port
        self.shadow_mode = shadow_mode
        
        # Initialize components
        self.packet_queue = asyncio.Queue()
        self.sniffer = ModbusSniffer(interface=interface, port=port, packet_queue=self.packet_queue)
        self.parser = ModbusParser()
        self.rules_engine = RulesEngine()
        self.action_generator = ActionGenerator(output_mode='log')
        self.fail_open = FailOpenMechanism(frequency_threshold_hz=59.5)
        
        # Statistics tracking
        self.stats = {
            'packets_captured': 0,
            'packets_analyzed': 0,
            'violations_detected': 0,
            'commands_blocked': 0,
            'commands_allowed': 0,
            'start_time': None
        }
        
        # Control flags
        self.running = False
    
    async def start(self):
        """Start the GridShield firewall."""
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        logger.info("=" * 70)
        logger.info("GridShield Semantic Firewall Starting...")
        logger.info("=" * 70)
        logger.info(f"Monitoring interface: {self.interface}")
        logger.info(f"Filtering port: {self.port}")
        logger.info(f"Mode: {'SHADOW (monitoring only)' if self.shadow_mode else 'NORMAL (active blocking)'}")
        logger.info("=" * 70)
        
        # Start the packet sniffer
        self.sniffer.start_sniffing()
        logger.info("Packet sniffer initialized")
        
        # Begin packet processing loop
        await self.process_packets()
    
    async def process_packets(self):
        """
        Main packet processing loop.
        
        Continuously retrieves packets from the queue and processes them
        through the entire DPI pipeline.
        """
        logger.info("Starting packet processing loop...")
        
        while self.running:
            try:
                # Get next packet from queue (wait up to 1 second)
                try:
                    packet = await asyncio.wait_for(self.packet_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                
                self.stats['packets_captured'] += 1
                
                # Parse the Modbus packet
                parsed_data = self.parser.parse_packet(packet)
                
                if parsed_data is None:
                    logger.debug("Failed to parse packet - not valid Modbus TCP")
                    continue
                
                self.stats['packets_analyzed'] += 1
                logger.info(f"Parsed: FC={parsed_data['function_code']} ({parsed_data['function_name']})")
                
                # Update grid frequency from simulator (in production, this would come from PMU/sensors)
                # For demo, we'll simulate occasional frequency fluctuations
                if random.random() < 0.05:  # 5% chance
                    simulated_frequency = 59.0 + random.random() * 2
                    self.fail_open.update_grid_state(simulated_frequency)
                
                # Validate against safety rules
                is_valid, violation_reason = self.rules_engine.validate_command(parsed_data)
                
                # Take action based on validation result
                if is_valid:
                    self.stats['commands_allowed'] += 1
                    logger.info(f"✓ ALLOWED | FC={parsed_data['function_code']}")
                    
                    # Log normal operation
                    self.action_generator.log_normal_operation(parsed_data, allowed=True)
                else:
                    self.stats['violations_detected'] += 1
                    
                    # Check if we're in shadow mode (fail-open)
                    if self.fail_open.is_shadow_mode():
                        self.stats['commands_allowed'] += 1
                        logger.warning(
                            f"⚠ SHADOW MODE | Would block but allowing due to fail-open | "
                            f"Violation: {violation_reason}"
                        )
                        
                        # Generate alert but don't block
                        self.action_generator.generate_alert(
                            parsed_data=parsed_data,
                            violation_reason=violation_reason,
                            action_taken="MONITORED",
                            grid_state=self.fail_open.get_status()
                        )
                    else:
                        self.stats['commands_blocked'] += 1
                        logger.critical(
                            f"✗ BLOCKED | Violation: {violation_reason} | "
                            f"FC={parsed_data['function_code']}"
                        )
                        
                        # Generate high-priority alert
                        self.action_generator.generate_alert(
                            parsed_data=parsed_data,
                            violation_reason=violation_reason,
                            action_taken="BLOCKED",
                            grid_state=self.fail_open.get_status()
                        )
                
                # Mark task as done
                self.packet_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error processing packet: {e}", exc_info=True)
    
    def stop(self):
        """Stop the GridShield firewall."""
        logger.info("Stopping GridShield firewall...")
        self.running = False
        self.sniffer.stop_sniffing()
        
        # Print final statistics
        self.print_statistics()
    
    def print_statistics(self):
        """Print operational statistics."""
        runtime = datetime.now() - self.stats['start_time'] if self.stats['start_time'] else None
        
        logger.info("=" * 70)
        logger.info("GridShield Final Statistics")
        logger.info("=" * 70)
        logger.info(f"Runtime: {runtime}")
        logger.info(f"Packets Captured: {self.stats['packets_captured']}")
        logger.info(f"Packets Analyzed: {self.stats['packets_analyzed']}")
        logger.info(f"Violations Detected: {self.stats['violations_detected']}")
        logger.info(f"Commands Blocked: {self.stats['commands_blocked']}")
        logger.info(f"Commands Allowed: {self.stats['commands_allowed']}")
        
        if self.stats['packets_analyzed'] > 0:
            block_rate = (self.stats['commands_blocked'] / self.stats['packets_analyzed']) * 100
            logger.info(f"Block Rate: {block_rate:.2f}%")
        
        logger.info(f"Fail-Open Status: {self.fail_open.get_status()}")
        logger.info("=" * 70)


async def main():
    """Main entry point."""
    import random  # For simulating grid frequency changes
    
    # Create the firewall instance
    firewall = GridShieldFirewall(interface='lo', port=502, shadow_mode=False)
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received")
        firewall.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start the firewall
        await firewall.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        firewall.stop()


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("GridShield v1.0 - Semantic Firewall for Power Grid Protection")
    print("=" * 70)
    print("\nStarting Deep Packet Inspection on Modbus TCP port 502...")
    print("Press Ctrl+C to stop\n")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nGridShield stopped")
    except PermissionError:
        print("\nERROR: This program must be run with sudo/root privileges")
        print("Try: sudo python3 main.py")
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
