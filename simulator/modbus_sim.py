"""
Modbus TCP Simulator for GridShield Testing
============================================
A simple PyModbus server that generates both legitimate and malicious 
Modbus traffic for testing the GridShield firewall.

Key Features:
- Simulates a Modbus slave device with holding registers
- Generates normal operational traffic (read/write commands)
- Injects malicious commands that violate safety rules
- Configurable attack patterns and timing

Usage:
    sudo python3 simulator/modbus_sim.py
    
This creates a Modbus server on port 502 and simulates various scenarios.
"""

import asyncio
import random
import logging
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import ModbusServerContext, ModbusSequentialDataBlock
from pymodbus.client import AsyncModbusTcpClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ModbusSimulator:
    """
    Modbus TCP simulator for generating test traffic.
    
    This class creates a Modbus server and client to simulate
    realistic ICS/OT communication patterns including attacks.
    """
    
    def __init__(self, host='127.0.0.1', port=502):
        """
        Initialize the Modbus simulator.
        
        Args:
            host (str): Host address for Modbus server
            port (int): Port number for Modbus server
        """
        self.host = host
        self.port = port
        self.running = False
        
        # Initialize data store with default register values
        # Address 0: Voltage, Address 1: Frequency, Address 2: Current, Address 3: Power
        data_block = ModbusSequentialDataBlock(0, [230, 60, 500, 5000] + [0] * 96)
        self.store = ModbusServerContext(data_block)
    
    async def run_server(self):
        """
        Run the Modbus TCP server.
        
        This coroutine starts the server and keeps it running until stopped.
        """
        logger.info(f"Starting Modbus TCP server on {self.host}:{self.port}")
        
        try:
            await StartAsyncTcpServer(
                context=self.store,
                address=(self.host, self.port),
            )
            logger.info("Modbus server started successfully")
        except Exception as e:
            logger.error(f"Server error: {e}")
            raise
    
    async def generate_normal_traffic(self, client: AsyncModbusTcpClient):
        """
        Generate legitimate Modbus traffic patterns.
        
        Args:
            client (AsyncModbusTcpClient): Connected Modbus client
        """
        logger.info("Generating NORMAL traffic pattern...")
        
        # Read holding registers (voltage, frequency)
        result = await client.read_holding_registers(address=0, count=4, unit=1)
        if not result.isError():
            logger.info(f"Read registers: {result.registers}")
        
        # Write single register (safe value within bounds)
        safe_voltage = random.randint(220, 240)
        await client.write_register(address=0, value=safe_voltage, unit=1)
        logger.info(f"Write safe voltage: {safe_voltage}V")
        
        # Read coils/discrete inputs
        await client.read_discrete_inputs(address=0, count=8, unit=1)
        
        await asyncio.sleep(1)
    
    async def generate_malicious_traffic(self, client: AsyncModbusTcpClient):
        """
        Generate malicious Modbus commands that should trigger GridShield alerts.
        
        Args:
            client (AsyncModbusTcpClient): Connected Modbus client
        """
        logger.warning("Generating MALICIOUS traffic pattern...")
        
        # Attack 1: Voltage setpoint out of bounds (>500V)
        malicious_voltage = 650
        logger.critical(f"ATTACK: Attempting to write dangerous voltage: {malicious_voltage}V")
        await client.write_register(address=0, value=malicious_voltage, unit=1)
        
        await asyncio.sleep(0.5)
        
        # Attack 2: Frequency setpoint out of bounds (<55Hz or >65Hz)
        malicious_frequency = 45
        logger.critical(f"ATTACK: Attempting to write dangerous frequency: {malicious_frequency}Hz")
        await client.write_register(address=1, value=malicious_frequency, unit=1)
        
        await asyncio.sleep(0.5)
        
        # Attack 3: Write multiple registers with dangerous values
        dangerous_values = [700, 40, 1200, 15000]  # All out of safe bounds
        logger.critical(f"ATTACK: Writing multiple dangerous values: {dangerous_values}")
        await client.write_registers(address=0, values=dangerous_values, unit=1)
        
        await asyncio.sleep(1)
    
    async def inject_grid_emergency(self, client: AsyncModbusTcpClient):
        """
        Simulate grid emergency conditions by setting frequency below threshold.
        
        This triggers the fail-open mechanism in GridShield.
        
        Args:
            client (AsyncModbusTcpClient): Connected Modbus client
        """
        logger.critical("SIMULATING GRID EMERGENCY - Frequency dropping below 59.5 Hz!")
        
        # Set frequency register to emergency level
        emergency_frequency = 59
        await client.write_register(address=1, value=emergency_frequency, unit=1)
        
        # Now attempt writes that would normally be blocked but should pass in fail-open
        logger.warning("Attempting writes during emergency (should enter SHADOW MODE)...")
        await client.write_register(address=0, value=600, unit=1)
        
        await asyncio.sleep(2)
    
    async def traffic_generator(self):
        """
        Main traffic generation loop.
        
        Connects to the server and generates a mix of normal and malicious traffic.
        """
        # Wait for server to start
        await asyncio.sleep(2)
        
        logger.info("Connecting to Modbus server as client...")
        client = AsyncModbusTcpClient(host=self.host, port=self.port)
        await client.connect()
        
        if not client.connected:
            logger.error("Failed to connect to Modbus server")
            return
        
        logger.info("Connected to Modbus server - starting traffic simulation")
        
        try:
            scenario = 0
            
            while self.running:
                scenario = scenario % 4
                
                if scenario == 0:
                    # Normal operation
                    await self.generate_normal_traffic(client)
                    logger.info("Scenario: Normal Operation ✓")
                
                elif scenario == 1:
                    # Malicious attack
                    await self.generate_malicious_traffic(client)
                    logger.warning("Scenario: Malicious Attack ⚠")
                
                elif scenario == 2:
                    # Grid emergency + fail-open test
                    await self.inject_grid_emergency(client)
                    logger.critical("Scenario: Grid Emergency / Fail-Open Test 🚨")
                
                elif scenario == 3:
                    # Back to normal
                    await self.generate_normal_traffic(client)
                    logger.info("Scenario: Recovery to Normal ✓")
                
                scenario += 1
                await asyncio.sleep(3)
                
        except Exception as e:
            logger.error(f"Traffic generator error: {e}")
        finally:
            client.close()
    
    async def run_simulation(self, duration_seconds: int = 60):
        """
        Run the complete simulation for specified duration.
        
        Args:
            duration_seconds (int): How long to run the simulation
        """
        self.running = True
        
        logger.info("=" * 60)
        logger.info("GridShield Modbus Traffic Simulator Starting...")
        logger.info("=" * 60)
        logger.info("This will generate:")
        logger.info("  ✓ Normal Modbus traffic")
        logger.info("  ⚠ Malicious commands (out-of-bounds values)")
        logger.info("  🚨 Grid emergency scenarios (fail-open testing)")
        logger.info("=" * 60)
        
        # Run server and traffic generator concurrently
        server_task = asyncio.create_task(self.run_server())
        traffic_task = asyncio.create_task(self.traffic_generator())
        
        # Let it run for specified duration
        await asyncio.sleep(duration_seconds)
        
        # Shutdown
        self.running = False
        traffic_task.cancel()
        server_task.cancel()
        
        try:
            await asyncio.gather(server_task, traffic_task, return_exceptions=True)
        except asyncio.CancelledError:
            pass
        
        logger.info("Simulation ended")


async def main():
    """Main entry point for the simulator."""
    simulator = ModbusSimulator(host='127.0.0.1', port=502)
    
    try:
        # Run for 60 seconds by default
        await simulator.run_simulation(duration_seconds=60)
    except KeyboardInterrupt:
        logger.info("Simulation interrupted by user")
    except Exception as e:
        logger.error(f"Simulation error: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("GridShield Modbus TCP Simulator")
    print("=" * 60)
    print("\nRunning simulation for 60 seconds...")
    print("Press Ctrl+C to stop early\n")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nSimulation stopped")
