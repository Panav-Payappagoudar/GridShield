"""
Modbus TCP Sniffer
==================
Uses Scapy and asyncio to passively capture Modbus TCP traffic on port 502 
via the loopback ('lo') interface without dropping packets.

Key Features:
- Non-intrusive packet capture using Scapy's sniff()
- Asyncio integration for low-latency processing
- Thread-safe packet queue for concurrent processing
- Runs on loopback interface to intercept local Modbus traffic
"""

import asyncio
from scapy.all import sniff, TCP, conf
from threading import Thread
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ModbusSniffer:
    """
    Passive Modbus TCP packet sniffer for port 502 on loopback interface.
    
    This class implements non-dropping packet capture using Scapy's sniff() 
    function in a separate thread to maintain asyncio event loop compatibility.
    """
    
    def __init__(self, interface='lo', port=502, packet_queue=None):
        """
        Initialize the Modbus sniffer.
        
        Args:
            interface (str): Network interface to sniff on (default: 'lo' for loopback)
            port (int): Modbus TCP port to filter (default: 502)
            packet_queue (asyncio.Queue): Queue for passing captured packets to parser
        """
        self.interface = interface
        self.port = port
        self.packet_queue = packet_queue or asyncio.Queue()
        self.sniffing = False
        self.sniffer_thread = None
        
        # Disable Scapy's verbose output for production
        conf.verb = 0
        
    def _packet_callback(self, packet):
        """
        Callback function invoked by Scapy for each captured packet.
        
        This method is called in the sniffer thread context and forwards
        packets to the asyncio queue for processing.
        
        Args:
            packet (scapy.Packet): Captured network packet
        """
        if packet.haslayer(TCP) and packet[TCP].dport == self.port:
            logger.debug(f"Captured Modbus packet from {packet[IP].src}:{packet[TCP].sport}")
            
            # Use asyncio.run_coroutine_threadsafe for thread-safe queue operation
            if self.packet_queue:
                asyncio.run_coroutine_threadsafe(
                    self.packet_queue.put(packet),
                    asyncio.get_event_loop()
                )
    
    def start_sniffing(self):
        """
        Start the packet capture process in a background thread.
        
        This method creates a daemon thread that runs Scapy's sniff() function
        continuously. The thread filters for TCP packets on port 502.
        """
        if self.sniffing:
            logger.warning("Sniffer already running")
            return
            
        self.sniffing = True
        
        # Create BPF filter for Modbus TCP port 502
        bpf_filter = f"tcp port {self.port}"
        
        # Start sniffer in separate thread to avoid blocking asyncio
        self.sniffer_thread = Thread(
            target=lambda: sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self._packet_callback,
                store=False,  # Don't store packets in memory
                stop_filter=lambda x: not self.sniffing
            ),
            daemon=True
        )
        
        self.sniffer_thread.start()
        logger.info(f"Started sniffing on interface '{self.interface}' for port {self.port}")
    
    def stop_sniffing(self):
        """
        Stop the packet capture process.
        
        Sets the sniffing flag to False which triggers the sniffer thread to exit.
        """
        self.sniffing = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2.0)
            logger.info("Sniffer stopped")
    
    async def get_packet(self):
        """
        Asynchronously retrieve the next captured packet from the queue.
        
        Returns:
            scapy.Packet: The next captured Modbus TCP packet
        """
        return await self.packet_queue.get()
    
    def get_queue_size(self):
        """
        Get the current number of packets waiting in the queue.
        
        Returns:
            int: Number of queued packets
        """
        return self.packet_queue.qsize()


# Import IP at module level for packet callback
from scapy.all import IP
