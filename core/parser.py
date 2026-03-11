"""
Modbus Protocol Parser
======================
Decodes Modbus TCP payloads extracting Function Codes, Register addresses, 
and Data Values from captured packets.

Key Features:
- Extracts Modbus Application Protocol (MBAP) header
- Parses PDU (Protocol Data Unit) for function codes
- Decodes read/write register operations
- Handles exception responses
"""

from scapy.all import Raw
import struct
import logging

logger = logging.getLogger(__name__)


class ModbusParser:
    """
    Modbus TCP protocol decoder and dissection engine.
    
    This class extracts semantic information from Modbus TCP packets including:
    - Transaction ID (for request-response correlation)
    - Unit ID (device identifier)
    - Function Code (operation type)
    - Register addresses and values
    """
    
    # Modbus Function Codes
    FUNCTION_CODES = {
        0x01: "Read Coils",
        0x02: "Read Discrete Inputs",
        0x03: "Read Holding Registers",
        0x04: "Read Input Registers",
        0x05: "Write Single Coil",
        0x06: "Write Single Register",
        0x0F: "Write Multiple Coils",
        0x10: "Write Multiple Registers",
    }
    
    def __init__(self):
        """Initialize the Modbus parser."""
        self.transaction_history = {}
    
    def parse_packet(self, packet):
        """
        Parse a Modbus TCP packet and extract semantic information.
        
        Args:
            packet (scapy.Packet): Captured network packet with TCP payload
            
        Returns:
            dict: Extracted Modbus information or None if parsing fails
        """
        if not packet.haslayer(Raw):
            return None
        
        try:
            raw_data = bytes(packet[Raw].load)
            
            # Modbus TCP requires at least 7 bytes for MBAP header
            if len(raw_data) < 7:
                logger.debug(f"Packet too short for Modbus TCP: {len(raw_data)} bytes")
                return None
            
            # Parse MBAP (Modbus Application Protocol) header
            mbap_header = self._parse_mbap(raw_data[:7])
            
            # Parse PDU (Protocol Data Unit)
            pdu_data = raw_data[7:]
            pdu = self._parse_pdu(pdu_data, mbap_header['function_code'])
            
            if pdu is None:
                return None
            
            # Combine header and PDU information
            result = {
                'transaction_id': mbap_header['transaction_id'],
                'protocol_id': mbap_header['protocol_id'],
                'length': mbap_header['length'],
                'unit_id': mbap_header['unit_id'],
                'function_code': mbap_header['function_code'],
                'function_name': self.FUNCTION_CODES.get(
                    mbap_header['function_code'], 
                    f"Unknown ({mbap_header['function_code']})"
                ),
                **pdu
            }
            
            logger.debug(f"Parsed Modbus: FC={result['function_code']} ({result['function_name']})")
            return result
            
        except Exception as e:
            logger.error(f"Error parsing Modbus packet: {e}")
            return None
    
    def _parse_mbap(self, header_bytes):
        """
        Parse the 7-byte MBAP header.
        
        MBAP Header Structure:
        - Bytes 0-1: Transaction ID (16-bit)
        - Bytes 2-3: Protocol ID (16-bit, always 0 for Modbus)
        - Bytes 4-5: Length (16-bit, remaining bytes count)
        - Byte 6: Unit ID (8-bit, slave device address)
        
        Args:
            header_bytes (bytes): 7-byte MBAP header
            
        Returns:
            dict: Parsed MBAP header fields
        """
        transaction_id, protocol_id, length, unit_id = struct.unpack('>HHHB', header_bytes)
        
        return {
            'transaction_id': transaction_id,
            'protocol_id': protocol_id,
            'length': length,
            'unit_id': unit_id
        }
    
    def _parse_pdu(self, pdu_bytes, function_code):
        """
        Parse the Protocol Data Unit (PDU) based on function code.
        
        Args:
            pdu_bytes (bytes): PDU data after MBAP header
            function_code (int): Modbus function code
            
        Returns:
            dict: Parsed PDU fields or None if unsupported
        """
        if len(pdu_bytes) < 1:
            return None
        
        # Check for exception response (function code + 0x80)
        if function_code > 0x80:
            exception_code = pdu_bytes[0] if len(pdu_bytes) > 0 else 0
            return {
                'is_exception': True,
                'exception_code': exception_code,
                'data_values': []
            }
        
        # Parse based on function code type
        if function_code in [0x03, 0x04]:  # Read Holding/Input Registers
            return self._parse_read_registers(pdu_bytes, function_code)
        elif function_code == 0x06:  # Write Single Register
            return self._parse_write_single_register(pdu_bytes)
        elif function_code == 0x10:  # Write Multiple Registers
            return self._parse_write_multiple_registers(pdu_bytes)
        elif function_code in [0x01, 0x02]:  # Read Coils/Discrete Inputs
            return self._parse_read_coils(pdu_bytes, function_code)
        elif function_code == 0x05:  # Write Single Coil
            return self._parse_write_single_coil(pdu_bytes)
        elif function_code == 0x0F:  # Write Multiple Coils
            return self._parse_write_multiple_coils(pdu_bytes)
        else:
            logger.debug(f"Unsupported function code: {function_code}")
            return {'data_values': [], 'register_address': None}
    
    def _parse_read_registers(self, pdu_bytes, function_code):
        """Parse Read Holding/Input Registers request/response."""
        if len(pdu_bytes) >= 5:
            start_address, quantity = struct.unpack('>HH', pdu_bytes[1:5])
            return {
                'register_address': start_address,
                'quantity': quantity,
                'data_values': list(struct.unpack('>' + 'H' * quantity, pdu_bytes[2:2+quantity*2])) 
                    if len(pdu_bytes) > 5 else []
            }
        return {'register_address': None, 'quantity': 0, 'data_values': []}
    
    def _parse_write_single_register(self, pdu_bytes):
        """Parse Write Single Register request."""
        if len(pdu_bytes) >= 5:
            register_address, value = struct.unpack('>HH', pdu_bytes[1:5])
            return {
                'register_address': register_address,
                'value': value,
                'data_values': [value]
            }
        return {'register_address': None, 'value': 0, 'data_values': []}
    
    def _parse_write_multiple_registers(self, pdu_bytes):
        """Parse Write Multiple Registers request."""
        if len(pdu_bytes) >= 6:
            start_address, quantity, byte_count = struct.unpack('>HHB', pdu_bytes[1:6])
            values = []
            if byte_count > 0:
                values = list(struct.unpack('>' + 'H' * (byte_count // 2), pdu_bytes[6:6+byte_count]))
            return {
                'register_address': start_address,
                'quantity': quantity,
                'data_values': values
            }
        return {'register_address': None, 'quantity': 0, 'data_values': []}
    
    def _parse_read_coils(self, pdu_bytes, function_code):
        """Parse Read Coils/Discrete Inputs request."""
        if len(pdu_bytes) >= 5:
            start_address, quantity = struct.unpack('>HH', pdu_bytes[1:5])
            return {
                'coil_address': start_address,
                'quantity': quantity,
                'data_values': []
            }
        return {'coil_address': None, 'quantity': 0, 'data_values': []}
    
    def _parse_write_single_coil(self, pdu_bytes):
        """Parse Write Single Coil request."""
        if len(pdu_bytes) >= 5:
            coil_address, value = struct.unpack('>HH', pdu_bytes[1:5])
            return {
                'coil_address': coil_address,
                'value': 0xFF00 if value == 0xFF00 else 0x0000,  # ON=0xFF00, OFF=0x0000
                'data_values': [value]
            }
        return {'coil_address': None, 'value': 0, 'data_values': []}
    
    def _parse_write_multiple_coils(self, pdu_bytes):
        """Parse Write Multiple Coils request."""
        if len(pdu_bytes) >= 6:
            start_address, quantity, byte_count = struct.unpack('>HHB', pdu_bytes[1:6])
            return {
                'coil_address': start_address,
                'quantity': quantity,
                'data_values': list(pdu_bytes[6:6+byte_count]) if byte_count > 0 else []
            }
        return {'coil_address': None, 'quantity': 0, 'data_values': []}
    
    def is_write_operation(self, parsed_data):
        """
        Check if the parsed Modbus operation is a write command.
        
        Args:
            parsed_data (dict): Parsed Modbus packet data
            
        Returns:
            bool: True if this is a write operation
        """
        write_function_codes = [0x05, 0x06, 0x0F, 0x10]
        return parsed_data.get('function_code') in write_function_codes
