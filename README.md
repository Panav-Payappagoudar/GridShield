# GridShield - Semantic Firewall for Power Grid Protection

## Overview

GridShield is a **semantic firewall** that provides Deep Packet Inspection (DPI) for industrial Modbus TCP protocols used in power grid operations. It intercepts, analyzes, and validates Modbus commands in real-time to protect against cyber attacks targeting physical infrastructure.

## Features

✅ **Protocol-Aware DPI** - Decodes Modbus TCP payloads extracting function codes and register values  
✅ **Semantic Validation** - Validates commands against safety invariants (voltage, frequency, current bounds)  
✅ **Fail-Open Mechanism** - Automatically enters monitoring-only mode during grid emergencies (<59.5 Hz)  
✅ **SIEM Integration** - Generates structured JSON alerts compatible with ELK stack  
✅ **Non-Dropping Capture** - Uses Scapy for passive packet capture without loss  
✅ **Asyncio Architecture** - Low-latency processing using Python asyncio  

## Project Structure

```
gridshield-mvp/
├── .devcontainer/
│   └── devcontainer.json       # GitHub Codespaces configuration
├── core/
│   ├── __init__.py
│   ├── sniffer.py              # Scapy-based packet capture on port 502
│   ├── parser.py               # Modbus protocol decoder
│   ├── rules_engine.py         # Semantic validation logic
│   └── action.py               # SIEM alert generator
├── config/
│   └── safety_rules.json       # Configurable safety bounds
├── utils/
│   └── fail_open.py            # Fail-open mechanism implementation
├── simulator/
│   └── modbus_sim.py           # Test traffic generator (normal + malicious)
├── main.py                     # Main orchestrator
└── requirements.txt            # Python dependencies
```

## Quick Start

### Prerequisites

- Python 3.9+
- Linux/Unix environment (for loopback interface access)
- Root/sudo privileges

### Installation

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Run GridShield (Terminal 1):**
```bash
sudo python3 main.py
```

3. **Generate test traffic (Terminal 2):**
```bash
sudo python3 simulator/modbus_sim.py
```

## How It Works

### Data Flow Pipeline

```
[Modbus TCP Traffic] 
    ↓
[Sniffer] → Captures packets on port 502 via loopback interface
    ↓
[Parser] → Extracts Function Code, Register Addresses, Values
    ↓
[Rules Engine] → Validates against safety bounds
    ↓
[Action Generator] → Creates JSON alerts for SIEM
    ↓
[Fail-Open Logic] → Determines block vs monitor based on grid state
```

### Operational Modes

**NORMAL Mode:**
- Active blocking of policy violations
- Commands exceeding bounds are dropped
- High-priority alerts generated

**SHADOW Mode (Fail-Open):**
- Triggered when grid frequency < 59.5 Hz
- All commands allowed (monitoring only)
- Alerts still generated but NOT blocked
- Prevents interference during emergency conditions

## Configuration

Edit `config/safety_rules.json` to customize:

- **Frequency threshold** (default: 59.5 Hz)
- **Allowed/blocked function codes**
- **Register bounds** (voltage: 0-500V, frequency: 55-65Hz, etc.)
- **Rate limits** (max 10 write commands/second)

## Testing Scenarios

The simulator generates three scenarios:

1. **Normal Operation** ✓
   - Safe voltage/frequency setpoints
   - Standard read/write operations

2. **Malicious Attacks** ⚠
   - Out-of-bounds voltage (>500V)
   - Dangerous frequency (<55Hz or >65Hz)
   - Multiple register writes with extreme values

3. **Grid Emergency / Fail-Open** 🚨
   - Frequency drops below 59.5 Hz
   - System enters SHADOW mode
   - Commands allowed that would normally be blocked

## Output Format

GridShield generates structured JSON logs:

```json
{
  "timestamp": "2026-03-11T12:34:56Z",
  "event_id": "GS-000001",
  "event_type": "MODBUS_VIOLATION",
  "severity": "CRITICAL",
  "violation": {
    "reason": "REGISTER_BOUNDS_VIOLATION",
    "action_taken": "BLOCKED"
  },
  "modbus_data": {
    "function_code": 6,
    "register_address": 0,
    "data_values": [650]
  },
  "grid_state": {
    "frequency_hz": 60.0,
    "mode": "NORMAL"
  }
}
```

## Deployment in GitHub Codespaces

1. Create a new Codespace from your repository
2. The `.devcontainer/devcontainer.json` will automatically:
   - Install Python 3.9+
   - Install Scapy and PyModbus
   - Configure network tools

3. Run the system as shown above

## Production Considerations

For production deployment:

- **Network Tapping**: Use port mirroring/SPAN instead of loopback capture
- **High Availability**: Deploy redundant GridShield instances
- **SIEM Integration**: Configure `action.py` to send alerts to your SIEM via HTTP webhook
- **Logging**: Forward JSON logs to Elasticsearch/Logstash
- **Monitoring**: Integrate with SCADA system for real-time grid frequency data

## Security Notes

⚠️ **WARNING**: This is an MVP for hackathon purposes. Production deployment requires:
- Additional hardening
- Formal verification of safety logic
- Compliance with IEC 62351 and NERC CIP standards
- Redundant fail-safe mechanisms

## License

MIT License - See LICENSE file

## Hackathon Team

Built for 24-hour ICS/OT Cybersecurity Hackathon  
GridShield Team - Protecting Critical Infrastructure
