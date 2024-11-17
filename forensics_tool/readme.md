# Advanced Forensics Triage Tool

## Overview
A comprehensive, flexible, and extensible forensics analysis tool designed for in-depth system, network, and memory investigations.

## Features
- 🔍 Multi-dimensional forensic scanning
- 🛡️ Modular and extensible architecture
- 📊 Detailed reporting and visualization
- 🚀 Advanced analysis capabilities

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup
```bash
# Clone th[e repository
git clone https://github.com/Ferny-erx/Triage_tool_backend.git
cd forensics-tool

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Scanning
```bash
# Perform a full system scan
python main.py --scan-type all

# Scan specific network range
python main.py --scan-type network --target 192.168.1.0/24

# Memory analysis
python main.py --scan-type memory
```

### Advanced Options
```bash
# Deep file analysis with extended capabilities
python main.py --scan-type system --max-depth 5

# Customize logging and output
python main.py --log-level DEBUG --output-dir /path/to/results
```



## License
[MIT license]


