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

## Extensibility

### Custom Analyzers
You can extend the tool by creating custom analyzers and plugins. Example:

```python
from forensics_tool.extensions import ExtendedForensicsTool

class MyCustomAnalyzer(ExtendedForensicsTool):
    def custom_analysis(self):
        # Add your custom analysis logic
        pass
```

### Plugin Architecture
The tool supports easy plugin integration:
1. Create a new plugin class
2. Inherit from base analyzers
3. Implement custom analysis methods

## Advanced Features

### File Analysis
- Comprehensive file metadata extraction
- Advanced file type detection
- Optional malware scanning with VirusTotal

### Network Analysis
- Detailed network interface scanning
- Connection tracking
- DNS cache analysis

### Memory Forensics
- Process enumeration
- Suspicious process detection
- Memory usage analysis

## PDF Forensics Plugin

### Advanced PDF Analysis Capabilities

The PDF Forensics Plugin provides comprehensive PDF file analysis:

#### Features
- 📄 Detailed PDF Metadata Extraction
- 🔒 Encryption and Security Analysis
- 🕵️ Structural File Inspection
- 🚨 Potential Risk Identification

#### Example Usage
```python
from pdf_forensics_plugin import PDFForensicsTool

# Create PDF forensics tool
pdf_tool = PDFForensicsTool()

# Scan a directory for PDF files
pdf_results = pdf_tool.pdf_forensic_scan('~/Documents')

# Analyze results
for result in pdf_results:
    print(f"File: {result['file_path']}")
    print(f"Potential Risks: {result['potential_risks']}")
```

#### Detailed Analysis Includes:
- File Metadata
  - Title, Author, Creator
  - Creation and Modification Dates
  - PDF Version
- Encryption Status
- Structural Integrity
- Potential Security Risks
  - Suspicious Metadata
  - Unusual Object Counts
  - Potential Embedded JavaScript

## Configuration

### Configuration File
Create a `config.ini` to customize tool behavior:
```ini
[Scanning]
max_depth = 3
timeout = 2.0

[Logging]
level = INFO
```

## Security Considerations
- Avoid scanning sensitive system directories
- Use API keys securely
- Run with appropriate permissions

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push and create a pull request

## License
[Specify your license]

## Disclaimer
This tool is for educational and authorized use only. Always obtain proper permissions before conducting forensic analysis.
