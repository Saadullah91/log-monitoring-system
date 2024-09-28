# log-monitoring-system


## 1. Introduction
The SOC Agent is a custom-built solution designed to collect logs from various sources, analyze them for vulnerabilities, and scan for malware. The system consists of three main components: the SOC agent, a vulnerability scanner, and a malware scanner. It provides real-time security monitoring and alerting capabilities, making it a comprehensive tool for cybersecurity operations.

## 2. System Overview
The system is designed to:
- **Collect Logs**: Gather log data from various sources, including Windows and Linux systems.
- **Vulnerability Detection**: Scan the collected logs for known vulnerabilities using a set of predefined rules.
- **Malware Detection**: Detect potential malware signatures in the log data to prevent security breaches.
- **Real-time Monitoring**: Provide real-time monitoring and alerting of security events.

## 3. Components

### 3.1 SOC Agent
The SOC Agent is responsible for:
- Collecting log data from multiple sources.
- Sending the collected logs to the vulnerability scanner and malware scanner for analysis.
- Acting as a central interface for configuring the other components.

**Features**:
- Supports both Windows and Linux log sources.
- Configurable to include/exclude specific log sources.
- Integration with vulnerability and malware scanners for comprehensive analysis.

### 3.2 Vulnerability Scanner
The Vulnerability Scanner analyzes the collected logs to detect known vulnerabilities based on predefined rules and signatures. It uses:
- **Predefined Rules**: A set of rules derived from sources like Wazuh to identify vulnerabilities in the logs.
- **Custom Rules**: Users can define their own rules to detect specific vulnerabilities.

**Features**:
- Scans logs in real-time.
- Provides detailed reports on detected vulnerabilities.
- Configurable to include or exclude specific rules.

### 3.3 Malware Scanner
The Malware Scanner scans the collected logs for known malware signatures. It performs:
- **Signature-based Detection**: Uses predefined malware signatures to detect potential threats.
- **Heuristic Analysis**: Analyzes the behavior patterns in the logs to identify potential malware.

**Features**:
- Real-time malware detection.
- Generates alerts when malware is detected.
- Can be configured to perform scheduled scans.

## 4. Architecture
1. **Log Collection**:
   - The SOC Agent collects logs from specified sources (Windows/Linux).
2. **Data Flow**:
   - The collected logs are passed to the Vulnerability Scanner for vulnerability detection.
   - The logs are also passed to the Malware Scanner for malware detection.
3. **Analysis and Alerting**:
   - The results from both scanners are aggregated and analyzed.
   - Alerts are generated if any vulnerabilities or malware are detected.
4. **User Interface**:
   - The system provides a command-line interface for configuration and management.

## 5. Installation and Configuration

### Prerequisites
- **Operating System**: Linux or Windows.
- **Dependencies**:
  - gcc compiler for compiling the source code.
  - Access to log files or systems generating logs.

### Execution
1. **Compile the Source Code**:
   ```bash
   gcc -c scanner.c -o scanner.o
   gcc -c malware_detector.c -o malware_detector.o
   gcc -c agent.c -o agent.o
   gcc agent.o scanner.o malware_detector.o -o log_monitor
   ```
2. **Run the SOC Agent**:
   ```bash
   ./log_monitor
   ```

### Configuration
Modify the configuration settings in the `config.h` file to specify:
- Log sources.
- Vulnerability scanning rules.
- Malware signatures.

## 6. Usage
To run the SOC Agent with the default settings, execute:
```bash
./log_monitor
```

### Command-Line Options
- `-s`: Start the SOC Agent.
- `-v`: Display the version information.
- `-c <config_file>`: Use the specified configuration file.

## 7. Code Structure
The project is organized as follows:

```
agent_project/
├── agent.c                # SOC Agent main logic
├── scanner.c              # Vulnerability Scanner
├── malware_detector.c      # Malware Scanner
├── config.h               # Configuration header file
├── rules/                 # Directory containing vulnerability rules
│   └── custom_rules.txt    # Custom vulnerability rules
├── signatures/            # Directory containing malware signatures
│   └── malware_signatures.txt # Malware signature definitions
└── logs/                  # Directory containing collected logs
    └── log_file.txt       # Sample log file
```

### File Descriptions
- `agent.c`: Contains the core logic for the SOC agent, including log collection and communication with the scanners.
- `scanner.c`: Implements the vulnerability scanning functionality.
- `malware_detector.c`: Implements the malware detection functionality.
- `config.h`: Configuration file for setting up log sources and scanning rules.

## 8. Examples

### Basic Example
```bash
./log_monitor
```

### Custom Configuration
To use a custom configuration file:
```bash
./log_monitor -c custom_config.h
```

## 9. Future Enhancements
- **Web Interface**: Adding a web-based interface for easier management and monitoring.
- **Machine Learning Integration**: Using machine learning algorithms for anomaly detection.
- **Distributed Architecture**: Supporting distributed agents for larger environments.

## 10. Troubleshooting

### Common Issues
1. **Compilation Errors**:
   - Ensure all dependencies are installed (gcc).
   - Check the paths to the source files and include headers.
2. **Log Collection Issues**:
   - Verify the log sources are correctly configured in `config.h`.
   - Check for permission issues when accessing log files.
3. **Scanner Not Detecting Issues**:
   - Ensure the rules and signatures are up-to-date.
   - Verify that the logs contain data that matches the rule criteria.
