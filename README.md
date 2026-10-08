AI-SIEM
A Python-based Security Information and Event Management (SIEM) project focused on security event detection, correlation, alerting, and incident management.

This project is being developed as a hands-on exploration of how SIEM detection and response pipelines can be designed and implemented from the ground up.

Phase 1 Checkpoint

Status: Working Phase 1 checkpoint

90 automated tests passing
Working detection and correlation pipeline
Unified alert generation
Incident management
Entity tracking
MITRE ATT&CK technique mapping
Automated test coverage across the detection pipeline
The project is actively under development and is not intended to be presented as a production-ready SIEM.

Current Capabilities

Detection

The current detection pipeline includes:

Sliding-window brute-force detection
Burst detection
Event ordering
Event normalization
Detection rule loading
Risk scoring
Correlation

Security events can be correlated across the detection pipeline.

One implemented flow is:

Failed login attempts
        ↓
Brute-force detection
        ↓
Successful login
        ↓
Event correlation
        ↓
Unified alert
        ↓
Incident
This allows related security events to be combined into a more meaningful security signal rather than treating every event independently.

Alerting

The project includes a unified alert pipeline with:

Alert generation
Alert lifecycle management
Alert deduplication
Severity handling
Detection-to-alert processing
Incident Management

The incident management layer provides:

Incident creation
Incident lifecycle handling
Severity escalation
Correlation of related alerts
Entity Tracking

The project tracks entities involved in security events to support investigation and correlation across the detection pipeline.

MITRE ATT&CK Mapping

Detection results can be associated with MITRE ATT&CK techniques to provide security context for detected activity.

Project Structure

AI-SIEM/
├── main.py
├── .gitignore
├── README.md
├── rules/
├── siem/
├── simulations/
└── tests/
Testing

Testing is an important part of the project.

The current Phase 1 checkpoint has:

90 tests passing

The test suite covers components including:

Brute-force detection
Burst detection
Event ordering
Correlation
Detection management
Detection pipelines
Alert generation
Alert deduplication
Alert lifecycle
Incident management
Risk scoring
End-to-end Phase 1 behavior
To run the test suite:

pytest
Running the Project

Clone the repository:

git clone https://github.com/RahatBhia1993/AI-SIEM.git
cd AI-SIEM
Then run:

pytest
The project also includes a brute-force simulation:

simulations/brute_force_simulation.py
Development History

The repository preserves the project's development history, including the Phase 1 Week 2 checkpoint.

A notable milestone is the week2-complete Git tag.

The current branch contains the clean Phase 1 detection and correlation checkpoint.

Current Status

This project is under active development.

The current focus is building and testing the core SIEM architecture, including:

Security event detection
Event normalization
Event correlation
Alert generation
Alert deduplication
Incident management
Entity tracking
Risk scoring
Future development will continue expanding the detection pipeline, improving security analysis capabilities, and adding additional SIEM functionality.

Disclaimer

This project is a learning and development project intended to explore SIEM architecture and security engineering concepts.

It should not currently be considered a production-ready security monitoring platform.

Author

Rahat Bhatia

Built as a hands-on security engineering project focused on Python, detection engineering, SIEM architecture, and defensive security