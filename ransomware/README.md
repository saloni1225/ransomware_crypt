# SentinelCrypt EDR

A ransomware detection and response platform designed to identify suspicious file activity, detect ransomware behavior in real time, generate alerts, and provide actionable response recommendations through an interactive dashboard.

---

## 📌 Overview

Ransomware attacks continue to be one of the most damaging cybersecurity threats. Traditional antivirus solutions often rely on signatures and may fail to detect new or evolving ransomware variants.

The SentinelCrypt EDR platform adopts a behavior-based detection approach that continuously monitors system activity, analyzes file operations, evaluates entropy changes, detects anomalies, and provides real-time threat intelligence through a centralized dashboard.

The platform combines:

* Real-time monitoring
* Behavioral analysis
* Entropy-based detection
* Canary file protection
* Threat visualization
* Alert management
* Automated response recommendations

---

## 🎯 Objectives

* Detect ransomware activity before significant damage occurs.
* Monitor suspicious file modifications and process behavior.
* Identify abnormal encryption patterns using entropy analysis.
* Generate real-time alerts and threat scores.
* Visualize attack timelines and system health.
* Provide incident response recommendations.
* Demonstrate modern Endpoint Detection and Response (EDR) concepts.

---

# 🏗️ System Architecture

```text
Agent Layer
     │
     ▼
Detection Engine
     │
     ▼
Decision Engine
     │
     ▼
Backend API
     │
     ▼
WebSocket Service
     │
     ▼
Frontend Dashboard
```

### Components

#### Agent Layer

Responsible for collecting system events and monitoring:

* File system activity
* Process activity
* Entropy changes
* Canary file access
* Suspicious behavior indicators

#### Detection Layer

Analyzes collected telemetry using:

* Entropy analysis
* Behavioral rules
* Anomaly detection
* Canary triggers

#### Decision Engine

Calculates:

* Risk score
* Threat severity
* Alert priority
* Response actions

#### Backend Layer

Provides:

* Detection APIs
* Alert management
* WebSocket communication
* Threat storage

#### Frontend Layer

Provides:

* Real-time monitoring dashboard
* Threat timeline visualization
* System health overview
* Alert management
* Response controls

---

# 📂 Project Structure

```text
ransomware-defense/
│
├── agent/
├── backend/
├── frontend/
├── simulator/
├── tests/
├── docs/
└── docker-compose.yml
```

---

# ⚙️ Key Features

## Real-Time File Monitoring

Continuously monitors:

* File creation
* File modification
* File deletion
* Mass file operations

---

## Entropy-Based Detection

Detects potential encryption activity by analyzing entropy changes within files.

Used to identify:

* Encrypted files
* Ransomware encryption patterns
* Sudden entropy spikes

---

## Behavioral Analysis

Monitors:

* File access frequency
* Rapid file modifications
* Process behavior
* Suspicious execution patterns

---

## Canary File Protection

Special decoy files are placed within monitored directories.

If accessed or modified:

* Immediate alert generated
* High-risk event created
* Potential ransomware activity flagged

---

## Threat Timeline

Displays:

* Detection events
* File activity
* Alert generation
* Response actions

Providing a complete attack narrative.

---

## Live Alert System

Real-time notifications using WebSockets.

Alert categories:

* Critical
* High
* Medium
* Low

---

## Response Center

Provides response recommendations:

* Investigate process
* Terminate suspicious process
* Isolate endpoint
* Review affected files

---

## Threat Forecasting

Analyzes historical events and threat trends to estimate future risk levels.

---

# 🛠️ Technology Stack

## Frontend

* React.js
* JavaScript
* CSS
* WebSocket Client

## Backend

* FastAPI
* Python
* REST APIs
* WebSockets

## Detection Engine

* Python
* Watchdog
* Entropy Analysis
* Behavioral Detection

## Containerization

* Docker
* Docker Compose

## Testing

* Pytest

---

#  Dashboard Modules

### System Health

Displays:

* CPU status
* Monitoring status
* Agent connectivity
* Detection engine health

### Risk Meter

Shows:

* Current risk level
* Threat score
* Severity status

### Threat Timeline

Visual representation of:

* Events
* Alerts
* Responses

### Activity Graph

Shows trends of:

* File operations
* Threat detections
* Alert frequency

### Alert Center

Provides:

* Active alerts
* Historical alerts
* Severity classification

---

# 🔄 Detection Workflow

```text
File Activity
      │
      ▼
Feature Extraction
      │
      ▼
Entropy Analysis
      │
      ▼
Anomaly Detection
      │
      ▼
Decision Engine
      │
      ▼
Alert Generation
      │
      ▼
Dashboard Notification
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/anmoliot/ransomware-defense-system.git
cd ransomware-defense
```

## Start Services

```bash
docker-compose up --build
```

## Backend

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

## Frontend

```bash
cd frontend
npm install
npm run dev
```

---

# 🧪 Running Tests

```bash
pytest tests/
```

---

# 🎮 Simulation

A ransomware simulator is included for safe testing.

```bash
python simulator/ransomware_simulator.py
```

The simulator generates controlled ransomware-like behavior for demonstrating detection capabilities.

---

# 🔐 Security Features

* Real-time ransomware detection
* Entropy-based analysis
* Behavioral monitoring
* Canary file protection
* Threat scoring
* WebSocket alerting
* Incident response recommendations

---

# 📈 Future Enhancements

* Machine Learning threat classification
* Heuristic threat reasoning
* Attack storyline visualization
* Automatic process isolation
* Cloud-based threat intelligence
* Endpoint trust scoring
* Multi-device management
* Centralized security dashboard

---

# License

This project is developed for academic and research purposes.

---

## Authors

Cybersecurity Engineering Project

SentinelCrypt EDR – Real-Time Detection and Response Platform
