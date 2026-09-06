# 🧠 NeuroForensics-AI

**AI-Powered Processor & GPU Digital Forensics Platform**

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()

---

## 📋 Overview

NeuroForensics-AI is an **AI-powered digital forensics platform** designed to acquire, preserve, correlate, and analyze volatile CPU and GPU evidence for cyber investigations. Built with Rust for performance and safety, it combines traditional forensic techniques with modern AI capabilities.

### 🎯 Key Features

- ✅ **Evidence Acquisition** - Collects volatile memory evidence from CPU/GPU
- ✅ **AI-Powered Analysis** - Isolation Forest & rule-based detection
- ✅ **Explainable AI (XAI)** - Understand why decisions were made
- ✅ **Comprehensive Correlation** - Links evidence across multiple sources
- ✅ **Forensic Reporting** - Generate detailed investigation reports
- ✅ **17,000+ Lines of Rust** - Optimized for performance
- ✅ **110+ Automated Tests** - Reliable and stable codebase

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    NeuroForensics-AI Platform                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│   ┌──────────────┐                                               │
│   │     MEMO     │                                               │
│   │  Collector   │ ──► Evidence Acquisition                      │
│   └──────┬───────┘                                               │
│          │                                                       │
│          ▼                                                       │
│   ┌──────────────┐                                               │
│   │     AIF      │ ──► Evidence Container (v1)                   │
│   │  Container   │      SHA-256 Verified                         │
│   └──────┬───────┘                                               │
│          │                                                       │
│          ▼                                                       │
│   ┌──────────────┐                                               │
│   │     MEMO     │                                               │
│   │   Analyzer   │ ──► Analysis Engine                           │
│   └──────┬───────┘                                               │
│          │                                                       │
│          ▼                                                       │
│   ┌────────────────────────────────────────────────┐             │
│   │            Evidence Ingestion Pipeline           │             │
│   ├────────────────────────────────────────────────┤             │
│   │  CPU │ GPU │ Processes │ Network │ Win Events   │             │
│   └──────┬─────────────────────────────────────────┘             │
│          │                                                       │
│          ▼                                                       │
│   ┌──────────────┐                                               │
│   │ Correlation  │ ──► Connect evidence dots                     │
│   └──────┬───────┘                                               │
│          │                                                       │
│          ▼                                                       │
│   ┌──────────────┐                                               │
│   │  Detection   │ ──► Threat identification                     │
│   └──────┬───────┘                                               │
│          │                                                       │
│          ▼                                                       │
│   ┌──────────────────────┐                                       │
│   │   AI + Explainable   │ ──► Intelligent analysis               │
│   │      AI (XAI)        │      with explanations                │
│   └──────┬───────────────┘                                       │
│          │                                                       │
│          ▼                                                       │
│   ┌──────────────┐                                               │
│   │   Forensic   │ ──► Professional report generation             │
│   │    Report    │                                               │
│   └──────────────┘                                               │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📦 Components

### 🔍 MEMO Collector
**Evidence Acquisition Component**
- Collects forensic evidence from running systems
- Produces AIF v1 evidence containers
- SHA-256 integrity verification
- Captures CPU/GPU memory, processes, network, and Windows events

### 🧪 MEMO Analyzer
**Native Desktop Forensic Analysis Platform**
- Built with Rust, egui/eframe, and SQLite
- AI-powered evidence analysis
- Correlation engine for connecting evidence
- Detection algorithms for threat identification
- Explainable AI for decision transparency
- Professional forensic report generation

---

## 🛠️ Technology Stack

| Component | Technology |
|-----------|------------|
| **Language** | Rust 🦀 |
| **GUI Framework** | egui/eframe |
| **Database** | SQLite |
| **Evidence Format** | AIF v1 |
| **Integrity** | SHA-256 |
| **AI/ML** | Isolation Forest |
| **Detection** | Rule-based + AI |
| **Explainability** | XAI techniques |
| **Testing** | 110+ automated tests |

---

## 📊 Project Status

| Metric | Value |
|--------|-------|
| **Lines of Code** | 17,237+ (Rust) |
| **Automated Tests** | 110+ |
| **Development Phases** | 8 ✅ |
| **Project ID** | P01615 |
| **Institution** | NRA CYBERTECH |

### ✅ Completed Features

- [x] CPU Evidence Collection
- [x] GPU Evidence Collection
- [x] Process Analysis
- [x] Network Analysis
- [x] Windows Events
- [x] Persistence Mechanisms
- [x] Evidence Correlation
- [x] Threat Detection
- [x] AI Integration (Isolation Forest)
- [x] Explainable AI (XAI)
- [x] Forensic Report Generation
- [x] AIF v1 Evidence Container

---

## 🚀 Getting Started

### Prerequisites

- **Rust** (1.70+)

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- **SQLite** (3.x or later)
- **Git**

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/<your-org>/NeuroForensics-AI.git
   cd NeuroForensics-AI
   ```

2. Build the project in release mode:

   ```bash
   cargo build --release
   ```

3. Run the test suite to verify your build:

   ```bash
   cargo test
   ```

4. Run the components:

   ```bash
   # Evidence collector
   cargo run --release --bin memo-collector

   # Forensic analyzer (GUI)
   cargo run --release --bin memo-analyzer
   ```

### Basic Usage

```bash
# Acquire evidence from the current system and produce an AIF v1 container
memo-collector --output ./evidence/case-001.aif

# Open the container in the analyzer for correlation, detection, and reporting
memo-analyzer --input ./evidence/case-001.aif
```

---

## 📁 Project Structure

```
NeuroForensics-AI/
├── memo-collector/       # Evidence acquisition component
├── memo-analyzer/        # Analysis, correlation, detection & reporting engine
├── aif-container/        # AIF v1 evidence container format & SHA-256 verification
├── docs/                 # Documentation
├── tests/                # Automated test suite (110+ tests)
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🏛️ Acknowledgments

Developed as part of Project P01615 at NRA CYBERTECH.
