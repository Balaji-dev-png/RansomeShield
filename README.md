# RansomShield — Capstone Architecture & Deployment Guide

RansomShield is a cross-platform (Windows & Linux) Endpoint Detection & Response (EDR) agent engineered to trap, detect, and decapitate ransomware attacks with zero data loss.

---

## 1. System Architecture

```
                  ┌──────────────────────────────────────────┐
                  │          Monitored Endpoint              │
                  │  (User Docs, Desktop, Downloads)         │
                  └────────────────────┬─────────────────────┘
                                       │ Traps traversal
                                       ▼
                  ┌──────────────────────────────────────────┐
                  │ CanaryManager: Honeypot Decoys           │
                  │ (_00_confidential.docx, ZZ_passwords...) │
                  └────────────────────┬─────────────────────┘
                                       │ Kernel hook trigger (eBPF / ETW)
                                       ▼
                  ┌──────────────────────────────────────────┐
                  │ EntropyAnalyzer (4KB Discrete Blocks)    │
                  │ H(X) >= 7.2 bits (AES/ChaCha detection)  │
                  └─────────┬──────────────────────┬─────────┘
                            │                      │
             Entropy < 7.2  │                      │ Entropy >= 7.2
                            ▼                      ▼
                     [Stand Down]        ┌───────────────────────────────┐
                                         │ MitigationEngine: Decapitate  │
                                         │ SIGKILL / TerminateProcess    │
                                         └──────────────┬────────────────┘
                                                        │
                                                        ▼
                                         ┌───────────────────────────────┐
                                         │ RollbackCache: In-Memory CoW  │
                                         │ Atomic restore over canary    │
                                         └──────────────┬────────────────┘
                                                        │
                                                        │ JSON WebSocket Telemetry
                                                        ▼
                                         ┌───────────────────────────────┐
                                         │ FastAPI Backend (/ws/agent)   │
                                         │ PostgreSQL (asyncpg ORM)      │
                                         └──────────────┬────────────────┘
                                                        │
                                                        │ Fanout WebSocket Broadcast
                                                        ▼
                                         ┌───────────────────────────────┐
                                         │ Next.js SOC Dashboard         │
                                         │ (/ws/soc - Tailwind CSS)      │
                                         └───────────────────────────────┘
```

---

## 2. Quickstart Execution Guide

### Tier 1: C++ EDR Agent
```bash
cd agent
mkdir -p build && cd build
cmake .. -DCMAKE_CXX_STANDARD=17
make -j$(nproc)

# Run agent with elevated privileges (needed for process termination & hooks)
sudo ./ransomshield-agent
```

### Tier 2: FastAPI Backend & PostgreSQL
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start backend server on port 8000
uvicorn app.main:app --reload --port 8000
```

### Tier 3: Next.js SOC Dashboard
```bash
cd frontend
npm install
npm run dev
# Dashboard opens on http://localhost:3000
```

