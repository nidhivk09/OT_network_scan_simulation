# IT/OT Network Security Scanner 🛡️

This project provides a powerful IT/OT (Information Technology / Operational Technology) network security scanner complete with a FastAPI backend and a fully containerized, simulated industrial lab environment using Docker Compose.

[cite_start]The scanner is designed to perform network discovery, identify devices, and distinguish between standard IT assets and critical OT/ICS (Industrial Control System) assets like PLCs, HMIs, and protocol gateways.

## ✨ Key Features

* [cite_start]**🌐 Comprehensive Network Discovery**: Uses ARP scans to reliably discover active hosts on the target subnet.
* [cite_start]**🔬 Multi-Protocol Identification**: Employs advanced techniques including banner grabbing and protocol-specific probes to identify services like **Modbus, S7comm, OPC-UA, MQTT, Ethernet/IP**, alongside common IT protocols (HTTP, SSH, RDP, etc.).
* [cite_start]**🤖 IT vs. OT Asset Classification**: Intelligently categorizes discovered services to differentiate between IT and OT systems, helping to prioritize security efforts.
* [cite_start]**⚠️ Risk Assessment**: Provides a basic risk level (Low, Medium, High, Critical) for each discovered device based on the presence and number of exposed OT services.
* [cite_start]**🚀 Asynchronous API**: Built with **FastAPI**, the backend API allows you to start scans and poll for results asynchronously, making it suitable for integration with a web frontend.
* **🐳 One-Command Lab Setup**: The entire simulated IT/OT lab environment and the scanner application are orchestrated with a single `docker-compose up` command.

---

## 🛠️ Tech Stack

* [cite_start]**Backend**: FastAPI, Uvicorn [cite: 1]
* [cite_start]**Scanning Engine**: Scapy, python-nmap, pymodbus, opcua, paho-mqtt [cite: 1]
* [cite_start]**Containerization**: Docker, Docker Compose 
* [cite_start]**CLI**: Rich for formatted console output [cite: 1]

---

## 🚀 Getting Started

Follow these instructions to get the project up and running on your local machine.

### Prerequisites

You must have **Docker** and **Docker Compose** installed on your system.

* [Install Docker Engine](https://docs.docker.com/engine/install/)
* [Install Docker Compose](https://docs.docker.com/compose/install/)

### Installation & Execution

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```

2.  **Build and run the containers:**
    This single command will build the FastAPI scanner image and start all the simulated lab services in detached mode.

    ```bash
    docker-compose up -d --build
    ```

3.  **Verify the services are running:**
    Check the status of the running containers. You should see `plc1`, `opcua1`, `mqtt`, `fastapi-backend`, and others in the list.
    ```bash
    docker-compose ps
    ```
    The FastAPI server will be available at `http://localhost:8000`.

---

## 🔬 How to Use the Scanner

You can interact with the scanner via its REST API or by running the script directly from the command line.

### 1. Using the REST API (Recommended)

[cite_start]The API provides an asynchronous way to manage scans.

**A. Start a Scan**

[cite_start]Send a `POST` request to the `/api/scan/start` endpoint. The default subnet in `docker-compose.yml` is `172.20.0.0/24`.

```bash
curl -X POST http://localhost:8000/api/scan/start \
-H "Content-Type: application/json" \
-d '{"subnet": "172.20.0.0/24", "scan_type": "2"}'
