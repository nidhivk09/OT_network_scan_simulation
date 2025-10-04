# IT/OT Network Security Scanner 🛡️

This project provides a powerful IT/OT (Information Technology / Operational Technology) network security scanner complete with a FastAPI backend and a fully containerized, simulated industrial lab environment using Docker Compose.

The scanner is designed to perform network discovery, identify devices, and distinguish between standard IT assets and critical OT/ICS (Industrial Control System) assets like PLCs, HMIs, and protocol gateways.






##  Getting Started

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

4. **Optionally run requirements.txt:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🔬 How to Use the Scanner

Run the scan.py file.
```bash
sudo python3 scan.py
```
main.py contains for for FAST API, which can be used to adapt and print results to a front-end UI.
