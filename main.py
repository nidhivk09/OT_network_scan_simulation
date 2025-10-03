import os
import json
import time
import uuid
import threading
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from rich.console import Console
from netaddr import IPNetwork  # Import for subnet validation

# Import your scanner class from the scan.py file
# FIX 1: Changed the import name to the new class name: AdvancedITOTScanner
from scan import AdvancedITOTScanner

# --- Configuration & In-Memory Storage ---
SCAN_TASKS = {}
API_CONSOLE = Console(color_system="truecolor")

# --- Initialize FastAPI ---
app = FastAPI(title="IT/OT Security Scan API")  # Updated title

# --- CORS Configuration (Crucial for React/Vite dev) ---
origins = [
    "http://localhost:5173",  # React/Vite dev server
    "http://127.0.0.1:5173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Pydantic Models ---
class ScanRequest(BaseModel):
    subnet: str
    shodan_api_key: str | None = None
    scan_type: str = "2"


class ScanResponse(BaseModel):
    task_id: str
    status: str
    message: str


# FIX 2: Updated Pydantic model to reflect all necessary data for the frontend
class ScanResultItem(BaseModel):
    ip: str
    mac: str
    vendor: str
    # Added open_ports field for direct port display
    open_ports: list[int]
    ot_services: list[tuple[int, str]]  # List of (port, protocol)
    it_services: list[tuple[int, str]]  # List of (port, protocol)
    risk: str
    port_count: int


class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    timestamp: float
    results: list[ScanResultItem] | None = None
    duration_seconds: float | None = None


# --- Background Task Function ---
def run_scan_in_background(task_id: str, request_data: ScanRequest):
    """Executes the long-running scan script and updates the global storage."""
    API_CONSOLE.print(f"[bold yellow]Task {task_id}: Starting scan for {request_data.subnet}[/bold yellow]")
    start_time = time.time()

    # Basic input validation for subnet
    try:
        IPNetwork(request_data.subnet)
    except:
        SCAN_TASKS[task_id]['status'] = 'failed'
        SCAN_TASKS[task_id]['error'] = "Invalid subnet format."
        return

    try:
        # FIX 3: Instantiated the new class name
        scanner = AdvancedITOTScanner(shodan_api_key=request_data.shodan_api_key)

        if request_data.scan_type == "1":
            # FIX 4: Updated quick scan ports to use the new ALL_PORTS list and reflect IT/OT
            scanner.ALL_PORTS = [21, 22, 23, 80, 443, 502, 102, 44818, 47808, 4840, 1883, 3389, 445]

        # Use the correct comprehensive scan method
        raw_results = scanner.run_comprehensive_scan(request_data.subnet)
        end_time = time.time()
        duration = end_time - start_time

        # Process results
        processed_results = []
        for r in raw_results:
            risk = "Low"
            ot_count = len(r['ot_services'])

            # Risk assessment logic (Prioritizing OT protocols)
            if ot_count > 3:
                risk = "Critical"
            elif ot_count > 1:
                risk = "High"
            elif ot_count > 0:
                risk = "Medium"
            # Secondary check for IT risk
            elif r['it_services']:
                it_risk_services = [s for p, s in r['it_services'] if p in [22, 23, 3389, 445]]
                if it_risk_services:
                    risk = "IT-Medium"
                else:
                    risk = "Low"

            processed_results.append(ScanResultItem(
                ip=r['ip'], mac=r['mac'], vendor=r['vendor'],
                open_ports=r['ports'],  # Passed the raw list of open ports
                ot_services=r['ot_services'],
                it_services=r['it_services'],
                risk=risk,
                port_count=len(r['ports'])
            ))

        # Update global task status
        SCAN_TASKS[task_id].update({
            'status': 'completed',
            'results': processed_results,
            'duration_seconds': duration
        })

        API_CONSOLE.print(f"[bold green]Task {task_id}: Scan completed in {duration:.2f} seconds[/bold green]")

    except Exception as e:
        API_CONSOLE.print(f"[bold red]Task {task_id}: Scan failed with error: {e}[/bold red]")
        SCAN_TASKS[task_id]['status'] = 'failed'
        SCAN_TASKS[task_id]['error'] = str(e)


# --- API Endpoints ---
@app.post("/api/scan/start", response_model=ScanResponse)
async def start_scan(request_data: ScanRequest, background_tasks: BackgroundTasks):
    task_id = str(uuid.uuid4())

    SCAN_TASKS[task_id] = {
        'status': 'running',
        'timestamp': time.time(),
        'results': None,
        'duration_seconds': None
    }

    background_tasks.add_task(run_scan_in_background, task_id, request_data)

    return ScanResponse(
        task_id=task_id,
        status="running",
        message="Scan started successfully in the background. Use the status endpoint to check progress."
    )


@app.get("/api/scan/status/{task_id}", response_model=TaskStatusResponse)
async def get_scan_status(task_id: str):
    task_info = SCAN_TASKS.get(task_id)

    if not task_info:
        raise HTTPException(status_code=404, detail="Task ID not found.")

    response_data = {
        'task_id': task_id,
        'status': task_info['status'],
        'timestamp': task_info['timestamp'],
        'duration_seconds': task_info.get('duration_seconds')
    }

    if task_info['status'] == 'completed':
        response_data['results'] = task_info['results']
    elif task_info['status'] == 'failed':
        raise HTTPException(status_code=500, detail=f"Scan failed: {task_info.get('error', 'Unknown error')}")

    return response_data


# Simple health check endpoint.
@app.get("/")
def read_root():
    return {"message": "IT/OT Scan API is running. Access /docs for documentation."}


# Dedicated health check endpoint.
@app.get("/health")
def health_check():
    return {"status": "ok", "service": "IT/OT Scan API"}


if __name__ == "__main__":
    import uvicorn

    API_CONSOLE.print("[bold green]Starting FastAPI server on http://127.0.0.1:8000[/bold green]")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
