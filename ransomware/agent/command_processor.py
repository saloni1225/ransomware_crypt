import logging
import os
import sys
import time
import json
import shutil
import threading
import requests
import psutil

sys.path.insert(0, os.path.dirname(__file__))
import config

logger = logging.getLogger("agent.command_processor")

SHARED_SECRET = os.getenv("RDS_SHARED_SECRET") or os.getenv("AGENT_SHARED_SECRET", "")
QUARANTINE_DIR = os.path.join(os.path.dirname(config.__file__), "quarantine")
QUARANTINE_MAP_PATH = os.path.join(os.path.dirname(config.__file__), "quarantine_map.json")

def _get_headers():
    return {
        "X-Agent-Secret": SHARED_SECRET,
        "Content-Type": "application/json"
    }

def _terminate_process(pid: int) -> dict:
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()
        return {"status": "terminated", "pid": pid, "name": name}
    except psutil.NoSuchProcess:
        raise ValueError(f"No running process found with PID: {pid}")

def _quarantine_file(file_path: str, scan_id: int) -> dict:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
        
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    
    filename = os.path.basename(file_path)
    quarantine_filename = f"{scan_id}_{filename}.quarantine"
    quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)
    
    # Handle existing quarantine files
    if os.path.exists(quarantine_path):
        os.remove(quarantine_path)
        
    shutil.move(file_path, quarantine_path)
    
    # Update quarantine map JSON
    quarantine_map = {}
    if os.path.exists(QUARANTINE_MAP_PATH):
        try:
            with open(QUARANTINE_MAP_PATH, "r", encoding="utf-8") as f:
                quarantine_map = json.load(f)
        except Exception:
            pass
            
    quarantine_map[str(scan_id)] = {
        "original_path": file_path,
        "quarantine_path": quarantine_path,
        "quarantine_time": time.time()
    }
    
    with open(QUARANTINE_MAP_PATH, "w", encoding="utf-8") as f:
        json.dump(quarantine_map, f, indent=4)
        
    return {"status": "quarantined", "original_path": file_path, "quarantine_path": quarantine_path}

def _restore_file(scan_id: int) -> dict:
    if not os.path.exists(QUARANTINE_MAP_PATH):
        raise FileNotFoundError("Quarantine registry map file not found")
        
    with open(QUARANTINE_MAP_PATH, "r", encoding="utf-8") as f:
        quarantine_map = json.load(f)
        
    entry = quarantine_map.get(str(scan_id))
    if not entry:
        raise ValueError(f"No quarantine record found for scan_id: {scan_id}")
        
    quarantine_path = entry["quarantine_path"]
    original_path = entry["original_path"]
    
    if not os.path.exists(quarantine_path):
        raise FileNotFoundError(f"Quarantined backup file not found at: {quarantine_path}")
        
    # Recreate target folder if deleted
    os.makedirs(os.path.dirname(original_path), exist_ok=True)
    shutil.move(quarantine_path, original_path)
    
    # Remove from map
    quarantine_map.pop(str(scan_id))
    with open(QUARANTINE_MAP_PATH, "w", encoding="utf-8") as f:
        json.dump(quarantine_map, f, indent=4)
        
    return {"status": "restored", "original_path": original_path}

def _update_command_status(session: requests.Session, cmd_id: int, status: str, result: dict = None, error_message: str = None) -> bool:
    status_url = f"{config.BACKEND_URL}/devices/{config.DEVICE_ID}/commands/{cmd_id}/status"
    payload = {"status": status}
    if result is not None:
        payload["execution_result"] = result
    if error_message is not None:
        payload["error_message"] = error_message

    for attempt in range(3):
        try:
            r = session.put(status_url, json=payload, timeout=10)
            if r.status_code in (200, 201):
                return True
            logger.warning("Attempt %d to update command %d to %s failed: status code %d", attempt + 1, cmd_id, status, r.status_code)
        except Exception as exc:
            logger.warning("Attempt %d to update command %d to %s failed: %s", attempt + 1, cmd_id, status, exc)
        if attempt < 2:
            time.sleep(1.0 * (2 ** attempt))
    logger.error("Failed to update status to %s for command %d after 3 attempts", status, cmd_id)
    return False

def execute_single_command(cmd: dict, session: requests.Session):
    cmd_id = cmd["id"]
    cmd_type = cmd["command_type"]
    payload = cmd["payload"] or {}
    
    logger.info("Executing command %d (%s)...", cmd_id, cmd_type)
    
    # 1. Report received
    _update_command_status(session, cmd_id, "received")
    
    # 2. Report started
    _update_command_status(session, cmd_id, "started")
    
    try:
        result = {}
        if cmd_type == "terminate_process":
            pid = payload.get("pid")
            if not pid:
                raise ValueError("Missing 'pid' in payload")
            result = _terminate_process(int(pid))
            
        elif cmd_type == "quarantine_file":
            file_path = payload.get("file_path")
            scan_id = payload.get("scan_id")
            if not file_path or scan_id is None:
                raise ValueError("Missing 'file_path' or 'scan_id' in payload")
            result = _quarantine_file(file_path, scan_id)
            
        elif cmd_type == "restore_file":
            scan_id = payload.get("scan_id")
            if scan_id is None:
                raise ValueError("Missing 'scan_id' in payload")
            result = _restore_file(scan_id)
            
        elif cmd_type == "acknowledge_alert":
            event_id = payload.get("threat_event_id")
            result = {"status": "acknowledged", "threat_event_id": event_id}
            
        elif cmd_type == "rollback":
            event_id = payload.get("threat_event_id")
            result = {"status": "rolled_back", "threat_event_id": event_id}
            
        elif cmd_type == "sync_policy":
            result = {"status": "synced", "applied_policy": payload}
            
        else:
            raise ValueError(f"Unknown command type: {cmd_type}")
            
        logger.info("Command %d (%s) executed successfully: %s", cmd_id, cmd_type, result)
        # 3. Report completed
        _update_command_status(session, cmd_id, "completed", result=result)
        
    except Exception as exc:
        logger.error("Failed to execute command %d (%s): %s", cmd_id, cmd_type, exc)
        # 4. Report failed
        _update_command_status(session, cmd_id, "failed", error_message=str(exc))

def poll_commands_loop(stop_event: threading.Event):
    logger.info("Command polling loop started (interval=10s)")
    session = requests.Session()
    session.headers.update(_get_headers())
    
    while not stop_event.is_set():
        try:
            url = f"{config.BACKEND_URL}/devices/{config.DEVICE_ID}/commands/pending"
            response = session.get(url, timeout=10)
            if response.status_code == 200:
                commands = response.json()
                for cmd in commands:
                    threading.Thread(
                        target=execute_single_command,
                        args=(cmd, session),
                        daemon=True,
                        name=f"agent-cmd-{cmd['id']}"
                    ).start()
            elif response.status_code != 404:
                logger.debug("Poll commands status code: %d", response.status_code)
        except Exception as e:
            logger.debug("Error polling backend commands: %s", e)
            
        stop_event.wait(10)

def start_command_processor() -> tuple:
    """Start command polling thread. Returns (thread, stop_event)."""
    stop_event = threading.Event()
    thread = threading.Thread(
        target=poll_commands_loop,
        args=(stop_event,),
        daemon=True,
        name="agent-command-processor"
    )
    thread.start()
    return thread, stop_event
