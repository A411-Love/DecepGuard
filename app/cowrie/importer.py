
import json
from datetime import datetime, timezone
from pathlib import Path

from app.extensions import db
from app.models import Alert, AttackEvent, Honeypot


LOG_PATH = Path("cowrie_logs/cowrie.json")
CHECKPOINT_PATH = Path("instance/cowrie_checkpoint.json")

EVENT_TYPES = {
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
}


def get_checkpoint():
    if not CHECKPOINT_PATH.exists():
        return 0

    try:
        data = json.loads(CHECKPOINT_PATH.read_text(encoding="utf-8"))
        return max(0, int(data.get("offset", 0)))
    except (ValueError, OSError, json.JSONDecodeError):
        return 0


def save_checkpoint(offset):
    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = CHECKPOINT_PATH.with_suffix(".tmp")
    temp_path.write_text(json.dumps({"offset": offset}), encoding="utf-8")
    temp_path.replace(CHECKPOINT_PATH)


def determine_severity(event_type, command=""):
    if event_type == "cowrie.login.failed":
        return "Medium"

    if event_type == "cowrie.login.success":
        return "High"

    suspicious_terms = (
        "wget", "curl", "chmod", "passwd",
        "useradd", "sudo", "nc ", "netcat"
    )

    if any(term in command.lower() for term in suspicious_terms):
        return "High"

    return "Low"


def import_cowrie_events():
    """Import new Cowrie events into DecepGuard."""

    if not LOG_PATH.exists():
        raise FileNotFoundError(f"Cowrie log not found: {LOG_PATH}")

    honeypot = Honeypot.query.filter_by(
        name="SSH Decoy",
        port=2222
    ).first()

    if honeypot is None:
        raise ValueError("SSH Decoy honeypot on port 2222 was not found.")

    offset = get_checkpoint()
    imported = 0

    with LOG_PATH.open("rb") as log_file:
        if offset > LOG_PATH.stat().st_size:
            offset = 0

        log_file.seek(offset)

        while True:
            line = log_file.readline()

            if not line:
                break

            new_offset = log_file.tell()

            try:
                event_data = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                break

            event_type = event_data.get("eventid")

            if event_type not in EVENT_TYPES:
                offset = new_offset
                continue

            source_ip = event_data.get("src_ip", "unknown")
            command = event_data.get("input", "")
            username = event_data.get("username", "")

            if event_type == "cowrie.login.failed":
                attack_type = "SSH Login Failure"
                description = "Failed SSH login attempt."

            elif event_type == "cowrie.login.success":
                attack_type = "SSH Login Success"
                description = "Successful SSH login observed."

            else:
                attack_type = "SSH Command Execution"
                description = f"Command executed: {command[:300]}"

            if username:
                description += f" Username: {username[:80]}"

            if source_ip in ("127.0.0.1", "::1"):
                description = "[LOCAL TEST] " + description

            try:
                timestamp = datetime.fromisoformat(
                    event_data["timestamp"].replace("Z", "+00:00")
                )
            except (KeyError, ValueError, TypeError, AttributeError):
                timestamp = datetime.now(timezone.utc)

            severity = determine_severity(event_type, command)

            attack = AttackEvent(
                honeypot_id=honeypot.id,
                source_ip=source_ip[:45],
                source_port=event_data.get("src_port"),
                destination_port=event_data.get("dst_port", 2222),
                protocol=event_data.get("protocol", "ssh").upper(),
                attack_type=attack_type,
                severity=severity,
                description=description,
                event_source="cowrie",
                timestamp=timestamp
            )

            db.session.add(attack)
            db.session.flush()

            alert = Alert(
                attack_event_id=attack.id,
                title=f"{attack_type} detected",
                description=description,
                severity=severity,
                status="New"
            )

            db.session.add(alert)
            imported += 1
            offset = new_offset

        db.session.commit()
        save_checkpoint(offset)

    return imported
