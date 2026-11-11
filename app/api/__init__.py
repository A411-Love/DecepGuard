import ipaddress

from flask import Blueprint, jsonify, request
from flask_login import login_required

from app.extensions import db
from app.models import Honeypot, AttackEvent, Alert
from app.auth.permissions import role_required

api = Blueprint("api", __name__)


# API Home
@api.route("/", methods=["GET"])
@login_required
def api_home():
    return jsonify({
        "message": "Welcome to DecepGuard REST API",
        "version": "1.0",
        "available_endpoints": [
            "/api/honeypots",
            "/api/events",
            "/api/alerts"
        ]
    }), 200


# Create a new honeypot using the REST API
@api.route("/honeypots", methods=["POST"])
@role_required("admin", "analyst")
def create_honeypot():

    # Check that the request contains JSON
    if not request.is_json:
        return jsonify({
            "error": "Request must contain JSON data."
        }), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid JSON request body."
        }), 400

    # Get and validate required fields
    name = data.get("name")
    honeypot_type = data.get("honeypot_type")
    ip_address = data.get("ip_address")
    port = data.get("port")
    description = data.get("description", "")
    status = data.get("status", "inactive")

    if not all([name, honeypot_type, ip_address, port]):
        return jsonify({
            "error": "Name, honeypot_type, ip_address and port are required."
        }), 400

    # Validate text fields
    if not all(isinstance(value, str) for value in
               [name, honeypot_type, ip_address, description, status]):
        return jsonify({
            "error": "Text fields must contain strings."
        }), 400

    name = name.strip()
    honeypot_type = honeypot_type.strip()
    ip_address = ip_address.strip()
    description = description.strip()
    status = status.strip().lower()

    if not name or len(name) > 100:
        return jsonify({"error": "Name must be between 1 and 100 characters."}), 400

    if not honeypot_type or len(honeypot_type) > 50:
        return jsonify({"error": "Invalid honeypot type."}), 400

    if len(description) > 2000:
        return jsonify({"error": "Description is too long."}), 400

    # Validate IP address
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return jsonify({"error": "Invalid IP address."}), 400

    # Validate port
    if isinstance(port, bool) or not isinstance(port, int):
        return jsonify({"error": "Port must be an integer."}), 400

    if not 1 <= port <= 65535:
        return jsonify({"error": "Port must be between 1 and 65535."}), 400

    # Validate status
    if status not in ["active", "inactive"]:
        return jsonify({
            "error": "Status must be active or inactive."
        }), 400

    # Create and save the honeypot
    honeypot = Honeypot(
        name=name,
        honeypot_type=honeypot_type,
        ip_address=ip_address,
        port=port,
        description=description,
        status=status
    )

    try:
        db.session.add(honeypot)
        db.session.commit()

    except Exception:
        db.session.rollback()
        return jsonify({
            "error": "Unable to create honeypot."
        }), 500

    return jsonify({
        "message": "Honeypot created successfully.",
        "honeypot": {
            "id": honeypot.id,
            "name": honeypot.name,
            "honeypot_type": honeypot.honeypot_type,
            "ip_address": honeypot.ip_address,
            "port": honeypot.port,
            "status": honeypot.status
        }
    }), 201

# Update an existing honeypot using the REST API
@api.route("/honeypots/<int:honeypot_id>", methods=["PUT"])
@role_required("admin", "analyst")
def update_honeypot(honeypot_id):

    # Find the honeypot
    honeypot = db.session.get(Honeypot, honeypot_id)

    if honeypot is None:
        return jsonify({
            "error": "Honeypot not found."
        }), 404

    # Check JSON request
    if not request.is_json:
        return jsonify({
            "error": "Request must contain JSON data."
        }), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not data:
        return jsonify({
            "error": "Invalid or empty JSON request body."
        }), 400

    # Only allow these fields to be updated
    allowed_fields = {
        "name", "honeypot_type", "ip_address",
        "port", "description", "status"
    }

    if not set(data.keys()).issubset(allowed_fields):
        return jsonify({
            "error": "Request contains unsupported fields."
        }), 400

    # Validate and update name
    if "name" in data:
        name = data["name"]

        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 100:
            return jsonify({
                "error": "Name must be between 1 and 100 characters."
            }), 400

        honeypot.name = name.strip()

    # Validate and update honeypot type
    if "honeypot_type" in data:
        honeypot_type = data["honeypot_type"]

        if not isinstance(honeypot_type, str) or not honeypot_type.strip() or len(honeypot_type.strip()) > 50:
            return jsonify({
                "error": "Invalid honeypot type."
            }), 400

        honeypot.honeypot_type = honeypot_type.strip()

    # Validate and update IP address
    if "ip_address" in data:
        ip_address = data["ip_address"]

        if not isinstance(ip_address, str):
            return jsonify({
                "error": "IP address must be a string."
            }), 400

        ip_address = ip_address.strip()

        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return jsonify({
                "error": "Invalid IP address."
            }), 400

        honeypot.ip_address = ip_address

    # Validate and update port
    if "port" in data:
        port = data["port"]

        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return jsonify({
                "error": "Port must be an integer between 1 and 65535."
            }), 400

        honeypot.port = port

    # Validate and update description
    if "description" in data:
        description = data["description"]

        if not isinstance(description, str) or len(description.strip()) > 2000:
            return jsonify({
                "error": "Description must be a string with a maximum of 2000 characters."
            }), 400

        honeypot.description = description.strip()

    # Validate and update status
    if "status" in data:
        status = data["status"]

        if not isinstance(status, str) or status.strip().lower() not in ["active", "inactive"]:
            return jsonify({
                "error": "Status must be active or inactive."
            }), 400

        honeypot.status = status.strip().lower()

    # Save changes
    try:
        db.session.commit()

    except Exception:
        db.session.rollback()
        return jsonify({
            "error": "Unable to update honeypot."
        }), 500

    return jsonify({
        "message": "Honeypot updated successfully.",
        "honeypot": {
            "id": honeypot.id,
            "name": honeypot.name,
            "honeypot_type": honeypot.honeypot_type,
            "ip_address": honeypot.ip_address,
            "port": honeypot.port,
            "description": honeypot.description,
            "status": honeypot.status
        }
    }), 200

# Delete a honeypot using the REST API
@api.route("/honeypots/<int:honeypot_id>", methods=["DELETE"])
@role_required("admin", "analyst")
def delete_honeypot(honeypot_id):

    honeypot = db.session.get(Honeypot, honeypot_id)

    if honeypot is None:
        return jsonify({
            "error": "Honeypot not found."
        }), 404

    try:
        db.session.delete(honeypot)
        db.session.commit()

    except Exception:
        db.session.rollback()
        return jsonify({
            "error": "Unable to delete honeypot."
        }), 500

    return jsonify({
        "message": "Honeypot deleted successfully.",
        "deleted_id": honeypot_id
    }), 200


# Get all honeypots
@api.route("/honeypots", methods=["GET"])
@login_required
def get_honeypots():
    honeypots = Honeypot.query.order_by(Honeypot.id.desc()).all()

    results = []

    for honeypot in honeypots:
        results.append({
            "id": honeypot.id,
            "name": honeypot.name,
            "type": honeypot.honeypot_type,
            "ip_address": honeypot.ip_address,
            "port": honeypot.port,
            "status": honeypot.status,
            "description": honeypot.description
        })

    return jsonify({
        "count": len(results),
        "honeypots": results
    }), 200


# Get all attack events
@api.route("/events", methods=["GET"])
@login_required
def get_events():
    events = AttackEvent.query.order_by(
        AttackEvent.timestamp.desc()
    ).all()

    results = []

    for event in events:
        results.append({
            "id": event.id,
            "honeypot_id": event.honeypot_id,
            "source_ip": event.source_ip,
            "source_port": event.source_port,
            "destination_port": event.destination_port,
            "protocol": event.protocol,
            "attack_type": event.attack_type,
            "severity": event.severity,
            "event_source": event.event_source,
            "description": event.description,
            "timestamp": event.timestamp.isoformat()
        })

    return jsonify({
        "count": len(results),
        "events": results
    }), 200


# Get all alerts
@api.route("/alerts", methods=["GET"])
@login_required
def get_alerts():
    alerts = Alert.query.order_by(
        Alert.created_at.desc()
    ).all()

    results = []

    for alert in alerts:
        results.append({
            "id": alert.id,
            "attack_event_id": alert.attack_event_id,
            "incident_id": alert.incident_id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "status": alert.status,
            "created_at": alert.created_at.isoformat()
        })

    return jsonify({
        "count": len(results),
        "alerts": results
    }), 200
