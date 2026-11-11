
from flask import Blueprint, jsonify
from flask_login import login_required

from app.models import Honeypot, AttackEvent, Alert

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
