"""
Flask Application Backend
Provides REST API endpoints for the Basic Network Sniffer and serves the frontend dashboard.
"""

import os
import sys
import time
from pathlib import Path
from flask import Flask, jsonify, make_response, request, send_from_directory

# Ensure backend directory is in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from packet_analyzer import export_packets_to_csv
from sniffer import PacketSniffer

# Paths configuration
ROOT_DIR = Path(current_dir).resolve().parents[1]
FRONTEND_DIR = str(ROOT_DIR / "frontend")
CAPTURES_DIR = str(ROOT_DIR / "captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
sniffer = PacketSniffer(max_buffer_size=3000)


@app.route("/")
def index():
    """Serve the single-page frontend web dashboard."""
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    """Serve frontend static assets (CSS, JS, icons)."""
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint indicating system readiness."""
    return jsonify({
        "status": "online",
        "service": "Basic Network Sniffer",
        "is_capturing": sniffer.is_running,
    })


@app.route("/api/interfaces", methods=["GET"])
def get_interfaces():
    """Return available network interfaces."""
    interfaces = sniffer.get_available_interfaces()
    return jsonify({"interfaces": interfaces})


@app.route("/api/start", methods=["POST"])
def start_capture():
    """Start packet sniffing on selected interface with optional protocol filter."""
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")
    protocol_filter = data.get("protocol_filter")

    success, error = sniffer.start(interface=interface, protocol_filter=protocol_filter)
    if not success:
        return jsonify({"success": False, "error": error}), 400

    return jsonify({
        "success": True,
        "message": "Packet capture started successfully.",
        "status": sniffer.get_status()
    })


@app.route("/api/stop", methods=["POST"])
def stop_capture():
    """Stop active packet sniffing."""
    success, msg = sniffer.stop()
    return jsonify({
        "success": success,
        "message": msg or "Capture stopped.",
        "status": sniffer.get_status()
    })


@app.route("/api/clear", methods=["POST"])
def clear_capture():
    """Clear buffer and reset packet statistics."""
    sniffer.clear()
    return jsonify({
        "success": True,
        "message": "Packet buffer and counters cleared.",
        "status": sniffer.get_status()
    })


@app.route("/api/status", methods=["GET"])
def status():
    """Get current capture status, metrics, and error state."""
    return jsonify(sniffer.get_status())


@app.route("/api/packets", methods=["GET"])
def get_packets():
    """
    Retrieve captured packets with query parameters:
      - since_id: Return packets with ID > since_id
      - limit: Max number of packets to return (default 100, max 500)
      - protocol: 'all', 'tcp', 'udp', 'icmp'
      - search: Text query matching IP, port, or summary
    """
    try:
        since_id = int(request.args.get("since_id", 0))
    except ValueError:
        since_id = 0

    try:
        limit = min(int(request.args.get("limit", 150)), 500)
    except ValueError:
        limit = 150

    protocol = request.args.get("protocol", None)
    search = request.args.get("search", None)

    packets = sniffer.get_packets(since_id=since_id, limit=limit, protocol=protocol, search=search)
    return jsonify({
        "packets": packets,
        "count": len(packets),
        "status": sniffer.get_status()
    })


@app.route("/api/export", methods=["GET"])
def export_csv():
    """
    Export current buffer of captured packets to CSV.
    Saves a persistent copy in the captures directory and delivers as a downloadable file.
    """
    packets = sniffer.get_all_packets_for_export()
    if not packets:
        return jsonify({"success": False, "error": "No packets captured to export."}), 400

    filename = f"capture_{int(time.time())}.csv"
    save_path = os.path.join(CAPTURES_DIR, filename)

    # Save to disk
    export_packets_to_csv(packets, filepath=save_path)

    # Also prepare HTTP downloadable response
    csv_stream = export_packets_to_csv(packets, filepath=None)
    response = make_response(csv_stream.getvalue())
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Basic Network Sniffer Web Server on http://127.0.0.1:{port}")
    print("[*] Note: For live packet sniffing on Windows, run this in an Administrator terminal.")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
