from flask import Flask, render_template, jsonify
from threading import Thread
import time

app = Flask(__name__)

# shared data (global)
packets = []
total_packets = 0

# 👇 detector से data यहाँ push होगा
def add_packet(data):
    global total_packets
    total_packets += 1

    packets.append(data)
    if len(packets) > 100:
        packets.pop(0)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def get_data():
    return jsonify({
        "packets": packets,
        "total": total_packets
    })
def run_dashboard():
    app.run(host="0.0.0.0", port=5000)
