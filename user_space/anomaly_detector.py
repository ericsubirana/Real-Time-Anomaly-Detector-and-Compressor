#!/usr/bin/python3

import sys
import time
import ctypes
import threading
import csv
import os
import gzip  # Para comprimir el CSV
from socket import inet_ntoa
from bcc import BPF
import numpy as np
from joblib import load

# Rutas relativas
MODEL_FILE = os.path.join("..", "AI_training", "incremental_model.joblib")
SCALER_FILE = os.path.join("..", "AI_training", "scaler.joblib")
PACKET_CAPTURE_FILE = os.path.join("..", "kernel_space", "packet_capture.c")

# Archivo CSV comprimido donde guardamos anomalías
CSV_FILENAME = "anomalies.csv.gz"

# Cargamos el modelo y el scaler
clf = load(MODEL_FILE)

def preprocess_flow_for_ai(flow_data):
    total_packets = sum(cpu_data.packet_count for cpu_data in flow_data)
    total_byte_count = sum(cpu_data.byte_count for cpu_data in flow_data)
    fwd_packet_count = sum(cpu_data.fwd_packet_count for cpu_data in flow_data)
    bwd_packet_count = sum(cpu_data.bwd_packet_count for cpu_data in flow_data)
    fwd_byte_count = sum(cpu_data.fwd_byte_count for cpu_data in flow_data)
    bwd_byte_count = sum(cpu_data.bwd_byte_count for cpu_data in flow_data)
    min_packet_length = min(cpu_data.min_packet_length for cpu_data in flow_data)
    max_packet_length = max(cpu_data.max_packet_length for cpu_data in flow_data)
    syn_count = sum(cpu_data.syn_count for cpu_data in flow_data)
    ack_count = sum(cpu_data.ack_count for cpu_data in flow_data)
    psh_count = sum(cpu_data.psh_count for cpu_data in flow_data)
    urg_count = sum(cpu_data.urg_count for cpu_data in flow_data)

    # Features con las que entrenamos/predijimos
    features = [
        total_packets,
        # total_byte_count,  # comentado en tu código original
        fwd_packet_count,
        bwd_packet_count,
        fwd_byte_count,
        bwd_byte_count,
        min_packet_length,
        max_packet_length,
        syn_count,
        ack_count,
        psh_count,
        urg_count
    ]

    # Escalamos
    scaler = load(SCALER_FILE)
    features = np.array(features).reshape(1, -1)
    features = scaler.transform(features)
    return features

def predict_flow_behavior(flow_data):
    features = preprocess_flow_for_ai(flow_data)
    prediction = clf.predict(features)
    return "BENIGN" if prediction == 1 else "ANOMALY DETECTED"

class FlowKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8)
    ]

class FlowData(ctypes.Structure):
    _fields_ = [
        ("first_seen", ctypes.c_uint64),
        ("last_seen", ctypes.c_uint64),
        ("packet_count", ctypes.c_uint32),
        ("byte_count", ctypes.c_uint64),
        ("fwd_packet_count", ctypes.c_uint32),
        ("bwd_packet_count", ctypes.c_uint32),
        ("fwd_byte_count", ctypes.c_uint64),
        ("bwd_byte_count", ctypes.c_uint64),
        ("min_packet_length", ctypes.c_uint16),
        ("max_packet_length", ctypes.c_uint16),
        ("syn_count", ctypes.c_uint16),
        ("ack_count", ctypes.c_uint16),
        ("psh_count", ctypes.c_uint16),
        ("urg_count", ctypes.c_uint16)
    ]

def save_anomaly_to_csv(flow_info):
    # Abre el archivo comprimido en modo 'append text'
    file_exists = os.path.isfile(CSV_FILENAME)
    with gzip.open(CSV_FILENAME, mode="at", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Si el fichero no existía, escribimos la cabecera
        if not file_exists:
            writer.writerow([
                "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", 
                "protocol", "packet_count", "byte_count",
                "fwd_packet_count", "bwd_packet_count", 
                "fwd_byte_count", "bwd_byte_count",
                "min_packet_length", "max_packet_length",
                "syn_count", "ack_count", "psh_count", "urg_count",
                "prediction"
            ])
        writer.writerow([
            flow_info["timestamp"],
            flow_info["src_ip"],
            flow_info["dst_ip"],
            flow_info["src_port"],
            flow_info["dst_port"],
            flow_info["protocol"],
            flow_info["packet_count"],
            flow_info["byte_count"],
            flow_info["fwd_packet_count"],
            flow_info["bwd_packet_count"],
            flow_info["fwd_byte_count"],
            flow_info["bwd_byte_count"],
            flow_info["min_packet_length"],
            flow_info["max_packet_length"],
            flow_info["syn_count"],
            flow_info["ack_count"],
            flow_info["psh_count"],
            flow_info["urg_count"],
            flow_info["prediction"]
        ])

try:
    with open(PACKET_CAPTURE_FILE, "r") as f:
        c_code = f.read()

    b = BPF(text=c_code)
    fn_capture_packet = b.load_func("capture_packet", BPF.XDP)
    b.attach_xdp(dev="enp0s3", fn=fn_capture_packet, flags=0)

    def getting_unupdated_flows(threshold_seconds=20, active_timeout=60):
        flows_map = b.get_table("flows")
        exported_flows_map = b.get_table("exported_flows")
        current_time_ns = time.monotonic_ns()

        print(f"Processing flows with idle_timeout={threshold_seconds}s and active_timeout={active_timeout}s:")

        for key, per_cpu_data in flows_map.items():
            src_ip = inet_ntoa(ctypes.c_uint32(key.src_ip).value.to_bytes(4, 'big'))
            dst_ip = inet_ntoa(ctypes.c_uint32(key.dst_ip).value.to_bytes(4, 'big'))

            last_seen = max(cpu_data.last_seen for cpu_data in per_cpu_data)
            first_seen = min((cpu_data.first_seen for cpu_data in per_cpu_data if cpu_data.first_seen > 0), default=0)

            if first_seen == 0 or first_seen > current_time_ns:
                print(f"Warning: Invalid first_seen value for flow: src_ip={src_ip}, dst_ip={dst_ip}")
                continue

            idle_duration = (current_time_ns - last_seen) / 1e9
            active_duration = (current_time_ns - first_seen) / 1e9

            if idle_duration > threshold_seconds or active_duration > active_timeout:
                total_packets = sum(cpu_data.packet_count for cpu_data in per_cpu_data)
                total_byte_count = sum(cpu_data.byte_count for cpu_data in per_cpu_data)
                fwd_packet_count = sum(cpu_data.fwd_packet_count for cpu_data in per_cpu_data)
                bwd_packet_count = sum(cpu_data.bwd_packet_count for cpu_data in per_cpu_data)
                fwd_byte_count = sum(cpu_data.fwd_byte_count for cpu_data in per_cpu_data)
                bwd_byte_count = sum(cpu_data.bwd_byte_count for cpu_data in per_cpu_data)
                min_packet_length = min(cpu_data.min_packet_length for cpu_data in per_cpu_data)
                max_packet_length = max(cpu_data.max_packet_length for cpu_data in per_cpu_data)
                syn_count = sum(cpu_data.syn_count for cpu_data in per_cpu_data)
                ack_count = sum(cpu_data.ack_count for cpu_data in per_cpu_data)
                psh_count = sum(cpu_data.psh_count for cpu_data in per_cpu_data)
                urg_count = sum(cpu_data.urg_count for cpu_data in per_cpu_data)

                new_data = FlowData(
                    first_seen=first_seen,
                    last_seen=last_seen,
                    packet_count=total_packets,
                    byte_count=total_byte_count,
                    fwd_packet_count=fwd_packet_count,
                    bwd_packet_count=bwd_packet_count,
                    fwd_byte_count=fwd_byte_count,
                    bwd_byte_count=bwd_byte_count,
                    min_packet_length=min_packet_length,
                    max_packet_length=max_packet_length,
                    syn_count=syn_count,
                    ack_count=ack_count,
                    psh_count=psh_count,
                    urg_count=urg_count
                )

                exported_flows_map[key] = new_data
                prediction = predict_flow_behavior(exported_flows_map[key])

                print(f"Flow from {src_ip} to {dst_ip} is: {prediction}")

                if prediction == "ANOMALY DETECTED":
                    print(f"ALERT: Anomalous flow detected from {src_ip} to {dst_ip}!")
                    flow_info = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": key.src_port,
                        "dst_port": key.dst_port,
                        "protocol": key.protocol,
                        "packet_count": total_packets,
                        "byte_count": total_byte_count,
                        "fwd_packet_count": fwd_packet_count,
                        "bwd_packet_count": bwd_packet_count,
                        "fwd_byte_count": fwd_byte_count,
                        "bwd_byte_count": bwd_byte_count,
                        "min_packet_length": min_packet_length,
                        "max_packet_length": max_packet_length,
                        "syn_count": syn_count,
                        "ack_count": ack_count,
                        "psh_count": psh_count,
                        "urg_count": urg_count,
                        "prediction": prediction
                    }
                    save_anomaly_to_csv(flow_info)

                del flows_map[key]

    def periodic_print_flows(interval):
        def print_and_reschedule():
            getting_unupdated_flows()
            threading.Timer(interval, print_and_reschedule).start()

        print_and_reschedule()

    periodic_print_flows(3)

except KeyboardInterrupt:
    b.remove_xdp(dev="enp0s3", flags=0)
    sys.exit()
