#!/usr/bin/python3

import sys
import time
import ctypes
import threading
from socket import inet_ntoa
from bcc import BPF

# Define ctypes structure for flow_key and flow_data
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
        ("last_seen", ctypes.c_uint64),
        ("packet_count", ctypes.c_uint32)
    ]

try:
    with open("/home/subi/Desktop/TMA_PROJECT/kernel_space/packet_capture.c", "r") as f:
        c_code = f.read()
    
    c_code = f"""{c_code}"""
    b = BPF(text=c_code)
    fn_capture_packet = b.load_func("capture_packet", BPF.XDP)
    b.attach_xdp(dev="enp0s3", fn=fn_capture_packet, flags=0)

    def getting_unupdated_flows(threshold_seconds=20, active_timeout=60):
        flows_map = b.get_table("flows")
        exported_flows_map = b.get_table("exported_flows")
        current_time_ns = time.monotonic_ns()  # Usar monotonic_ns para evitar desincronización
        print(f"Processing flows with idle_timeout={threshold_seconds}s and active_timeout={active_timeout}s:")

        for key, per_cpu_data in flows_map.items():
            src_ip = inet_ntoa(ctypes.c_uint32(key.src_ip).value.to_bytes(4, 'big'))
            dst_ip = inet_ntoa(ctypes.c_uint32(key.dst_ip).value.to_bytes(4, 'big'))

            # Agregar datos de las CPUs
            total_packets = sum(cpu_data.packet_count for cpu_data in per_cpu_data)
            last_seen = max(cpu_data.last_seen for cpu_data in per_cpu_data)
            first_seen = min(cpu_data.first_seen for cpu_data in per_cpu_data if cpu_data.first_seen > 0)

            # Validar que `first_seen` tenga sentido
            if first_seen == 0 or first_seen > current_time_ns:
                print(f"Warning: Invalid first_seen value for flow: src_ip={src_ip}, dst_ip={dst_ip}")
                continue

            # Calcular duraciones
            idle_duration = (current_time_ns - last_seen) / 1e9
            active_duration = (current_time_ns - first_seen) / 1e9

            if idle_duration > threshold_seconds or active_duration > active_timeout:
                print(f"Exporting flow: src_ip={src_ip}, dst_ip={dst_ip}, src_port={key.src_port}, "
                    f"dst_port={key.dst_port}, protocol={key.protocol}, "
                    f"packet_count={total_packets}, idle_duration={idle_duration:.2f}s, "
                    f"active_duration={active_duration:.2f}s")
                exported_flows_map[key] = per_cpu_data
                del flows_map[key]  # Eliminar el flujo del mapa


    def periodic_print_flows(interval):
        def print_and_reschedule():
            getting_unupdated_flows()
            threading.Timer(interval, print_and_reschedule).start()

        print_and_reschedule()

    # Start the periodic function
    periodic_print_flows(3) 
except KeyboardInterrupt:
    b.remove_xdp(dev="enp0s3", flags=0)
    sys.exit()