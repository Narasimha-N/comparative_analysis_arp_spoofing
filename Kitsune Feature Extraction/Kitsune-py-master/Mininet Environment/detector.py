#import required libraries

import time #for timestamps
import threading #to run sniff function in background while Flask is working on main thread
import joblib #to load best generalized model
import numpy as np #for numeric operations required in netStat function
import pandas as pd # to build the feature row as DataFrame
import torch #to run the pyTorch DNN model (best-genaralized)
import torch.nn as nn #to define architecture of DNN
from sklearn.base import BaseEstimator, ClassifierMixin #required in wrapper function of DNN Classifier
from scapy.all import sniff, IP, IPv6, TCP, UDP, ARP, ICMP # sniff for live packet capture and others for packet-type classification
from flask import Flask, jsonify, render_template_string # For Flask app and rendering of json API and inline HTML
import netStat as ns #Kitsune's own netStat function
import os      #to get process id and absolute output path
import csv     #to write the metrics CSV file
import signal  #to catch Ctrl-C so we can write the CSV before exit
import psutil  #to sample CPU and memory of this process


measure_metrics = True          # If this is false, the detector will not measure any metrics

# ground truth: a packet is a real ATTACK packet if it comes from the attacker host.
# this is required for false positive rate, detection rate and retention ratio,
# because those metrics need the true label of each packet.
# we can find it once inside Mininet with ifconfig on the host h1  
attacker_mac = "ba:55:f3:83:4b:46"  # helps to find the TP,TN,FP,FN

# offline performance of this DNN on the Mininet test set (combination 6) in cross-dataset_evaluation notebook.
# used only to compute the retention ratios = live_metric / offline_metric.
# from the offline confusion matrix (TP=3997, FN=3, FP=1377, TN=2623):
# recall = 3997/4000 = 0.9993 ; attack-class F1 = 0.8528
offline_recall = 0.9993        #  offline recall (detection rate) for this model
offline_f1 = 0.8528            #  offline attack-class F1 for this model

cpu_sample_interval = 1.0       # seconds between CPU/memory samples
metrics_csv = "metrics_summary.csv"   # single output CSV for the whole run

class TorchDNN(nn.Module):
    def __init__(self, n_features):
        super().__init__()
        self.network=nn.Sequential(
            nn.Linear(n_features, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(32,1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.network(x)

class DNNClassifier(BaseEstimator, ClassifierMixin):
    def __init__(self, epochs=50, batch_size=256, lr=0.001, patience=5, random_state=42):
        self.epochs=epochs
        self.batch_size=batch_size
        self.lr=lr
        self.patience=patience
        self.random_state=random_state

    def predict_proba(self, X):
        self.model_.eval()
        X=np.asarray(X, dtype=np.float32)
        with torch.no_grad():
            X_t=torch.tensor(X)
            proba_attack=self.model_(X_t).numpy().flatten()
        proba_benign=1-proba_attack
        return np.column_stack([proba_benign, proba_attack])

    def predict(self, X, threshold=0.5):
        proba=self.predict_proba(X)[:,1]
        return (proba >= threshold).astype(int)

scaler = joblib.load("scaler.pkl") #statnardScaler fit on training data
dnn_model=joblib.load("best_cross_dataset_model_dnn.pkl")  #trained DNN model
dnn_model.model_.eval()  #ensures droput is off for insference
final_featute_columns=joblib.load("final_feature_columns.pkl") # extract exact 102 features

maxHost=100000000000 #maximum hist table size Kitsune netStat will track
maxSession= 100000000000 #maximum session table size
nstat=ns.netStat(np.nan, maxHost, maxSession) #creating the instance of the netStat class
kitsune_headers=nstat.getNetStatHeaders()

interface="mirror0" #the OVS mirror port we sniff live traffic from

attack_logs=[]
log_lock=threading.Lock() #prevents race condition between sniffer thread and Flask thread

metrics_lock = threading.Lock()      # guards every metric structure below
stop_event = threading.Event()       # set on Ctrl-C so threads stop cleanly

latencies_ms = []                    # per-packet detection latency (extraction + inference), in ms
cpu_samples = []                     # cpu_percent samples for this process
memory_samples = []                     # resident memory (MB) samples

# confusion matrix accumulated live using the attacker-MAC ground truth
confusion = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

metrics_summary = {}                 # final computed summary (also print on the dashboard)
run_start_time = None                # set when sniffing starts, it will helps to calculate total run duration

current_process = psutil.Process(os.getpid())  # handle to this detector process for CPU/memory sampling

def parse_packet(packet):
    IPtype=np.nan
    timestamp=packet.time
    framelen=len(packet)
    detected_proto=None

    if packet.haslayer(IP):
        srcIP, dstIP, IPtype = packet[IP].src, packet[IP].dst, 0
    elif packet.haslayer(IPv6):
        srcIP, dstIP, IPtype = packet[IPv6].src, packet[IPv6].dst, 1
    else:
        srcIP, dstIP='', ''

    if packet.haslayer(TCP):
        srcproto, dstproto= str(packet[TCP].sport), str(packet[TCP].dport)
        detected_proto="TCP"
    elif packet.haslayer(UDP):
        srcproto, dstproto= str(packet[UDP].sport), str(packet[UDP].dport)
        detected_proto="UDP"
    else:
        srcproto, dstproto='', ''

    srcMAC, dstMAC=packet.src, packet.dst

    if srcproto=='':
        if packet.haslayer(ARP):
            srcproto = dstproto = 'arp'
            srcIP, dstIP, IPtype=packet[ARP].psrc, packet[ARP].pdst, 0
            detected_proto="ARP"
        elif packet.haslayer(ICMP):
            srcproto = dstproto = 'icmp'
            IPtype=0
            detected_proto="ICMP"
        elif srcIP + srcproto + dstIP + dstproto == '':
            srcIP, dstIP = packet.src, packet.dst

    return IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto, framelen, timestamp, detected_proto


def process_packet(packet):
    IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto, framelen, timestamp, detected_proto = parse_packet(packet)

    # start the detection-latency timer (it includes feature extraction and inference)
    t0 = time.perf_counter()
    try:
        raw_vec=nstat.updateGetStats( IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto, int(framelen), float(timestamp))
    except Exception as e:
        print(f"Exception occured: {e}")
        return

    if len(raw_vec) ==0:
        return

    row=dict(zip(kitsune_headers, raw_vec))  #100 Kitsune Features
    row["length"]=framelen #frame length
    row["proto_ARP"] = 1 if detected_proto == "ARP" else 0 # ARP one-hot protocol as we have only proto_ARP in our training and testing sets

    row_df=pd.DataFrame([row]).reindex(columns=final_featute_columns, fill_value=0) #enforces exact training column order
    scaled=scaler.transform(row_df.values)

    # single inference: keep the probability so the sigmoid-saturation finding is captured
    proba_attack = float(dnn_model.predict_proba(scaled)[0, 1])
    pred = 1 if proba_attack >= 0.5 else 0
    t1 = time.perf_counter()
    latency_ms = (t1 - t0) * 1000.0   # detection latency for this packet
    # latency timer stopped 

    label="ATTACK" if pred ==1 else "BENIGN"

    ts_str=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
    tag = "ATTACK" if label == "ATTACK" else "benign"
    print(f"[{ts_str}] {tag} | {srcIP or srcMAC} --> {dstIP or dstMAC} | proto= {detected_proto} | p(attack)={proba_attack:.3f} | {latency_ms:.2f} ms")

    #  record measurements
    if measure_metrics and not stop_event.is_set():
        # ground truth from attacker MAC: packets sent by the attacker host are real attacks
        true_attack = 1 if (attacker_mac and srcMAC and srcMAC.lower() == attacker_mac.lower()) else 0

        with metrics_lock:
            latencies_ms.append(latency_ms)
            if true_attack == 1 and pred == 1:
                confusion["TP"] += 1
            elif true_attack == 0 and pred == 1:
                confusion["FP"] += 1
            elif true_attack == 0 and pred == 0:
                confusion["TN"] += 1
            elif true_attack == 1 and pred == 0:
                confusion["FN"] += 1
    
    if label=="ATTACK":
        entry = {
            "timestamp": ts_str,
            "src_ip": srcIP,
            "dst_ip": dstIP,
            "src_mac": srcMAC,
            "dst_mac": dstMAC,
            "protocol": detected_proto
        }
        with log_lock:
            attack_logs.insert(0,entry) #newest first

def sample_resources():
    current_process.cpu_percent(None)   # the psutil counter
    while not stop_event.is_set():
        cpu = current_process.cpu_percent(interval=cpu_sample_interval)   # %CPU for this process over the interval
        rss_mb = current_process.memory_info().rss / (1024.0 * 1024.0)    # resident memory in MB
        with metrics_lock:
            cpu_samples.append(cpu)
            memory_samples.append(rss_mb)

def find_percentile(values, q):
    if not values:
        return 0.0
    return float(np.percentile(np.array(values), q))

def finalize_metrics():
    global metrics_summary

    with metrics_lock:
        lat = list(latencies_ms)
        cpus = list(cpu_samples)
        mems = list(memory_samples)
        cm = dict(confusion)

    run_seconds = round(time.time() - run_start_time, 2) if run_start_time else 0.0

    TP, FP, TN, FN = cm["TP"], cm["FP"], cm["TN"], cm["FN"]
    total = TP + FP + TN + FN
    recall = TP / (TP + FN) if (TP + FN) else 0.0          # detection rate
    precision = TP / (TP + FP) if (TP + FP) else 0.0
    fpr = FP / (FP + TN) if (FP + TN) else 0.0             # false positive rate
    accuracy = (TP + TN) / total if total else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    # retention ratios: how much of the offline performance survives live deployment
    retention_recall = (recall / offline_recall) if offline_recall else 0.0
    retention_f1 = (f1 / offline_f1) if offline_f1 else 0.0

    metrics_summary = {
        "run_seconds": run_seconds,
        "packets_measured": total,
        "latency_mean_ms": round(float(np.mean(lat)), 4) if lat else 0.0,
        "latency_median_ms": round(float(np.median(lat)), 4) if lat else 0.0,
        "latency_p95_ms": round(find_percentile(lat, 95), 4),
        "latency_p99_ms": round(find_percentile(lat, 99), 4),
        "latency_max_ms": round(max(lat), 4) if lat else 0.0,
        "cpu_mean_pct": round(float(np.mean(cpus)), 2) if cpus else 0.0,
        "cpu_max_pct": round(float(np.max(cpus)), 2) if cpus else 0.0,
        "mem_mean_mb": round(float(np.mean(mems)), 2) if mems else 0.0,
        "mem_max_mb": round(float(np.max(mems)), 2) if mems else 0.0,
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "recall_detection_rate": round(recall, 4),
        "precision": round(precision, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round(accuracy, 4),
        "f1": round(f1, 4),
        "offline_recall": offline_recall,
        "offline_f1": offline_f1,
        "retention_ratio_recall": round(retention_recall, 4),
        "retention_ratio_f1": round(retention_f1, 4),
    }

    # write the single summary CSV (one metric per row)
    with open(metrics_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        for m, v in metrics_summary.items():
            writer.writerow([m, v])

    # print a summary of this current run to the console once the execution ends
    print("\nSummary of Real-time Detector")
    print(f" run duration (s)        : {run_seconds}")
    print(f" packets measured        : {total}")
    print(f" latency mean / p95 (ms) : {metrics_summary['latency_mean_ms']} / {metrics_summary['latency_p95_ms']}")
    print(f" CPU mean / max (%)      : {metrics_summary['cpu_mean_pct']} / {metrics_summary['cpu_max_pct']}")
    print(f" memory mean / max (MB)  : {metrics_summary['mem_mean_mb']} / {metrics_summary['mem_max_mb']}")
    print(f" confusion TP/FP/TN/FN   : {TP}/{FP}/{TN}/{FN}")
    print(f" detection rate (recall) : {recall:.4f}")
    print(f" false positive rate     : {fpr:.4f}")
    print(f" accuracy / f1           : {accuracy:.4f} / {f1:.4f}")
    print(f" retention (recall)      : {retention_recall:.4f}  (offline recall = {offline_recall})")
    print(f" retention (f1)          : {retention_f1:.4f}  (offline f1 = {offline_f1})")
    print(f" CSV written to          : {os.path.abspath(metrics_csv)}")
    
def get_live_snapshot():
    # snapshot for the dashboard while the run is ongoing
    with metrics_lock:
        n = len(latencies_ms)
        mean_lat = round(float(np.mean(latencies_ms)), 3) if latencies_ms else 0.0
        cm = dict(confusion)
        last_cpu = cpu_samples[-1] if cpu_samples else 0.0
        last_mem = round(memory_samples[-1], 1) if memory_samples else 0.0
    return {
        "packets_measured": n,
        "latency_mean_ms": mean_lat,
        "cpu_pct_last": last_cpu,
        "mem_mb_last": last_mem,
        "confusion": cm,
        "finished": stop_event.is_set(),
    }

def start_sniff():
    global run_start_time
    print(f"Starting live detection on the interface: {interface}")
    print(f"Loaded model: {type(dnn_model).__name__}, expecting {len(final_featute_columns)} features")
    print("Measuring... press Ctrl-C to stop and write the metrics CSV.")
    run_start_time = time.time()
    # stop_filter lets sniff() exit promptly once Ctrl-C sets the stop_event
    sniff(iface=interface, prn=process_packet, store=False,
          stop_filter=lambda pkt: stop_event.is_set())

# Flask APP
app = Flask(__name__)
flask_web="""
<!DOCTYPE html>
<html>
<head>
    <title>ARP Spoofing Detector</title>
    <meta http-equiv="refresh" content="2">
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f5f5f5;
            color: #222;
            margin: 20px;
        }

        h1, h2 {
            color: #333;
            margin-bottom: 10px;
        }

        .count {
            font-size: 18px;
            margin: 10px 0 20px 0;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 25px;
            background: #fff;
        }

        th, td {
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
            font-size: 14px;
        }

        th {
            background: #e9e9e9;
        }

        tr:nth-child(even) {
            background: #fafafa;
        }
    </style>
</head>
<body>
    <h1>Detected ARP spoofing packets</h1>

    <div class="count">
        Total Attack packet detected: {{ attacks|length }}
    </div>

    <h2>Live measurement</h2>
    <table>
        <tr>
            <th>Metric</th>
            <th>Value</th>
        </tr>
        <tr>
            <td>Packets measured</td>
            <td>{{ m.packets_measured }}</td>
        </tr>
        <tr>
            <td>Mean latency (ms)</td>
            <td>{{ m.latency_mean_ms }}</td>
        </tr>
        <tr>
            <td>CPU now (%)</td>
            <td>{{ m.cpu_pct_last }}</td>
        </tr>
        <tr>
            <td>Memory now (MB)</td>
            <td>{{ m.mem_mb_last }}</td>
        </tr>
        <tr>
            <td>TP / FP / TN / FN</td>
            <td>{{ m.confusion.TP }} / {{ m.confusion.FP }} / {{ m.confusion.TN }} / {{ m.confusion.FN }}</td>
        </tr>
    </table>

    <h2>Attack packet log</h2>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Source MAC</th>
            <th>Destination MAC</th>
            <th>Protocol</th>
        </tr>
        {% for a in attacks %}
        <tr>
            <td>{{ a.timestamp }}</td>
            <td>{{ a.src_ip }}</td>
            <td>{{ a.dst_ip }}</td>
            <td>{{ a.src_mac }}</td>
            <td>{{ a.dst_mac }}</td>
            <td>{{ a.protocol }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route("/")
def dashboard():
    with log_lock:
        attacks=list(attack_logs)
    snapshot = get_live_snapshot()
    return render_template_string(flask_web, attacks=attacks, m=snapshot)

@app.route("/api/attacks")
def api_attacks():
    with log_lock:
        return jsonify(list(attack_logs))

@app.route("/api/metrics")
def api_metrics():
    if metrics_summary:
        return jsonify(metrics_summary)
    return jsonify(get_live_snapshot())

def handle_stop(signum, frame):
    # Ctrl-C: stop sniffing, compute and write the CSV, then exit
    if not stop_event.is_set():
        print("\nStopping... writing metrics CSV.")
        stop_event.set()
        if measure_metrics:
            finalize_metrics()
    os._exit(0)   # exit so the daemon threads and Flask stop immediately

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_stop) #When (ctrl+c) clicked the execution stops and print the details of the current run
    sniff_thread=threading.Thread(target=start_sniff, daemon=True)
    sniff_thread.start()

    if measure_metrics:
        resource_thread = threading.Thread(target=sample_resources, daemon=True)
        resource_thread.start()

    app.run(host="0.0.0.0", port=8080)