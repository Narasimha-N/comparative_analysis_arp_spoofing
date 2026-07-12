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

    def predict_proba(self,X):
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
     
     row_df=pd.DataFrame([row]).reindex(columns=final_featute_columns, fill_value=0) #enforces exatc training column order
     scaled=scaler.transform(row_df.values)
     pred=dnn_model.predict(scaled)[0]
     label="ATTACK" if pred ==1 else "BENIGN"
     
     ts_str=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
     tag = "ATTACK" if label == "ATTACK" else "benign"
     print(f"[{ts_str}] {tag} | {srcIP or srcMAC} --> {dstIP or dstMAC} | proto= {detected_proto}")
     
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
             
def start_sniff():
    print(f"Starting live detection on the interface: {interface}")
    print(f"Loaded model: {type(dnn_model).__name__}, expecting {len(final_featute_columns)} features")
    sniff(iface=interface, prn=process_packet, store=False)
    

# Flask APP

app = Flask(__name__)

flask_web="""
<!DOCTYPE html>
<html>
    <head>
        <title>ARP spoofing RealTime Detector</title>
        <meta http-equiv="refresh" content="2">
        <style>
            body {font-family: monospace; background: #111; color: #eee; margin: 20px;}
            h1 {color: #ff555f;}
            table {border-collapse: collapse; width: 100%;}
            th, td {border: 1px solid #444; padding: 8px; text-align: left; font-size: 12px;}
            th {background: #222;color: #ff555f;}
            tr:nth-child(even) {background: #1a1a1a;}
            .count {color: #fa0; font-size: 18px; margin-bottom: 10px;}
        </style>
    </head>
    <body>
        <h1> Detected ARP spoofing packets </h1>
        <div class="count"> Total Attack packet detected: {{attacks|length}} </div>
        <table>
            <tr>
                <th> Timestamp </th> <th> Source IP</th> <th> Destination IP </th> <th> Source MAC </th> <th> Destination MAC </th>
                <th>Protocol </th>
            </tr>
            {% for a in attacks %}
            <tr>
                <td>{{a.timestamp}}</td>
                <td>{{a.src_ip}}</td>
                <td>{{a.dst_ip}}</td>
                <td>{{a.src_mac}}</td>
                <td>{{a.dst_mac}}</td>
                <td>{{a.protocol}}</td>
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
    return render_template_string(flask_web, attacks=attacks)

@app.route("/api/attacks")
def api_attacks():
    with log_lock:
        return jsonify(list(attack_logs))
        
if __name__ == "__main__":
    sniff_thread=threading.Thread(target=start_sniff, daemon=True)
    sniff_thread.start()
    app.run(host="0.0.0.0", port=8080)
