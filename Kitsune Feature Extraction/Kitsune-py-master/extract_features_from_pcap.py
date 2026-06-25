#import Libraries
import csv # required to read and write the CSV file
import subprocess # to run tshark as an external command
import pandas as pd #to create DataFrames to save CSV files
from FeatureExtractor import FE # importing Kitsunes original FE class from FeatureExtractor.py which is a parent class that handles the PCAP to TSV conversion and feature extraction

#specify the paths for input PCAP and output CSV
PCAP_PATH = r"C:\Users\NARASIMHA N\OneDrive\Desktop\Kitsune Feature Extraction\PCAPs with only 20K Packets\UQ_IOT_IDS_Benign_Dataset.pcap"         
OUTPUT_CSV = r"C:\Users\NARASIMHA N\OneDrive\Desktop\Kitsune Feature Extraction\Kitsune-py-master\Extracted 20k featured CSV files\UQ_IOT_IDS_Benign_Dataset.csv" 
LABEL = "Benign"  # I will change the label to "ARP_Spoofing" if the PCAP is attack PCAP

#Extract these fields mentioned in the FeatureExtraction.py file + one feature _ws.col.Protocol () from PCAPs
FIELDS = (
    "-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst -e _ws.col.Protocol"
)

#Child class that inherit everything from parebt calss FE
class FE_with_protocol(FE):
    def pcap2tsv_with_tshark(self): # only this function is beeing overridden to exttact one extra feature from PCAP
        cmd = (
            f'"{self._tshark}" -r "{self.path}" -T fields {FIELDS} '
            f'-E header=y -E occurrence=f > "{self.path}.tsv"'
        )
        subprocess.run(cmd, shell=True, check=True) # it will run the tshark command on command shell

#function to read TSV filegeberated by tshark and extract only two values per row: Frame length and protocol
def load_tsv_rows(tsv_path):
    rows = []
    with open(tsv_path, "r", encoding="utf8") as f:
        reader = csv.reader(f, delimiter="\t") # creates CSV reader that splits each line by tab character (since it is TSV)
        header = next(reader) #it will skipps the first row (feature headers)
        for row in reader: # it will traverse through every remaining rows of the TSV file
            if len(row) < 20: #it will skips the row which has less than 20 features
                continue
            length = row[1] # reading frame length of that packet
            proto = row[19] if row[19] else "UNKNOWN" # reading the protocol used in that packet if no protocol mention, then it will fill this field with UNKNOWN
            rows.append((length, proto)) # append these two tuple values to the row[] list
    return rows

# the important function that runs full feature extraction pipeline
def extract_features(pcap_path):
    fe = FE_with_protocol(pcap_path) # creating an instance of the child class which authomaticlly triggers the __init__() method in parent calss
    headers = fe.nstat.getNetStatHeaders() # this will get the 100 statistical features 

    tsv_rows = load_tsv_rows(fe.path) # this will loads all (length, protocol) tuples from the TSV file into memory.

    #three empty lists to accumulate the features as we processed each packets
    kitsune_rows = []
    lengths = []
    protocols = []

    i = 0 # to keep track of currently running packet
    while True: # infinite loop untill all packets are processed
        vec = fe.get_next_vector() # this calls the Kitsune's get_next_vector() function. This will read the next row from TSV and updates the running statistics in netStat.py class. and returns a 100-dimensional numpy array of features for this packet.
        if len(vec) == 0: # This condition will check if Kitsune has finished processing all packets
            break # if this contition is true, then the loop will be breaked

        if i >= len(tsv_rows): #  stops the loop if the Kitsune vector count exceeds the number of rows in the TSV file. This prevents index out of bounds errors if there is a mismatch between packet counts.
            break

        length, proto = tsv_rows[i] # Unpacks the (length, protocol) tuple for the current packet from our pre-loaded TSV rows list.
        kitsune_rows.append(vec)  #this will add the 100-statistical Kitsune feature vector for this packet to the list.
        lengths.append(int(length) if str(length).isdigit() else 0) # it will stores the framelength into the length list after converting to integer. If that is not integer or string, then it will be stored as 0
        protocols.append(proto) # it will strores the protocol name to crotocol list.
        i += 1 # updating the packet count

    kitsune_df = pd.DataFrame(kitsune_rows, columns=headers) #it will convert 100 Kitsune fields into pandas DataFrame. So, each eow is 1 packet and each column is one feature
    kitsune_df["length"] = lengths # Adds framelength as a new feature
    proto_onehot = pd.get_dummies(pd.Series(protocols, name="Protocol"), prefix="proto") # One-hot encodes the protocol strings. It converts text like "ARP", "TCP" into binary columns proto_ARP, proto_TCP etc and each packet gets a True in its protocol column and False in all others.
    df = pd.concat([kitsune_df, proto_onehot], axis=1) #it will combine the Kitsune features, frame length, and one-hot protocol columns into one DataFrame side by side using axis=1

    if LABEL is not None: # This will add the label to each and every row as mentioned above
        df["label"] = LABEL

    df.to_csv(OUTPUT_CSV, index=False) # this will save the complete dataframe to CSV
    print(f"Conversion of PCAP to CSV is done. \nThe CSV file is stored in: \n {OUTPUT_CSV}: {df.shape[0]} rows x {df.shape[1]} columns") # printing the success message on console

if __name__ == "__main__": # main function
    extract_features(PCAP_PATH) # entry point of the program    