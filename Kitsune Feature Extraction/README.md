For feature Extraction, Kitsune Feature Extraction method is used. The entire Github repository (https://github.com/ymirsky/Kitsune-py) was downloaded to the host machine and a custom python script was developed to extract required features from PCAP files.  

The Kitsune Feature Extraction module is responsible only for generating 100 statistical features using the python scripts FeatureExtraction.py, netstat.py and AfterImage.py. 

To obtain additional features such as Protocol and one-hot encoded protocol features, a new script must be developed to extracts these wireshark features (frame.len and _ws.col.Protocol) directly from the PCAP file. These features are then concatenated with the corresponding packet flow in the CSV file produced by Kitsune Feature Extraction approach.  

Kitsune Master directory contains all the feature extraction scripts.

Merged PCAP Files:
The merged PCAP files contain the original PCAP files combined into a single PCAP per class. If a dataset class contained multiple PCAP files, they were merged as follows:


CICIoT2023 : Attack (2 PCAPs) Merged into 1 PCAP  : Benign (4 PCAPs) Merged into 1 PCAP
IoTNID	   : Attack (6 PCAPs) Merged into 1 PCAP  : Benign (1 PCAP)
UQIOT      : Attack (8 PCAPs) Merged into 1 PCAP  : Benign (1 PCAP)
These PCAP files were stored in: "Kitsune Feature Extraction\MergedPCAPs".

Initially, these PCAPs were used directly in the extract_features_from_pcap.py script to extract 100 Kitsune Features, one frame length feature and one-hot encoded protocol features for every packet. However, while extracting features from benign PCAPs of the UQIoT and CICIoT datasets, the process required more than 30 hours to complete for single PCAP file because the datasets contains approximately 17 million and 11 million packets respectively. 

Therefore, it was decided to use only 20000 packets for each class (attack and benign). To achieve this, Wireshark's editcap.exe utility was utilized to extract first 20000 packets from each PCAP file.


Using Wireshark's editpcap.exe, 20,000 packets were extracted from each merged PCAPs using the command: "editcap.exe -r input_file.pcap output_file.pcap 1-20000". The resulting PCAP files, each containing 20000 packets were stored in:  "Kitsune Feature Extraction\PCAPs with only 20K Packets".

PCAPs with only 20k Flows : 20000 packets were separated from each merged PCAPs
Using these PCAPs, Kitsune Feature Extractor generates 20000 rows per class (example, 20000 Attack rows and 20000 Benign rows for each dataset)


Dataset Preprocessing is having the four folders:

1. Remove Uncommon features:
 	This directory contains a jupyter notebook (remove_uncommon_features.ipynb), which removes the uncommon featres from all three datasets. And finally, it will produce the same set of features across all datasets.
	This folder also contains CSV files (20k flows in all CSV files with 104 features including label). However, UQIoT dataset's attack dataset contains only 15302 rows.

2. CICIoT2023 Dataset:
	This directory has two subdirectories:
	i)  Test and Train Sets: It contains separate testing and training CSV files
	ii) .ipynb_checkpoints: It has two jupyter notebook files, one notebook splits the datasets into training and testing sets. The other notebook trains and evaluates models on the CICIoT Dataset.

3. IoT Network Intrusion Dataset:
	This directory has two subdirectories:
	i)  Test and Train Sets: It contains separate testing and training CSV files
	ii) .ipynb_checkpoints: It has two jupyter notebook files, one notebook splits the datasets into training and testing sets. The other notebook trains and evaluates models on the IoT-Network Intrusion Dataset.

4. UQ-IoT Dataset:
	This directory has two subdirectories:
	i)  Test and Train Sets: It contains separate testing and training CSV files
	ii) .ipynb_checkpoints: It has two jupyter notebook files, one notebook splits the datasets into training and testing sets. The other notebook trains and evaluates models on the UQ-IoT Dataset.

5. Cross-Dataset Evaluation:
	This directory contains a Jupyter notebooook and a directory named outpts:
	i) The jupyter notebook is used for cross-dataset evaluation. It  trains a model on training set of one dataset and tests the trained model on the testing set of another dataset. The results show that the models failed to generalize across different datasets, even though they achieve near-perfect F1 scores when both training nad testing performed on the same dataset. 
	ii) The outputs directory contains the results of the above notebook. These inculde confusion matrices of all 36 experiments (6 dataset combinations X 6 models), a heatmap for visualize the results and an Excel file that shows the results in tabular format. 