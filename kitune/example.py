from Kitsune import Kitsune
import numpy as np
import time
import pandas as pd
from scipy import stats

##############################################################################
# Kitsune a lightweight online network intrusion detection system based on an ensemble of autoencoders (kitNET).
# For more information and citation, please see our NDSS'18 paper: Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection

# This script demonstrates Kitsune's ability to incrementally learn, and detect anomalies in recorded a pcap of the Mirai Malware.
# The demo involves an m-by-n dataset with n=115 dimensions (features), and m=100,000 observations.
# Each observation is a snapshot of the network's state in terms of incremental damped statistics (see the NDSS paper for more details)

#The runtimes presented in the paper, are based on the C++ implimentation (roughly 100x faster than the python implimentation)
###################  Last Tested with Anaconda 3.6.3   #######################

# Load Mirai pcap (a recording of the Mirai botnet malware being activated)
# The first 70,000 observations are clean...
# print("Unzipping Sample Capture...")
# import zipfile
# with zipfile.ZipFile("mirai.zip","r") as zip_ref:
#     zip_ref.extractall() #解压缩
import os

packet_limit = np.Inf #the number of packets to process
# KitNET params:
maxAE = 10 #maximum size for any autoencoder in the ensemble layer
FMgrace = 200 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
ADgrace = 0 #the number of instances used to train the anomaly detector (ensemble itself)


def wirte_tsv(root):
	total_file = "total_feature.tsv"
	i = 0
	for dirpath, dirnames, filenames in os.walk(root):
		for filename in filenames:
			path = os.path.join(dirpath, filename)
			# File location
			#path = "train_00000_20220111130000.pcap" #the pcap, pcapng, or tsv file to process.
			if ".tsv" in path:
				print(path)
				data = pd.read_csv(path,skipinitialspace=True,header=0,sep='\t')
				train_data = data[0:]
				with open(total_file,'a+') as write_tsv:
					write_tsv.write(train_data.to_csv(sep='\t',index=False))
				i = i + 1

def parse_pcap(root):
	i = 0
	for dirpath, dirnames, filenames in os.walk(root):
		for filename in filenames:
			path = os.path.join(dirpath, filename)	
			K = Kitsune(path,packet_limit,maxAE,FMgrace,ADgrace) #读了文件第一行字段名称


def kitsune(file_path):



	# file_path = "total_feature.tsv"
	# file_path = '../2022champion_100_100/black/abddfadab35f01664952aec80a594cce.pcap'
	#



	packet_limit = np.Inf #the number of packets to process
	# KitNET params:
	maxAE = 10 #maximum size for any autoencoder in the ensemble layer
	FMgrace = 200 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
	ADgrace = 10 #the number of instances used to train the anomaly detector (ensemble itself)
	# Build Kitsune
	K = Kitsune(file_path,packet_limit,maxAE,FMgrace,ADgrace) #读了文件第一行字段名称



	print("Running Kitsune:")
	RMSEs = []
	RMSEs_ensembleLayer = []
	i = 0
	execute_cnt = 0
	autoencoders_num = 0
	start = time.time()
	# Here we process (train/execute) each individual packet.
	# In this way, each observation is discarded after performing process() method.
	while i<400000:
		i+=1
		if i % 1000 == 0:
			print(i)
		rmse, rmses_ensembleLayer = K.proc_next_packet()
		if rmse == -1:
			break
		RMSEs.append(rmse)
		print(rmse)
		if i > FMgrace + ADgrace+1: #可能需要 +1 因为不知道为啥执行阶段第一个样本rmses_ensembleLayer是没有的
			RMSEs_ensembleLayer.append(rmses_ensembleLayer)
	RMSEs_ensembleLayer = np.array(RMSEs_ensembleLayer)
	np.save("train_feature.npy",RMSEs_ensembleLayer)
	stop = time.time()
	print("Complete. Time elapsed: "+ str(stop - start))



#kitsune('../2022champion_100_100/black/abddfadab35f01664952aec80a594cce.pcap')
parse_pcap('../2022champion_100_100/black/')
