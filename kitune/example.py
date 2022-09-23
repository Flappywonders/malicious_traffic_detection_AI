import array

from Kitsune import Kitsune
import numpy as np
import time
import pandas as pd
from scipy import stats
import argparse
import os

from kitune.FeatureExtractor import FE

packet_limit = np.Inf #the number of packets to process
maxAE = 10 #maximum size for any autoencoder in the ensemble layer
FMgrace = 200 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
ADgrace = 0 #the number of instances used to train the anomaly detector (ensemble itself)


def write_tsv(root):

	i = 0
	for dirpath, dirnames, filenames in os.walk(root):
		for filename in filenames:
			path = os.path.join(dirpath, filename)
			# File location
			#path = "train_00000_20220111130000.pcap" #the pcap, pcapng, or tsv file to process.
			if ".tsv" in path:
				if os.path.getsize(path)/float(1024)> 512:
					continue
				print(path)
				data = pd.read_csv(path,skipinitialspace=True,header=0,sep='\t')
				train_data = data[0:]
				if i == 0:
					with open(total_file,'a+') as write_tsv:
						write_tsv.write(train_data.to_csv(sep='\t',index=False))
					i = i + 1
				else:
					with open(total_file,'a+') as write_tsv:
						write_tsv.write(train_data.to_csv(sep='\t',index=False,header=None))


def parse_pcap(root):
	for dirpath, dirnames, filenames in os.walk(root):
		for filename in filenames:
			path = os.path.join(dirpath, filename)
			K = Kitsune(path,packet_limit,maxAE,FMgrace,ADgrace) #读了文件第一行字段名称


def kitsune(type):
	if type == "train":
		white_file = "train_feature_white.tsv"
		black_file = "train_feature_black.tsv"
	elif type == "test":
		white_file = "test_feature_white.tsv"
		black_file = "test_feature_black.tsv"
	packet_limit = np.Inf #the number of packets to process
	# KitNET params:
	maxAE = 10 #maximum size for any autoencoder in the ensemble layer
	FMgrace = 200 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
	ADgrace = 10 #the number of instances used to train the anomaly detector (ensemble itself)
	# Build Kitsune
	K_white = Kitsune(white_file,packet_limit,maxAE,FMgrace,ADgrace) #读了文件第一行字段名称
	K_black = Kitsune(black_file,packet_limit,maxAE,FMgrace,ADgrace)


	print("Running Kitsune:")
	RMSEs = []
	RMSEs_ensembleLayer = []
	label = []
	i = 0
	start = time.time()
	# Here we process (train/execute) each individual packet.
	# In this way, each observation is discarded after performing process() method.
	while i<400000:
		i+=1
		if i % 1000 == 0:
			print(i)
		rmse, rmses_ensembleLayer = K_white.proc_next_packet()
		#print(rmses_ensembleLayer)
		if rmse == -1:
			break
		RMSEs.append(rmse)
		#print(rmse)
		if i > FMgrace + ADgrace+1: #可能需要 +1 因为不知道为啥执行阶段第一个样本rmses_ensembleLayer是没有的
			RMSEs_ensembleLayer.append(rmses_ensembleLayer)
			label.append(0)
	i = 0
	while i<400000:
		i+=1
		if i % 1000 == 0:
			print(i)
		rmse, rmses_ensembleLayer = K_black.proc_next_packet()
		#print(rmses_ensembleLayer)
		if rmse == -1:
			break
		RMSEs.append(rmse)
		#print(rmse)
		if i > FMgrace + ADgrace+1: #可能需要 +1 因为不知道为啥执行阶段第一个样本rmses_ensembleLayer是没有的
			RMSEs_ensembleLayer.append(rmses_ensembleLayer)
			label.append(1)
	RMSEs_ensembleLayer = np.array(RMSEs_ensembleLayer)
	label = np.array(label)
	if type == "train":
		np.save("train_feature.npy",RMSEs_ensembleLayer)
		np.save("train_label.npy",label)
	elif type == "test":
		np.save("test_feature.npy",RMSEs_ensembleLayer)
		np.save("test_label.npy",label)
	stop = time.time()
	print("Complete. Time elapsed: "+ str(stop - start))



if __name__ == '__main__':
	parse = argparse.ArgumentParser()
	parse.add_argument('--model', type=str, help='parse pcap or running kitsune',default=None)
	parse.add_argument('--type', type=str, help='train or test',default=None)
	parse.add_argument('--root', type=str, help='pcap package location',default=None)
	args = parse.parse_args()
	#root = "train_white"
	# if args.model == "parse":
	# 	#parse_pcap(args.root)
	# 	write_tsv(args.root)
	# elif args.model == "kitsune":
	# 	kitsune(args.type)

	# M = np.load('test_feature.npy',allow_pickle=True)
	# L = np.load('test_label.npy',allow_pickle=True)
	# for i in range(len(M)):
	# 	print(len(M[i]),L[i])

	#
	# for dirpath, dirnames, filenames in os.walk('../../pcaps_divided/train_white'):
	# 	i = 0
	# 	for filename in filenames:
	# 		path = os.path.join(dirpath, filename)
	# 		# File location
	# 		#path = "train_00000_20220111130000.pcap" #the pcap, pcapng, or tsv file to process.
	# 		if ".tsv" in path:
	# 			data = pd.read_csv(path,skipinitialspace=True,header=0,sep='\t')
	# 			train_data = data[0:]
	# 			with open('base_white.tsv','a+') as write_tsv:
	# 				write_tsv.write(train_data.to_csv(sep='\t',index=False,header=None))
	#

	#
	data = pd.read_csv('./test_feature_black.tsv',skipinitialspace=True,header=0,sep='\t')
	train_data = data[0:]
	with open('base_black.tsv','a+') as write_tsv:
		write_tsv.write(train_data.to_csv(sep='\t',index=False,header=None))
	data = pd.read_csv('./train_feature_black.tsv',skipinitialspace=True,header=0,sep='\t')
	train_data = data[0:]
	with open('base_black.tsv','a+') as write_tsv:
		write_tsv.write(train_data.to_csv(sep='\t',index=False,header=None))

	# data = pd.read_csv('../train_feature_white.tsv',skipinitialspace=True,header=0,sep='\t')
	# train_data = data[0:]
	# with open('base_white.tsv','a+') as write_tsv:
	# 	write_tsv.write(train_data.to_csv(sep='\t',index=False))

	# data = pd.read_csv('../test_feature_black.tsv',skipinitialspace=True,header=0,sep='\t')
	# train_data = data[0:]
	# with open('total.tsv','a+') as write_tsv:
	# 	write_tsv.write(train_data.to_csv(sep='\t',index=False))
	# # data = pd.read_csv('../train_feature_black.tsv',skipinitialspace=True,header=0,sep='\t')
	# # train_data = data[0:]
	# # with open('total.tsv','a+') as write_tsv:
	# # 	write_tsv.write(train_data.to_csv(sep='\t',index=False,header=None))
	# with open('total.tsv','a+') as write_tsv:
	# 	write_tsv.write('break	break\n')
	# # data = pd.read_csv('train_feature_white.tsv',skipinitialspace=True,header=0,sep='\t')
	# # train_data = data[0:]
	# # with open('total.tsv','a+') as write_tsv:
	# # 	write_tsv.write(train_data.to_csv(sep='\t',index=False,header=None))
	# data = pd.read_csv('../test_feature_white.tsv',skipinitialspace=True,header=0,sep='\t')
	# train_data = data[0:]
	# with open('total.tsv','a+') as write_tsv:
	# 	write_tsv.write(train_data.to_csv(sep='\t',index=False,header=None))

	# # KitNET params:
	# maxAE = 10 #maximum size for any autoencoder in the ensemble layer
	# FMgrace = 200 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
	# ADgrace = 10 #the number of instances used to train the anomaly detector (ensemble itself)
	#
	# total = Kitsune('total.tsv',packet_limit,maxAE,FMgrace,ADgrace)
	# print("Running Kitsune:")
	# #RMSEs = []
	# RMSEs_ensembleLayer = []
	# i = 0
	# start = time.time()
	# Here we process (train/execute) each individual packet.
	# In this way, each observation is discarded after performing process() method.
	# while True:
	# 	i+=1
	# 	if i % 100000 == 0:
	# 		print(i)
	# 		#RMSEs_ensembleLayer = np.array(RMSEs_ensembleLayer)
	# 		np.save('blackfeatures'+str(i)+'.npy',RMSEs_ensembleLayer)
	# 		RMSEs_ensembleLayer = []
	# 	rmse, rmses_ensembleLayer = total.proc_next_packet()
	# 	#print(rmses_ensembleLayer)
	# 	if rmse == -1:
	# 		break
	# 	#RMSEs.append(rmse)
	# 	#print(rmse)
	# 	if i > FMgrace + ADgrace+1: #可能需要 +1 因为不知道为啥执行阶段第一个样本rmses_ensembleLayer是没有的
	# 		RMSEs_ensembleLayer.append(rmses_ensembleLayer)
	# #RMSEs_ensembleLayer = np.array(RMSEs_ensembleLayer)
	# np.save('blackfeatures'+str(i)+'.npy',RMSEs_ensembleLayer)
	# RMSEs_ensembleLayer = []
	# i = 0
	# while i<400000:
	# 	i+=1
	# 	if i % 100000 == 0:
	# 		print(i)
	# 		#RMSEs_ensembleLayer = np.array(RMSEs_ensembleLayer)
	# 		np.save('whitefeatures'+str(i)+'.npy',RMSEs_ensembleLayer)
	# 		RMSEs_ensembleLayer = []
	# 	rmse, rmses_ensembleLayer = total.proc_next_packet()
	# 	#print(rmses_ensembleLayer)
	# 	if rmse == -1:
	# 		break
	# 	#RMSEs.append(rmse)
	# 	#print(rmse)
	# 	RMSEs_ensembleLayer.append(rmses_ensembleLayer)
	# #RMSEs_ensembleLayer = np.array(RMSEs_ensembleLayer)
	# np.save('whitefeatures'+str(i)+'.npy',RMSEs_ensembleLayer)
	# RMSEs_ensembleLayer = []
	#
	# stop = time.time()
	# print("Complete. Time elapsed: "+ str(stop - start))
