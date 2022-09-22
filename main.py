import argparse
import os

import numpy as np
import pandas as pd

from kitune.Kitsune import *



packet_limit = np.Inf #the number of packets to process
# KitNET params:
maxAE = 10 #maximum size for any autoencoder in the ensemble layer
FMgrace = 200 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
ADgrace = 10 #the number of instances used to train the anomaly detector (ensemble itself)


def parse_pcap(root):
    for dirpath, dirnames, filenames in os.walk(root):
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            K = Kitsune(path, packet_limit, maxAE, FMgrace, ADgrace) #读了文件第一行字段名称


def write_tsv(root):
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
                with open('./kitune/total.tsv','a+') as write_tsv:
                    write_tsv.write('break	break\n')
                    write_tsv.write(train_data.to_csv(sep='\t',index=False))


if __name__ == '__main__':
    parse = argparse.ArgumentParser()
    parse.add_argument('--root', type=str, help='pcap package location',default=None)
    args = parse.parse_args()

    ###
    # step0: install wireshark on default path, and install the packages in requirements.txt
    ###
    ###
    # step1: put the root path of pcaps into this fun
    ###
    parse_pcap(args.root)
    ###
    # step2: put all data in the generated .tsv file into one file
    ###
    write_tsv(args.root)
