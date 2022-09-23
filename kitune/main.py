import argparse
import os
from copy import deepcopy

import numpy as np
import pandas as pd
from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.utils import shuffle

from Kitsune import *
from sklearn.ensemble import RandomForestClassifier

packet_limit = np.Inf  # the number of packets to process
maxAE = 10  # maximum size for any autoencoder in the ensemble layer
FMgrace = 200  # the number of instances taken to learn the feature mapping (the ensemble's architecture)
ADgrace = 10  # the number of instances used to train the anomaly detector (ensemble itself)


paths = []
def parse_pcap(root):
    for dirpath, dirnames, filenames in os.walk(root):
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            paths.append(path)
            K = Kitsune(path, packet_limit, maxAE, FMgrace, ADgrace)  # 读了文件第一行字段名称


def write_tsv(root):
    for dirpath, dirnames, filenames in os.walk(root):
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            # File location
            # path = "train_00000_20220111130000.pcap" #the pcap, pcapng, or tsv file to process.
            if ".tsv" in path:
                print(path)
                data = pd.read_csv(path, skipinitialspace=True, header=0, sep='\t')
                train_data = data[0:]
                with open('./base_test.tsv', 'a+') as write_tsv:
                    write_tsv.write('break	break\n')
                    write_tsv.write(train_data.to_csv(sep='\t', index=False, header=None))


if __name__ == '__main__':
    parse = argparse.ArgumentParser()
    parse.add_argument('--root', type=str, help='pcap package location', default=None)
    args = parse.parse_args()

    start = time.time()



    ###
    # step0: install wireshark on default path, and install the packages in requirements.txt
    ###
    ###
    # step1: gen the train features and labels, it takes 20-30 minutes on my  intel i5 cpu
    ###
    # blackkitsune = Kitsune('base_black.tsv', packet_limit, maxAE, FMgrace, ADgrace)
    # whitekitsune = Kitsune('base_white.tsv', packet_limit, maxAE, FMgrace, ADgrace)
    testkitsune = Kitsune('base_test.tsv', packet_limit, maxAE, FMgrace, ADgrace)
    # #
    # print("begin feature generation")
    # RMSEs_ensembleLayer = []
    # labels = []
    # i = 0
    # print('Generate black features')
    # # black features for training
    # while True:
    #     i += 1
    #     rmse, rmses_ensembleLayer = blackkitsune.proc_next_packet()
    #     #print(rmses_ensembleLayer)
    #     if rmse == -1:
    #         break
    #     if i > FMgrace + ADgrace + 2:  # todo :find why +2
    #         RMSEs_ensembleLayer.append(rmses_ensembleLayer)
    #         labels.append(0)
    # print('Generate white features')
    # # white features for training
    # i = 0
    # while True:
    #     i += 1
    #     rmse, rmses_ensembleLayer = whitekitsune.proc_next_packet()
    #     if rmse == -1:
    #         break
    #     if i > FMgrace + ADgrace + 2:  # todo :find why +2
    #         RMSEs_ensembleLayer.append(rmses_ensembleLayer)
    #         labels.append(1)
    # # save the train data
    # np.save('train_feature.npy',RMSEs_ensembleLayer)
    # np.save('train_label.npy',labels)


    ###
    # step2: train the model
    ###
    print('Run RandomForestClassifier')
    X = np.load('train_feature.npy',allow_pickle=True)
    Y = np.load('train_label.npy',allow_pickle=True)
    X_train,Y_train = shuffle(X,Y)
    print('shape: ',X.shape,Y.shape)
    X_train = preprocessing.scale(X_train)
    rf = RandomForestClassifier(n_estimators=100)
    rf.fit(X_train,Y_train)

    ###
    # step3: run the test
    ###
    i = 0
    while i < FMgrace + ADgrace + 2:
        i += 1
        rmse, rmses_ensembleLayer = testkitsune.proc_next_packet()


    # please modify the path
    test_root = '../2022champion_100_100/white/'
    final = open('../results.txt','w')
    for dirpath, dirnames, filenames in os.walk(test_root):
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            if not (path.split('.')[-1] == 'pcap' or path.split('.')[-1] == 'pcapng'):
                continue
            print(path)
            Kitsune(path, packet_limit, maxAE, FMgrace, ADgrace)
            tsvf = open(path+'.tsv','r')
            packgeSize = len(tsvf.readlines())
            tsvf.close()
            tsvf = open(path+'.tsv','r')
            testkitsune.FE.tsvin = csv.reader(tsvf, delimiter='\t')
            rmses_ensembleLayer_record = []
            for i in range(packgeSize):
                rmse, rmses_ensembleLayer = testkitsune.proc_next_packet()
                #print(rmse,rmses_ensembleLayer)
                if rmse != -1:
                    rmses_ensembleLayer_record.append(rmses_ensembleLayer)


            y = rf.predict(preprocessing.scale(rmses_ensembleLayer_record))
            print(list(y).count(0)/len(y))
            if list(y).count(0)/len(y) < 0.32:
                final_result = 1
            else:
                final_result = 0
            print(filename+str(final_result)+'\n')
            final.write(filename+','+str(final_result)+'\n')
            tsvf.close()
    final.close()



    stop = time.time()
    print("Complete. Time elapsed: " + str(stop - start))
