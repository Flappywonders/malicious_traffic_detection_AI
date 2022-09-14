import pandas as pd



def csv2vec(csvpath):
    csvfile = pd.read_csv(csvpath)
    print(csvfile)