from flowmeter.flowmeter import Flowmeter


def pcap2csv(filepath):
    feature_gen = Flowmeter(filepath)

    df = feature_gen.build_feature_dataframe()
    csvpath = filepath.split('.pcap')[0]+'.csv'
    df.to_csv(csvpath)
    return csvpath
