from flowmeter.flowmeter import Flowmeter


def pcap2csv(filepath):
    feature_gen = Flowmeter(filepath)

    df = feature_gen.build_feature_dataframe()
    df.to_csv(filepath.split('.pcap')[0]+'.csv')

