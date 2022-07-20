import pyshark
import datetime
import pandas as pd
from dfModel import model


def update_l2(frame, model):
    model["timestamp"].append(frame.sniff_time)
    model["smac"].append(frame.eth.src)
    model["dmac"].append(frame.eth.dst)

def update_l3(frame, model):
    model["ipId"].append(frame.ip.id)
    model["ttl"].append(frame.ip.ttl)
    model["sip"].append(frame.ip.src)
    model["dip"].append(frame.ip.dst)

def update_l4(frame, model):
    model["sport"].append(frame.tcp.srcport)
    model["dport"].append(frame.tcp.dstport)
    model["msslen"].append(frame.tcp.len)
    model["rseq"].append(frame.tcp.seq)
    model["rack"].append(frame.tcp.ack)
    model["nseq"].append(frame.tcp.nxtseq)
    model["flags_reset"].append(frame.tcp.flags_reset)
    model["flags_cwr"].append(frame.tcp.flags_cwr)
    model["flags_urg"].append(frame.tcp.flags_urg)
    model["flags_ack"].append(frame.tcp.flags_ack)
    model["flags_push"].append(frame.tcp.flags_push)
    model["flags_syn"].append(frame.tcp.flags_syn)
    model["flags_fin"].append(frame.tcp.flags_fin)


if __name__ == "__main__":
    start = datetime.datetime.now().replace(microsecond=0)
    count = 0
    read_pcap = pyshark.FileCapture("HTTP.cap")

    for packet in read_pcap:
        count += 1
        update_l2(packet, model)
        update_l3(packet, model)
        update_l4(packet, model)

    dataFrame = pd.DataFrame(model)
    dataFrame.to_excel("HTTP.xlsx")
    end = datetime.datetime.now().replace(microsecond=0)
    print(f"captured frames: {count}")
    print(f"time to convert to data frame: {end - start}")
