#!/usr/bin/env python3

from probe_hdrs import *
from mycontroller import *
import pandas as pd

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def handle_pkt(pkt):
    # bit_cnt = []
    # pkt_num = []
    # Queue_size = []
    if ProbeData in pkt:
        data_layers = [l for l in expand(pkt) if l.name=='ProbeData']
        print("")
        for sw in data_layers:
            utilization = []
            utilization0 = 0 if sw.cur_time == sw.last_time else 8.0*sw.byte_cnt/(sw.cur_time - sw.last_time)
            utilization1 = 0 if sw.cur_time == sw.last_time else 1000000*sw.pkt_num/(sw.cur_time - sw.last_time)
            utilization2 = 0 if sw.cur_time == sw.last_time else 1000000*sw.queue_size/(sw.cur_time - sw.last_time)
            utilization3 = 0 if sw.cur_time == sw.last_time else (sw.cur_time - sw.last_time)/1000000
            # print("Switch {} - Port {}: {} Mbps,{}pkt_num/s, QueueSize:{}, Current_time:{}, Last_time:{}".format(sw.swid, sw.port, utilization0, utilization1, utilization2, sw.cur_time, sw.last_time))
            print("Switch {} - Port {}: {} Mbps,{}pkt_num/s, QueueSize:{}".format(sw.swid, sw.port, utilization0, utilization1, utilization2))
            utilization.append(utilization0)
            utilization.append(utilization1)
            utilization.append(utilization3)
            df = pd.DataFrame(utilization)
            df.to_csv('./csv/h1.csv', mode ='a', header=False,index=False)

def main():
    iface = 'eth0'
    print("sniffing on {}".format(iface))
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
