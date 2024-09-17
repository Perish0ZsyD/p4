#!/usr/bin/env python3
import sys
import time

from probe_hdrs import *
from mycontroller import *


def main():

    probe_pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=get_if_hwaddr('eth0')) / \
                Probe(hop_cnt=0) / \
                ProbeFwd(egress_spec=3) / \
                ProbeFwd(egress_spec=3) / \
                ProbeFwd(egress_spec=4) / \
                ProbeFwd(egress_spec=2) / \
                ProbeFwd(egress_spec=1) / \
                ProbeFwd(egress_spec=1) / \
                ProbeFwd(egress_spec=1) / \
                ProbeFwd(egress_spec=1) / \
                ProbeFwd(egress_spec=1) / \
                ProbeFwd(egress_spec=4) 
                                
    while True:
        try:
            sendp(probe_pkt, iface='eth0')
            time.sleep(0.01)
        except KeyboardInterrupt:
            sys.exit()

if __name__ == '__main__':
    main()
    #ITGRecv
    #ITGSend -a 10.0.1.1 -T TCP -C 1000 -c 5000 -t 2000000
    #tcprewrite --srcipmap=0.0.0.0/0:x.x.x.x --dstipmap=0.0.0.0/0:x.x.x.x --enet-dmac=x:x:x:x:x:x --enet-smac=x:x:x:x:x:x  --infile=test.pcap --outfile=1.pcap -C
    #tcpreplay -i eth0 -p 1000 -l 100000000 1.pcap

