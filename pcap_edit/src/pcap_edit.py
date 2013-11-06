# -*- coding: utf-8 -*- 

import dpkt
import socket

print u"モジュールのロード"

def main():
    filename = u'../pcap/iperf-he-24-0.pcap'
    #filename = u'../pcap/01.pcap'
    pcr = dpkt.pcap.Reader(open(filename, 'rb'))
    packet_count = 0
    flow_list = {}
    
    for ts,buf in pcr:
        packet_count += 1
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            print 'Fail parse FrameNo:', packet_count, '. skipped.'
            continue
        
        print ts

        """if type(eth.data) == dpkt.ip.IP:
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            flow_word = src + " to " + dst
            if flow_list.has_key(flow_word):
                flow_list[flow_word] += len(str(buf))
            else:
                flow_list[flow_word] = len(str(buf))"""

    for k,v in flow_list.iteritems():
        print k, ':', v, '[Byte]'

if __name__ == '__main__':
    main()