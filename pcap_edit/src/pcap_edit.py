# -*- coding: utf-8 -*- 

import dpkt
import socket
import struct
import binascii
import ctypes
import csv

#Fix value for judge
ETH_PROTOCOL_IP = '0021'
ETH_FLAG_START = 'd002'
ETH_FLAG_FIN = 'a011'

def hex2decima_int(string):
    return int(string, 16)

def hex2decima(hexa):
    tmp=hex2decima_int(hexa)
    return str(tmp)
def print_r(obj):
    for word in obj:
        print word
def adrs_convert(adrs_txt):
    try:
        adrs_tmp=[adrs_txt[0:2], adrs_txt[2:4], adrs_txt[4:6], adrs_txt[6:8]]
        adrs=''
    except:
        return False
    for part in adrs_tmp:
        adrs = adrs + hex2decima(part) + '.'
    adrs=adrs.rstrip('.')
    return adrs

class Test:
    class Pcap_edit:
        __counter = 0
        __stream_index=[]
        __info_box=[]
        __trigger_box=[]
        def __init__(self, buf, ts, stream):
            self.buf = binascii.hexlify(buf)
            self.proto=self.buf[0:4]
            self.src_adr=adrs_convert(self.buf[28:36])
            self.dst_adr=adrs_convert(self.buf[36:44])
            self.src_port=hex2decima(self.buf[44:48])
            self.dst_port=hex2decima(self.buf[48:52])
            self.seq=hex2decima_int(self.buf[52:60])
            self.ack=hex2decima_int(self.buf[60:68])
            self.flag=self.buf[68:72]
            self.ts=ts
            self.stream_index=stream
            self.len=len(buf)
            
        
        def detect_start(self):
            tmp_box = []
            if self.proto == ETH_PROTOCOL_IP: #IP PROTOCOL
                if self.flag == ETH_FLAG_START:
                    tmp_box.append(self.src_port)
                    tmp_box.append(self.src_adr)
                    tmp_box.append(self.dst_adr)
                    tmp_box.append(self.ts)
                    tmp_box.append(0)
            #print tmp_box
            if tmp_box != []:
                self.__info_box.append(tmp_box)
            #return tmp_box
        def detect_stream(self):
            tmp_box = []
            for num in self.__stream_index:
                if num[0] == self.src_port and num[1] == self.dst_port:
                    num[2] += self.len
                    return False
                elif num[1] == self.src_port and num[0] == self.dst_port:
                    num[2] += self.len
                    return False
            tmp_box.append(self.src_port)
            tmp_box.append(self.dst_port)
            tmp_box.append(0)
            self.__stream_index.append(tmp_box)
            
        def detect_fin(self):
            #print 'flag : ', self.flag
            tmp_box = []
            if self.proto == ETH_PROTOCOL_IP: #IP PROTOCOL
                if self.flag == ETH_FLAG_FIN:
                    tmp_box.append(self.src_port)
                    tmp_box.append(self.dst_port)
                    tmp_box.append(self.seq+1)
                        #stream_index.append(self.ts)
            if tmp_box != []:
                self.__trigger_box.append(tmp_box)
        
        def detect_fin_ack(self):
            if self.__trigger_box ==[] or self.__trigger_box ==[]:
                return False
            else:
                for item in self.__trigger_box:
                    if item[0] == self.dst_port and item[1] == self.src_port and item[2] == self.ack:
                        for item2 in self.__info_box:
                            if item2[0] == self.dst_port:
                                item2[4] = self.ts
                        self.__trigger_box.remove(item)

        def show(self):
            print 'stream_index'
            print self.__stream_index
            print 'info_box'
            print self.__info_box
            print 'trigger_box'
            print self.__trigger_box
        
        def xml_gen(self, name):
            filename = '../xml/' + name + '.csv'
            writecsv = csv.writer(file(filename, 'w'), lineterminator='\n')
           # writecsv.writerow(['src_port', 'src_adrs', 'dst_adrs', 'start_time', 'end_time', 'completion_time'])
            for item in self.__info_box:
                if item[4] != 0:
                    writecsv.writerow([item[0], item[1], item[2], item[3], item[4], item[4]-item[3]])
                else:
                    writecsv.writerow([item[0], item[1], item[2], item[3], item[4]])
            print 'completion generating : ', filename
            #return self.__stream_index

def main():
    index = raw_input('input the index of the node ->')
    file = 'iperf-he-' + index + '-0'
    filename = u'../pcap/'+file+'.pcap'
    pcr = dpkt.pcap.Reader(open(filename, 'rb'))
    packet_count = 0
    flow_list = {}
    b=[]
    c=Test()
    for ts,buf in pcr:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            print 'Fail parse FrameNo:', packet_count, '. skipped.'
            continue
        hex = binascii.hexlify(buf)
        a=c.Pcap_edit(buf, ts, 0)
        a.detect_start()
        a.detect_stream()
        a.detect_fin()
        a.detect_fin_ack()
        packet_count += 1
    #print_r(b)
    a.show()
    a.xml_gen(file)
    for k,v in flow_list.iteritems():
        print k, ':', v, '[Byte]'

if __name__ == '__main__':
    main()