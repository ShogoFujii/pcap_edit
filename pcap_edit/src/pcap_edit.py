# -*- coding: utf-8 -*- 

import dpkt
import socket
import struct
import binascii
import ctypes
import csv
import os.path
import sys

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
def find_ary(ary, target, trigger, index):
    for word in ary:
        if word[trigger] == target:
            return  word[index]
    return False
def fild_all_files(directory):
    for root, dirs, files in os.walk(directory):
        #yield root
        #print list(files)
        for file in files:
            if file[0] != ".":
                yield os.path.join(root, file)

def list_delete(ary, path):
    length=len(path)
    #print ary
    lists=[]
    for file in ary:
        lists.append(file[length:])
    return lists

class Test:
    __counter = 0
    __stream_index=[]
    __info_box=[]
    __trigger_box=[]
    def show_all(self):
        print self.__info_box
    class Pcap_edit:
        __counter = 0
        __stream_index=[]
        __info_box=[]
        __trigger_box=[]
        def __init__(self, buf, ts, stream):
            #print __trigger_box
            __counter = 0
            __stream_index=[]
            __info_box=[]
            __trigger_box=[]
            try:
                self.buf = binascii.hexlify(buf)
                self.proto=self.buf[0:4]
                #print "aa : ", self.buf
                self.src_adr=adrs_convert(self.buf[28:36])
                #print self.src_adr
                self.dst_adr=adrs_convert(self.buf[36:44])
                self.src_port=hex2decima(self.buf[44:48])
                self.dst_port=hex2decima(self.buf[48:52])
                self.seq=hex2decima_int(self.buf[52:60])
                self.ack=hex2decima_int(self.buf[60:68])
                self.flag=self.buf[68:72]
                self.ts=ts
                self.stream_index=stream
                self.len=len(buf)
            except:
                self.proto=''
                #print "aa : ", self.buf
                self.src_adr=''
                                #print self.src_adr
                self.dst_adr=''
                self.src_port=''
                self.dst_port=''
                self.seq=''
                self.ack=''
                self.flag=''
                self.ts=0
                self.stream_index=-1
                self.len=0
            
        def detect_start(self):
            tmp_box = []
            if self.proto == ETH_PROTOCOL_IP: #IP PROTOCOL
                if self.flag == ETH_FLAG_START:
                    tmp_box.append(self.src_port)
                    tmp_box.append(self.src_adr)
                    tmp_box.append(self.dst_adr)
                    tmp_box.append(0)
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
                    tmp_box.append(self.ts)
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
                                item2[3] = find_ary(self.__stream_index, self.dst_port, 0, 2)
                                item2[5] = item[3]
                        self.__trigger_box.remove(item)

        def show(self):
            print 'stream_index'
            print self.__stream_index
            print 'info_box'
            print self.__info_box
            print 'trigger_box'
            print self.__trigger_box
            print "len : " + str(len(self.__info_box))
            
        def reset(self):
            del self.__stream_index[:]
            del self.__info_box[:]
            del self.__trigger_box[:]
        
        def xml_gen(self, name, index):
            filename = '../xml/' + name + '.csv'
            if os.path.isfile(filename):
                print 'file exists!'
                csvfile = open(filename, 'r+')
                csv_ary= csv.reader(csvfile)
                temp=[]
                for word in csv_ary:
                    temp.append(word)
                writecsv = csv.writer(csvfile, lineterminator='\n')
                #writecsv.writerow(['2004as5f', 'testetst'])
                for item in self.__info_box:
                    if item[5] != 0 and item[1].split(".")[2]==index:
                        writecsv.writerow([item[0], item[1], item[2], item[3], item[4], item[5], item[5]-item[4], (item[5]-item[4])*1000])
                        self.__info_box.remove(item)
                        
                csvfile.close()
            else:
                csvfile2 = file(filename, 'w')
                writecsv2 = csv.writer(csvfile2, lineterminator='\n')
                writecsv2.writerow(['src_port', 'src_adrs', 'dst_adrs', 'Flow_Size',  'start_time', 'end_time', 'completion_time', 'completion_time[ms]'])
                for item in self.__info_box:
                    if item[5] != 0 and item[1].split(".")[2]==index:
                        writecsv2.writerow([item[0], item[1], item[2], item[3], item[4], item[5], item[5]-item[4], (item[5]-item[4])*1000])
                csvfile2.close()
            print 'completion generating : ', filename
            #print self.__trigger_box
            
            #return self.__stream_index

def main(range_num):
    update = True
    auto_all = True
    if auto_all:
        index_list = []
        file_list = os.listdir('../pcap/1/')
        for tmp in file_list:
            if tmp[0] != ".":
                index_list.append(tmp.split('-')[2])
        #print index_list
        if update:
            file2 = raw_input('what is the csv name? ->')
            for i in range(1000):
                print 'dir : ', i
                pre_ins=Test()
                index_list2=list(set(index_list))
                for index in index_list2:
                    for j in range(range_num):
                        num = int(index)-20
                        file = 'iperf-he-' + index + '-' + str(j)
                        filename = u'../pcap/'+str(i+1)+'/'+file+'.pcap'
                        print filename
                        try:
                            pcr = dpkt.pcap.Reader(open(filename, 'r+'))
                            packet_count = 0
                            for ts,buf in pcr:
                                pcap_edit=pre_ins.Pcap_edit(buf, ts, 0)
                                pcap_edit.detect_start()
                                pcap_edit.detect_stream()
                                pcap_edit.detect_fin()
                                pcap_edit.detect_fin_ack()
                            #pcap_edit.show()
                            if update:
                                pcap_edit.xml_gen(file2, str(num))
                            else:
                                pcap_edit.xml_gen(file, str(num))
                            #pcap_edit.show()
                            pcap_edit.reset()
                        except:
                            print 'hitt'
                    
        else:
            for j in range(3):
                index = raw_input('input the index of the node ->')
                num = int(index)-20
                file = 'iperf-he-' + index + '-' + str(j)
                if update:
                    file2 = raw_input('what is the csv name? ->')
                filename = u'../pcap/'+file+'.pcap'
                
                pcr = dpkt.pcap.Reader(open(filename, 'r'))
                packet_count = 0
                pre_ins=Test()
                for ts,buf in pcr:
                    pcap_edit=pre_ins.Pcap_edit(buf, ts, 0)
                    pcap_edit.detect_start()
                    pcap_edit.detect_stream()
                    pcap_edit.detect_fin()
                    pcap_edit.detect_fin_ack()
                    packet_count += 1
                #print_r(b)
                #if(num == 12):
                    #pcap_edit.show()
                if update:
                    pcap_edit.xml_gen(file2, str(num))
                else:
                    pcap_edit.xml_gen(file, str(num))
    """
    index = raw_input('input the index of the node ->')
    num = int(index)-20
    file = 'iperf-he-' + index + '-0'
    if update:
        file2 = raw_input('what is the csv name? ->')
    filename = u'../pcap/'+file+'.pcap'

    pcr = dpkt.pcap.Reader(open(filename, 'rb'))
    packet_count = 0
    pre_ins=Test()
    for ts,buf in pcr:
        pcap_edit=pre_ins.Pcap_edit(buf, ts, 0)
        pcap_edit.detect_start()
        pcap_edit.detect_stream()
        pcap_edit.detect_fin()
        pcap_edit.detect_fin_ack()
        packet_count += 1
    #print_r(b)
    pcap_edit.show()
    if update:
        pcap_edit.xml_gen(file2, str(num))
    else:
        pcap_edit.xml_gen(file, str(num))
        """

if __name__ == '__main__':
    param = sys.argv
    main(int(param[1]))
