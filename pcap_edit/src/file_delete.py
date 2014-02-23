# -*- coding: utf-8 -*- 

import dpkt
import socket
import struct
import binascii
import ctypes
import csv
import os.path


def fild_all_files(directory):
    for root, dirs, files in os.walk(directory):
        #yield root
        #print list(files)
        for file in files:
            if file[0] != ".":
                yield os.path.join(root, file)


tmp_ary = list(fild_all_files('./he/')) 
for pcap_path in tmp_ary:
    host = int(pcap_path.split('-')[2])
    if(host < 20):
        print pcap_path
        os.remove(pcap_path)
    
#print index_list
