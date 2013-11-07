# -*- coding: utf-8 -*- 

import dpkt
import socket
import struct
import binascii
import ctypes
import csv

a=['aaa', 1]
b=[[1,2], [1,4]]
b.remove([1, 2])
print b

#filename = '../xml/iperf-he-24-0.csv'
index = raw_input('input the index of the node ->')
file_tmp = 'iperf-he-' + index + '-0'
filename = '../xml/' + file_tmp + '.csv'
writecsv = csv.writer(file(filename, 'w'), lineterminator='\n')
writecsv.writerow(['2004as5f', 'testetst'])
writecsv.writerow(['2004as5f', 'testetst'])
var = raw_input("aaaa")
file = 'iperf-he-' + var + '-0'
print file