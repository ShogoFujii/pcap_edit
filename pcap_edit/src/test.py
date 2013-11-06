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
a='iperf-he-24-0'
filename = '../xml/' + a + '.csv'
writecsv = csv.writer(file(filename, 'w'), lineterminator='\n')

writecsv.writerow(['2004as5f', 'testetst'])
writecsv.writerow(['2004as5f', 'testetst'])