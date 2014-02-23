# -*- coding: utf-8 -*- 

import dpkt
import socket
import struct
import binascii
import ctypes
import csv
import os.path

a=['aaa', 1]
b=[[1,2], [1,4]]
b.remove([1, 2])

def find_ary(ary, target, trigger, index):
    for word in ary:
        if word[trigger] == target:
            return  word[index]
    return False

def search_path(path):
    files = os.listdir('../pcap/')
    index_list = []
    for tmp in files:
        if tmp[0] != ".":
            index_list.append(tmp)
    return index_list
def fild_all_files(directory):
    for root, dirs, files in os.walk(directory):
        #yield root
        #print list(files)
        for file in files:
            if file[0] != ".":
                yield os.path.join(root, file)

def list_delete(ary, path):
    length=len(path)
    print ary
    lists=[]
    for file in ary:
        lists.append(file[length:])
    return lists
"""
index = raw_input('input the index of the node ->')
file_tmp = 'iperf-he-' + index + '-0'
filename = '../xml/' + file_tmp + '.csv'
writecsv = csv.writer(file(filename, 'w'), lineterminator='\n')
writecsv.writerow(['2004as5f', 'testetst'])
writecsv.writerow(['2004as5f', 'testetst'])
"""

file_tmp = 'test'
filename = '../xml/' + file_tmp + '.csv'
"""
writecsv = csv.writer(file(filename, 'w'), lineterminator='\n')
writecsv.writerow(['2004as5f', 'testetst'])
writecsv.writerow(['2004as5f', 'testetst'])
"""
"""
print os.path.isfile(filename)
if os.path.isfile(filename):
    csvfile = open(filename, 'r+')
    csv_ary= csv.reader(csvfile)
    temp=[]
    for word in csv_ary:
        temp.append(word)
    writecsv = csv.writer(csvfile, lineterminator='\n')
    writecsv.writerow(['2004as5f', 'testetst'])
else:
    print a

csvfile.close()
print csvfile
"""
a = '10.2.5.2'
tmp_ary = list(fild_all_files('../pcap/')) 
ary =list_delete(tmp_ary, '../pcap/')

"""
tmp2=''
for tmp in files:
    if tmp[0] != ".":
        index_list.append(tmp.split('-')[2])
print index_list
"""
__a=[[2,3], [4,5]]
print 'as ' + str(len(__a))
#print index_list
