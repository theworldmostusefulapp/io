#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys, dbm

if __name__ == "__main__":
    if (len(sys.argv) == 2):
        ff = sys.argv[1]
        with dbm.open(ff) as dl:
            print ('LENGTH: %d' % len(dl.keys()))
            for item in dl.keys():
                print ('%02d:%02d' %(len(item), len(dl[item])), item, dl[item])
    
