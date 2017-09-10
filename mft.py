#!/usr/bin/python
# -*- coding: utf-8 -*-

import mftlib
import sys
import argparse

"""
Author			:	Ingo Braun
Created			:	02/04/16
Last Modified   :   21/05/16

This script parses ntfs mft entries from partitions on a device or raw image.
Devices and partitions only works, using linux.
"""

version = "0.9"



def printVersion():
    '''
    print the actual version of the script
    :return: nothing
    '''
    print"mft.py Version\t\t:", version
    print"mftlib.py Version\t:", mftlib.version

    sys.exit(0)



def start_parsing( _offset ,_image, _record):
	'''
	calls the parsing functions from modul
	:param _image:
	:return: PartitionTable
	'''

	#get MFT position and VBR Data

	(datarunMFT, vbrdata) = mftlib.findMFT(_image, _offset)

	#calculate Clustersize
	clustersize = vbrdata["bps"] * vbrdata["spc"]

	#find the recordoffset with read data from above
	recordoffset = mftlib.findMFTRecord(_offset, clustersize, _record, datarunMFT)

	#get read record and produce OUPUT dictonary;
	# variable searchRec only for debugging
	searchedRec, OUTPUT = mftlib.readMFTRecord(recordoffset)

	# print OUTPUT
	for key in OUTPUT:

		print OUTPUT[key]


	sys.exit(0)


def usage():
    '''
    Info for usage of the tool
    :return: nothing
    '''
    print "mft.py [-h] [-v] -o <<OFFSET>> -i <<IMAGE>> -m <<MFT_RECORD_NUMBER>>\n"\
	"\t-o specifies the offset to the start of the partition in sectors\n"\
    "\t-i specifies the image file\n"\
    "\t-m specifies the MFT_RECORD_NUMBER to process\n"\
    "\t-h prints a help message and exits\n"\
    "\t-v displays version information and exits\n"

    sys.exit(0)



def main(argv):
    '''
    checking startoptions and call the needed function
    :return:
    '''

    parser = argparse.ArgumentParser(description='Process MFT Records.')
    parser.add_argument('-v', action='store_true', default=False, help='shows version')
    parser.add_argument('-o', nargs=1, metavar='<<OFFSET>>', type=int,help='decimal offset of partition start')
    parser.add_argument('-i',  nargs=1, metavar='<<IMAGE>>', help='Path to rawimagefile')
    parser.add_argument('-m',  nargs=1, metavar='<<MFT_RECORD_NUMBER>>', type=int, help='MFT Record number')

    args = parser.parse_args()

    if args.v:
        printVersion()

    if not args.i and not args.o and not args.m:
        usage()

    if not args.i:
        print "Imagefile required"
        usage()

    if not args.o: #or type(args.o) not "int":
        print "Offset required"
        usage()

    if not args.m:# or type(args.m) not "int":
        print "Recordnumber required"
        usage()


    offset  =   args.o[0]
    image   =   args.i[0]
    record  =   args.m[0]

    start_parsing(offset, image, record)


# get started
if __name__ == '__main__':
    main(sys.argv)
