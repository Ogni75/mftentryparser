# !/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import struct
import binascii
import stat
import re

from datetime import datetime, timedelta
from string import Template, printable




"""
Author			:	Ingo Braun
Created			:	02/04/16
Last Modified   :   21/05/16

This module provide functions to read mftrecords and export resident files.

Todo:

- USN exchange (in this version error in information which is written at end of sector)
- dos flags
- index root parsing
- complete bitmap parsing
- additional attributes which are not parsed yet
- travel to redmond and discuss if they are affected in the head for this crazy database...
"""


version = "0.8"

################
DEBUG=False      # produce real much output ... only, really only for testing
################

# FS signature
# {"Name":name, position:decimalvalue, header:hexvalue, shift:decimalvalue}
VBRHEADER = [

    {"name": "NTFS",            "pos": 3,   "header": "4e54465320202020",   "shift": 0},
    {"name": "EXFAT",           "pos": 3,   "header": "4558464154202020",   "shift": 0},
    {"name": "FAT32",           "pos": 82,  "header": "4641543332",         "shift": 0},
    {"name": "FAT12",           "pos": 2,   "header": "4641543132",         "shift": 0},
    {"name": "FAT16",           "pos": 2,   "header": "4641543136",         "shift": 0},
    {"name": "EXTx",            "pos": 56,  "header": "53ef",               "shift": 1024},
    {"name": "HFSX",            "pos": 0,   "header": "4858",               "shift": 1024},
    {"name": "HFS+",            "pos": 0,   "header": "482b",               "shift": 1024},
    {"name": "HFS",             "pos": 0,   "header": "4244",               "shift": 1024},
    {"name": "ReiserFS",        "pos": 34,  "header": "526549734572",       "shift": 10000},
    {"name": "XFS",             "pos": 0,   "header": "584653",             "shift": 0},
    {"name": "Reiser2FS",       "pos": 53,  "header": "526549734572324673", "shift": 65535},
    {"name": "JFS",             "pos": 0,   "header": "4a465331",           "shift": 32768},
    {"name": "Linux Swapspace", "pos": 502, "header": "53574150535041434532", "shift": 3584},
    {"name": "Unknown",         "pos": 0,   "header": "",                   "shift": 0}
]

# known Attributes
# {"name": "name of attribute",    "var":"name of table" ,  "func":function name for parsing    "hex": "hex identifier"},
ATTRIBUTES =[
    {"name": "Standard Information",    "var":"SID_DATA" ,      "func":"parseSID",          "hex": "10000000"},
    {"name": "Attribute List",          "var":"AttList_DATA",   "func":"parseAttList",      "hex": "20000000"},
    {"name": "Filename",                "var":"FN_DATA",        "func":"parseFilename",     "hex": "30000000"},
    {"name": "Object Identifier",       "var":"ObjId_DATA",     "func":"parseObjID",        "hex": "40000000"},
    {"name": "Securtity Descriptor",    "var":"SecDes_DATA",    "func":"parseSecDes",       "hex": "50000000"},
    {"name": "Volume Name",             "var":"VolName_DATA",   "func":"notparsed",         "hex": "60000000"},
    {"name": "Volume Information",      "var":"VolInfo_DATA",   "func":"notparsed",         "hex": "70000000"},
    {"name": "Data",                    "var":"DATA_DATA",      "func":"parseDATA",         "hex": "80000000"},
    {"name": "Index Root",              "var":"IndRoot_DATA",   "func":"parseIndRoot",      "hex": "90000000"},
    {"name": "Index Allocation",        "var":"IndAll_DATA",    "func":"parseIndAll",       "hex": "a0000000"},
    {"name": "Bitmap",                  "var":"Bitmap_DATA",    "func":"parseBitmap",       "hex": "b0000000"},
    {"name": "SymbolicLink/Reparse Point","var":"SymLink_DATA", "func":"parseSymLink",      "hex": "c0000000"},
    {"name": "EA Information",          "var":"EAInfo_DATA",    "func":"notparsed",         "hex": "d0000000"},
    {"name": "EA",                      "var":"EA_DATA",        "func":"notparsed",         "hex": "e0000000"},
    {"name": "Logged Utility Stream",   "var":"LUS_DATA",       "func":"notparsed",         "hex": "00010000"},
    {"name": "End of Attributes",       "var":"nothing",        "func":"notparsed",         "hex": "ffffffff"}
]

#data tables
#{"name": "keyname",        "offset":rel. startoffset,    "length":length to read, "format":"format to calculate"},
# if length=0 field is varies


VBR_DATA = [
    {"name": "bps",         "offset":11,    "length":2, "format":"<H"},         #bytes per sector
    {"name": "spc" ,        "offset":13 ,   "length":1, "format":"<b"},         #sectors per cluster
    #{"name": "sectorstotal","offset":40,    "length":8, "format":"<Q"},         #total number of sectors per partition
    {"name": "mftstart" ,   "offset":48 ,   "length":8, "format":"<Q"},         #startcluster of mft
    #{"name": "mirstart" ,   "offset":56 ,   "length":8, "format":"<Q"},         #start of mft mirror
    {"name": "cpr" ,        "offset":64 ,   "length":1, "format":">B"}          #clusters per record
]

MFTRec_DATA =[
    {"name":"sig",          "offset": 0,     "length": 4, "format":"4s"},       # signature
    #{"name":"updseqoff",    "offset": 4,     "length": 2, "format":"<H"},       # update sequenz offset
    #{"name":"updseq",       "offset": 6,     "length": 2, "format":"<H"},       # update sequenz
    {"name":"links",        "offset": 18,    "length": 2, "format":"<H"},       # Hard link Count
    {"name":"attStart",     "offset": 20,    "length": 2, "format":"<H"},       # Offset to start of attributes
    {"name":"flag",         "offset": 22,    "length": 2, "format":"<H"},       # Flags (FILE_FLAG)
    {"name":"usedbytes",    "offset": 24,    "length": 4, "format":"<I"},       # Amount of space used by $MFT
    {"name":"allocbytes",   "offset": 28,    "length": 4, "format":"<I"},       # Amount of space allocated for $MFT
    {"name":"mftRecNr",     "offset": 44,    "length": 4, "format":"<I"},       # $MFT Record number
    {"name": "updateSeq1",  "offset": 50,    "length": 2, "format": "2s"},      # Update sequence sector 1
    {"name": "updateSeq2",  "offset": 54,    "length": 2, "format": "2s"}       # Update sequence sector 2
]

MFTRec_Nr=[
    {"name":"mftRecNr",     "offset": 44,    "length": 4, "format":"<I"}]       # $MFT Record number

#Attribute Header

ATT_HEADER =[
    {"name": "attID",       "offset": 0,    "length": 4, "format": "4s"},       # attribute ID
    {"name": "attLen",      "offset": 4,    "length": 4, "format": "<I"},       # attribute length
    {"name": "resident",    "offset": 8,    "length": 1, "format": "<B"},       # resident/non resident (POSITION_FLAG)
    {"name": "attNr",       "offset": 14,   "length": 2, "format": "<H"}        # attribute identifier

]


# Standard Information Attribute 0x10

SID_DATA = [
    {"name": "creation",     "offset": 24,   "length": 8, "format": "<Q"},      # timestamp
    {"name": "modified",     "offset": 32,   "length": 8, "format": "<Q"},      # timestamp
    {"name": "mftmodified",  "offset": 40,   "length": 8, "format": "<Q"},      # timestamp
    {"name": "lastaccess",   "offset": 48,   "length": 8, "format": "<Q"},      # timestamp
    {"name": "dosflag",      "offset": 56,   "length": 4, "format": "4s"}       # flags (DOS_FLAGS)
]

# Attribute List 0x20

AttList_DATA =[
    {"name": "type",          "offset": 24, "length": 4, "format": "<I"},
    {"name": "reclen",        "offset": 28, "length": 2, "format": "<H"},
    {"name": "namelen",       "offset": 30, "length": 1, "format": "<B"},
    {"name": "fileref",       "offset": 40, "length": 8, "format": "<Q"},
    {"name": "ID",            "offset": 48, "length": 2, "format": "<H"},
    {"name": "name",          "offset": 50, "length": 0, "format": "."},

]

# Filename Attribute 0x30

FN_DATA = [
    {"name": "parentRec",   "offset": 24,   "length": 6, "format": "6s"},       # parent record
    {"name": "creation",    "offset": 32,   "length": 8, "format": "<Q"},       # timestamp
    {"name": "modified",    "offset": 40,   "length": 8, "format": "<Q"},       # timestamp
    {"name": "mftmodified", "offset": 48,   "length": 8, "format": "<Q"},       # timestamp
    {"name": "lastaccess",  "offset": 56,   "length": 8, "format": "<Q"},       # timestamp
    {"name": "nameLength",  "offset": 88,   "length": 1, "format": "<B"},       # length of filename
    {"name": "fntype",      "offset": 89,   "length": 1, "format": "<B"},
    {"name": "filename",    "offset": 90,   "length": 0, "format": "."}         # filename
]

# Object Identifier Attribute 0x40

ObjId_DATA=[
    {"name": "GUID",        "offset": 24,    "length": 16, "format":"16s"},      # objectID guid
    {"name": "birthVolGUID","offset": 40,    "length": 16, "format": "16s"},     # Birth Volume GUID
    {"name": "birthObjGUID","offset": 56,    "length": 16, "format": "16s"}     # birth ObjectGUID
]

# Volume Name 0x60
VolName_DATA=[
    {"name": "volname",     "offset": 24,     "length": 0, "format": "."}       # Name in Unicode
]

# Volume Information 0x70

VolInfo_DATA=[
    {"name": "majorVer",    "offset": 32,     "length": 1, "format": "<B"},
    {"name": "minorVer",    "offset": 24,     "length": 1, "format": "<B"},
    {"name": "flags",       "offset": 24,     "length": 2, "format": "<H"}
]

# Data Attribute (resident) 0x80

DATA_DATA =[
    {"name": "res_size",    "offset":16,    "length": 4, "format": "<I"},       # size of resident data
    {"name": "res_data",    "offset":24,    "length": 0, "format": "."}         # resident data

]

# Data Attribute (non resident) 0x80

DATAnonres_DATA = [
    {"name": "VCNstart",    "offset":16,    "length": 8, "format": "<Q"},       #virtual cluster number Start
    {"name": "VCNend",      "offset":24,    "length": 8, "format": "<Q"},       #virtual cluster number End
    {"name": "physSize",    "offset":40,    "length": 8, "format": "<Q"},       # physical size
    {"name": "logSize",     "offset":48,    "length": 8, "format": "<Q"},       # logical size
    {"name": "resSize",     "offset":56,    "length": 8, "format": "<Q"},       # reserved size
    #{"name": "datarun",     "offset":64,    "length": 0, "format": "."}
]

# Index Root Attribute 0x90

IndRoot_DATA=[### has To be revised - not correct! Attribute not parsed yet!
    {"name": "flags",       "offset": 12,     "length": 2, "format": "<H"},     #
    {"name": "StreamName",  "offset": 24,     "length": 8, "format": "8s"},     #
    {"name": "storedAtt",   "offset": 32,     "length": 4, "format": "<I"},     #
    {"name": "IndBytesize", "offset": 40,     "length": 4, "format": "<I"},     #
    {"name": "IndClustsize","offset": 44,     "length": 1, "format": "<B"},     #
    {"name": "IndNodeOff",  "offset": 48,     "length": 4, "format": "<I"},     #
    {"name": "IndNodelen",  "offset": 52,     "length": 4, "format": "<I"},     #
    {"name": "IndMFTRec",   "offset": 64,     "length": 8, "format": "<Q"},     #
    {"name": "IndexDirFlags","offset":76,     "length": 4, "format": "<I"},     #
    {"name": "creation",    "offset": 88,     "length": 8, "format": "<Q"},     #
    {"name": "modified",    "offset": 96,     "length": 8, "format": "<Q"},     #
    {"name": "mftmodified", "offset": 104,    "length": 8, "format": "<Q"},     #
    {"name": "lastaccess",  "offset": 112,    "length": 8, "format": "<Q"},     #
    {"name": "physSize",    "offset": 120,    "length": 8, "format": "<Q"},     #
    {"name": "logSize",     "offset": 128,    "length": 8, "format": "<Q"},     #
    {"name": "nameLength",  "offset": 144,    "length": 1, "format": "<B"},     #
    {"name": "filename",    "offset": 146,    "length": 0, "format": "."}
]

IndHeader_DATA=[

]

IndNode_DATA=[

]

# Index Allocation Attribute 0xa0

IndAll_DATA=[
    {"name": "flags",       "offset": 12,     "length": 2, "format": "<H"},     # FILE_TYPE_FLAGS
    {"name": "startVCN",    "offset": 16,     "length": 8, "format": "<Q"},     # starting VCN of runlist
    {"name": "endVCN",      "offset": 24,     "length": 8, "format": "<Q"},     # ending VCN of runlist
    {"name": "physSize",    "offset": 40,     "length": 8, "format": "<Q"},     # allocated size (physical)
    {"name": "logSize",     "offset": 48,     "length": 8, "format": "<Q"},     # actual size (logical)
    {"name": "iniSize",     "offset": 56,     "length": 8, "format": "<Q"},     # initialized in bytes
    {"name": "StreamName",  "offset": 64,     "length": 8, "format": "8s"}      # stream name
    #{"name": "runlist",     "offset": 72,     "length": 0, "format": "."}       # runlist
]

# Bitmap Attribute 0xb0

Bitmap_DATA= [
    {"name": "TypeFlags",    "offset": 12,      "length": 2, "format": "<H"},   #
    {"name": "StreamName",   "offset": 24,      "length": 8, "format": "8s"},   #
    {"name": "bitmap",       "offset": 32,      "length": 8, "format": "<Q"}    #
]

# SymbolicLink/Reparse Point Attribute 0xc0

SymLink_DATA=[
    {"name": "reparseType", "offset": 24,    "length": 4, "format": "4s"},      # Reparse Point Type (REPARSE_FLAG)
    {"name": "nameOff",     "offset": 32,    "length": 2, "format": "<H"},      # Offset to target name
    {"name": "nameLen",     "offset": 34,    "length": 2, "format": "<H"},      # Length of target name
    {"name": "prNameOff",   "offset": 36,    "length": 2, "format": "<H"},      # Offset of print target name
    {"name": "prNameLen",   "offset": 38,    "length": 2, "format": "<H"},      # length of print target name
    {"name": "folderPath",  "offset": 40,    "length": 0, "format": "."}        # path
]




# Other attributes; not implemented for now. Compare with names from table "ATTRIBUTES" above

SecDes_DATA =[] # Security Descriptor   0x50
EAInfo_DATA =[] # EA Information        0xd0
EA_DATA     =[] # EA                    0xe0
LUS_DATA    =[] # Logged Utility Stream 0x0001


# Dictonaries and lists for some Flags

SIGNATURE= ["FILE", "BAAD", "INDX"]

FILE_FLAG={
    0:"Deleted File",
    1:"Allocated File",
    2:"Deleted Directory",
    3:"Allocated Directory",

}

FILENAME_TYPE={
    0:"Posix",
    1:"Win32",
    2:"DOS Short Name",
    3:"Win32/DOS"
}



POSITION_FLAG={
    0:"Non Resident",
    1:"Resident"
}
# dosflags
# bitposition backwards : flag
DOS_FLAGS={
    0:"Read Only",1:"Hidden",2:"System",
    4:"Directory",5:"Archive",6:"Device",7:"Normal",
    8:"Temporary",9:"Sparse File",10:"Reparse Point",11:"Compressed",
    12:"Offline",13:"Not Content Indexed",14:"Encrypted"}


FILE_TYPE_FLAGS={
    1:"Compressed",
    2:"Sparse",
    3:"Encrypted"
}

REPARSE_FLAG={
    "00000020": "Is Alias",
    "00000040": "Is high latency",
    "00000080": "Is Microsoft",
    "05000068": "NSS",
    "06000068": "NSS recover",
    "07000068": "SIS",
    "08000068": "DFS",
    "03000088": "Mount Point",
    "030000A0": "Junction",
    "040000A8": "HSM",
    "000000E8": "Symbolic Link"
}


'''
Templates
'''

ENTRYHEADER = Template("MFT Entry Header Values:\tMFT RECORD NUMBER: $mftrec\n"
                       "\t\t\t\tAbsolute offset to entry: $offset\n"
                       "\t\t\t\t$filetype\n"
                       "\t\t\t\tLinks: $linkcount\n")
ATTRIBUTENAME = Template("\t\t\t\t$atttype Attribute Values:\n")
FILENAME = Template("\t\t\t\tName: $filename\n"
                    "\t\t\t\tFilenametype: $filenametype\n"
                    "\t\t\t\tParent MFT Entry: $parent\n"
                    "\t\t\t\tAllocated Size: $physize Actual Size: $realsize\n")
TIMESTAMPS = Template("\t\t\t\tCreated        : $created\n"
                      "\t\t\t\tFile modified  : $modified\n"
                      "\t\t\t\tMFT modified   : $mftmodified\n"
                      "\t\t\t\tAccessed       : $accessed\n")
ATTRIBUTELIST = Template("\t\t\t\tType: $atttype Name: $attname $location size: $size\n")
DOSFLAG     = Template("\t\t\t\tFileflags: $flags\n")

ADDTEXT     = Template("\t\t\t\t$text $value")

'''
Filehandling
'''

def openFile(_image):
    """
    Open file; check access and path;
    set global variables to be sure that everything neede is open

    :param _image: Imagefile or device
    :return: true if everything work
    """

    # define global variables
    global file_is_open
    global openedFile

    # try to open file; set global marker 'file_is_open' to true
    try:
        openedFile = open(_image, "rb")
        file_is_open = True
    except IOError as syserr:
        errnote = "({})".format(syserr)
        sys.exit(errnote)

    return True


def closeFile():
    """closes the given file _image; return true if closed"""

    # define variables
    global file_is_open

    # check if file is open
    if file_is_open:
        # try to close file and unset file_is_open
        try:
            openedFile.close()
            file_is_open = False
        except IOError as syserr:
            errnote = "({})".format(syserr)
            sys.exit(errnote)

    return True


def readBinary(_position, _length):
    """read binary from file from _position with _length and return the value

    :param _position: position in bytes
    :param _length: length in bytes
    :return: read value
    """
    global file_is_open

    # check if file is open
    if file_is_open:
        # read length at position
        i = 0
        # create pointer for USN
        _recordarea = []
        while i < _length:
            _pointer1024 = int((_position + i) % 1024)
            _recordarea.append(_pointer1024)

            i += 1

        (USN, USNcount)=checkUSN(_recordarea)

        if USN:
            if DEBUG:
                print "position to change USN:", USNcount
                print "recordarea", _recordarea

            print "Warning! Data in USN Area. Verify Data by Hand!"

        try:
            openedFile.seek(_position)
            value = openedFile.read(_length)
        except IOError as syserr:
            # feedback variable is set and file isn't open; which should never happen
            closeFile()
            errnote = "({})".format(syserr)
            sys.exit(errnote)

        return value
    else:
        # end script if file isn't open
        errnote = "No file to read is open."
        sys.exit(errnote)


def checkfile(_image):
    """
    check image file/device if exist and readable etc
    :param _image: raw image name or block device
    :return: _file_is_ok, _errnote, _devicesize
    """

    _errnote = ""
    _devicesize = 0
    _file_is_ok = True

    # check if path exists
    if not os.path.exists(_image):
        _errnote = "({})".format("'" + _image + "' not exists.")
        _file_is_ok = False

    # check if file
    elif os.path.isdir(_image):
        _errnote = "({})".format("'" + _image + "' is a path. Please specify the file for analysis.")
        _file_is_ok = False
    # or only path
    elif not os.path.isfile(_image):
        # check if file and not blockdevice
        if not isblockdevice(_image):
            _errnote = "({})".format("'" + _image + "' is not a valid file/device. Please specify the filename.")
            _file_is_ok = False
    # path read access
    elif not os.access(_image, os.R_OK):
        _errnote = "({})".format("Permission denied. Please change the permission to read this file or device!")
        _file_is_ok = False
    # get devicesize
    if _file_is_ok:
        try:
            _devicesize = getdevicesize(_image)
            if _devicesize < 512:
                _errnote = "({})".format("File is to small. No boot record possible!")
                _file_is_ok = False
        except:
            if isblockdevice(_image):
                _errnote = "({})".format(
                        "Error while opening block device. It's not possible to read file size. You need to be root to read block devices.")
            else:
                _errnote = "({})".format("Error while opening imagefile. It's not possible to read file size.")
            _file_is_ok = False

    if not _file_is_ok:
        return False, _errnote, _devicesize

    return _file_is_ok, _errnote, _devicesize


def getdevicesize(_image):
    """
    check devicesize
    :param _image: raw image name or block device
    :return: devicesize
    """
    f = os.open(_image, os.O_RDONLY)
    try:
        _size = os.lseek(f, 0, os.SEEK_END)
        return _size
    finally:
        os.close(f)


def isblockdevice(_image):
    """
    check if _image is a block device
    :param _image: raw image name or block device
    :return: boolean
    """
    # try to read the inode of file
    try:
        _imagemode = os.lstat(_image).st_mode
    except OSError:
        return False
    else:
        # checks inode for blockdevice
        return stat.S_ISBLK(_imagemode)


'''

Parsing MFT

'''


def findMFT(_image, _partoffset):
    """
    read vbr from given offset position, parse the first mft record, which gives the basicinfo to find the
    requested MFT record
    :param _image:      imagefilename; only raw images!
    :param _offset:     start of ntfs partition
    :return:            return the position of complete mft
    """

    openFile(_image)

    _partitionFS = getPartitionFS(_partoffset)
    if _partitionFS != "NTFS":
        closeFile()
        _errnote = "Partition is not a NTFS partition. " + _partitionFS + " partition found."
        sys.exit( _errnote)

    _vbrdata = readMFTData(_partoffset, VBR_DATA)

    _mftPosition = (_vbrdata['bps'] * _vbrdata['spc'] * _vbrdata['mftstart']) + _partoffset

    # read first mftentry to verify MFT exists
    _mftzero =  readMFTData(_mftPosition , MFTRec_DATA)
    if not _mftzero['sig'] == "FILE" or not _mftzero['mftRecNr'] == 0 :
        closeFile()
        err_note = "No expected data at record 0. Cancel this Operation"
        sys.exit(err_note)

    _nextAttPos =   _mftPosition + _mftzero['attStart']
    _attributetoread = findAttr(_nextAttPos)


    while _attributetoread['hex'] != "ffffffff":

        attvar=globals()[_attributetoread["var"]]

        attributes = readAttData( _nextAttPos, attvar )
        if _attributetoread['hex'] == "80000000":
            break

        _nextAttPos = _nextAttPos + attributes['attLen']

        _attributetoread = findAttr(_nextAttPos)

    _mftPosition = readRunlist((_nextAttPos+64), attributes['attLen'])

    if DEBUG:
        print "Runlist MFT: ",_mftPosition

    return _mftPosition, _vbrdata


def findAttr(_attPos):
    """
    compares attribute with global variable from above and returns attribute key
    :param _attPos:
    :return:
    """

    _rawdata = binascii.hexlify(readBinary(_attPos, 4))

    for key in ATTRIBUTES:
        if _rawdata == key['hex']:
            return key


    err_note = "Error finding attribute."
    sys.exit(err_note)


def findMFTRecord(_partoffset, _clustersize, _recordnr, _datarunMFT):
    """
    search the recordentry in the MFT
    :param _partoffset: start of partition
    :param _recordnr:   record to search
    :param _datarunMFT: MFT Positions
    :return:
    """


    _lastoffset = _partoffset
    i = 0
    while i < len(_datarunMFT):

        _startrecord = 0
        _endrecord  = 0

        _startoffset = (_datarunMFT[i]['start'] * _clustersize)  + _lastoffset
        _endoffset = (_datarunMFT[i]['start'] * _clustersize)  + \
                     (_datarunMFT[i]['length'] * _clustersize) + _lastoffset - 1024
        _lastoffset = _startoffset

        if DEBUG:
            print "MFTChunk {:} Startoffset: {:} Endoffset: {:}".format(i, _startoffset, _endoffset)


        _recData = readMFTData(_startoffset, MFTRec_Nr)
        _startrecord = _recData["mftRecNr"]

        _recData = readMFTData(_endoffset, MFTRec_Nr)
        _endrecord = _recData["mftRecNr"]

        while _endrecord == 0:

            _endoffset = _endoffset-1024
            _recData = readMFTData(_endoffset, MFTRec_Nr)
            _endrecord = _recData["mftRecNr"]

        if _recordnr >= _startrecord and _recordnr <=_endrecord:

            while _startrecord <= _endrecord:
                _chunkmid = _startrecord + (_endrecord - _startrecord) / 2
                _offsetmid = ((_startoffset + (_endoffset - _startoffset) / 2) -\
                              ((_startoffset + (_endoffset - _startoffset) / 2) % 1024))

                if _chunkmid == _recordnr:
                    _recData = readMFTData(_offsetmid, MFTRec_DATA)

                    if _recordnr != _recData["mftRecNr"]:
                        err_note = "Problems with MFTRecord!\n Searched: {:}\tRead: {:}"\
                            .format(_recordnr, _recData["mftRecNr"])
                        sys.exit(err_note)

                    if _recData["sig"] not in SIGNATURE:
                        err_note = "Problems with MFTRecord! Unknown Header!"
                        sys.exit(err_note)

                    if DEBUG:
                        print "Found Record: {:} Offset: {:}".format(_recData["mftRecNr"], _offsetmid)

                    return _offsetmid

                elif _chunkmid < _recordnr:
                   _startrecord = _chunkmid+1
                   _startoffset = _offsetmid + 1024
                else:
                   _endrecord = _chunkmid - 1
                   _endoffset = _offsetmid - 1024


        i += 1

    err_note = "Record " + str(_recordnr) + " not found in MFT.\nHighest recordnumber to choose: " + str(_endrecord)
    sys.exit(err_note)


def findMFTRecordold(_partoffset, _clustersize, _recordnr, _datarunMFT):   #very slow; should new constructed; if time ;)
    """
    search the recordentry in the MFT
    :param _partoffset: start of partition
    :param _recordnr:   record to search
    :param _datarunMFT: MFT Positions
    :return:
    """

    i = 0
    h = 0
    _lastoffset=_partoffset
    _mftRecNr=0

    while i < len(_datarunMFT):

        _startoffset = (_datarunMFT[i]['start'] * _clustersize)  + _lastoffset
        _endoffset = (_datarunMFT[i]['start'] * _clustersize)  + (_datarunMFT[i]['length']*_clustersize) + _lastoffset
        _lastoffset=_startoffset
        if DEBUG:
            print "MFTChunk Startoffset: {:<} Endoffset: {:<}".format(_startoffset, _endoffset)



        while _startoffset < _endoffset:

            _recData = readMFTData(_startoffset, MFTRec_Nr)

            _mftRecNr = _recData["mftRecNr"]

            if _mftRecNr == _recordnr:
                if DEBUG:
                    print "Found Record: {:} Offset: {:}".format(_recData["mftRecNr"], _offsetmid)

                return _startoffset

            _startoffset += 1024

            h+=1

        i += 1

    err_note = "Record "+str(_recordnr)+" not found in MFT"
    sys.exit(err_note)

    return

def readMFTData(_startoffset, _datavar):
    """
    read the needed MFT data, described in global var from above
    :param _startoffset:
    :param _datavar:
    :return:
    """

    #create attributeData list
    _mftData = {}
    if DEBUG:
        print "readMFTData startoffset {:} Datavar: {:}".format(_startoffset, _datavar)
    #read data, using the templates
    i = 0
    while i != len(_datavar):

        _readpos = 0
        # read attribute information
        _name   = _datavar[i]["name"]
        _pos    = _datavar[i]["offset"]
        _length = _datavar[i]["length"]
        _format = _datavar[i]["format"]
        # calculate position
        _readpos = _startoffset + _pos

        _structstring = _format

        if _length != 0:

            _rawdata =  readBinary(_readpos, _length)

            _data = struct.unpack_from(_structstring, _rawdata)[0]

        else:

            _length = _mftData['attStart'] - _pos

            _rawdata = readBinary(_readpos, _length)

            _data = _rawdata

        if DEBUG:
            print "Round: " + str(i) + "\tName: " + _name + "\t\tData: " + str(_data)

        _mftData[_name] = _data

        i += 1

    return _mftData


def readMFTRecord(_startoffset):
    '''
    read the data from searched mftrecord which starts at startoffset
    :param _startoffset:
    :return:
    '''

    _outputtemp = ""
    OUTPUT = {}

    _record = readMFTData(_startoffset, MFTRec_DATA)

    _nextAttPos =   _startoffset+_record['attStart']
    _attributetoread = findAttr(_nextAttPos)
    if _attributetoread['var']=="nothing":
        err_note="Empty MFT Record. Nothing to parse"
        sys.exit(err_note)

    attributeList = []
    i = 0
    while _attributetoread['hex'] != "ffffffff":


        attvar = globals()[_attributetoread["var"]]

        attributes = readAttData(_nextAttPos, attvar)

        (_attributedata, _outputtemp) = eval(_attributetoread["func"] + "(  attributes, _record, _nextAttPos  )")

        if DEBUG:
            print "readMFTRecord - AttributeData: ", _attributedata

        attributeList.append(_attributedata)
        OUTPUT[i] = _outputtemp

        if _attributetoread['hex'] == "ffffffff":
            break

        _nextAttPos = _nextAttPos + attributes['attLen']

        _attributetoread = findAttr(_nextAttPos)

        i += 1
        if i==2:    #position 2 is reserved for attribute list
            i=3

        OUTPUT[2]= LISTattributes(attributeList)





    return attributeList, OUTPUT





def readAttData(_startoffset, _datavar):
    """
    reads attribute data; take fields from global variable, given with _datavar
    :param _startoffset: of attribute
    :param _datavar:     attribute variable to read
    :return:
    """

    i = 0
    #create attributeData list
    _attributeHeaderData = {}

    while i != len(ATT_HEADER):

        _name   = ATT_HEADER[i]["name"]
        _pos    = ATT_HEADER[i]["offset"]
        _length = ATT_HEADER[i]["length"]
        _format = ATT_HEADER[i]["format"]

        # calculate position
        _readpos = _startoffset + _pos


        _structstring = _format

        _rawdata = readBinary(_readpos, _length)

        _data = struct.unpack_from(_structstring, _rawdata)[0]

        _attributeHeaderData[_name] = _data


        i += 1


    #read data, using the templates
    _attributeData = {}
    i = 0
    #print "Resifent:", _attributeHeaderData['resident']
    if binascii.hexlify(_attributeHeaderData['attID'])=="80000000":
        #print "Resifent:",_attributeHeaderData['resident']
        if _attributeHeaderData['resident']==0:
            _datavar=DATA_DATA

        else:
            _datavar=DATAnonres_DATA

    while i != len(_datavar):

        _readpos = 0

        # read attribute information
        _name   = _datavar[i]["name"]
        _pos    = _datavar[i]["offset"]
        _length = _datavar[i]["length"]
        _format = _datavar[i]["format"]
        # calculate position
        _readpos = _startoffset + _pos

        _structstring = _format

        if _length != 0:

            _rawdata =  readBinary(_readpos, _length)

            _data = struct.unpack_from(_structstring, _rawdata)[0]

        else:

            _length = _attributeHeaderData['attLen']-_pos
            if _length<0:
                _length=0

            _rawdata = readBinary(_readpos, _length)

            _data = _rawdata

        if DEBUG:
            print "readAttData : ", _startoffset
            print "Round: " + str(i) + "\tName: " + _name + "\t\tData: " + str(_data)
            print "Position: {:} Readposition modulo : {:}".format(_pos, _readpos % 512)


        _attributeData[_name] = _data

        i += 1

    _attributeData.update(_attributeHeaderData)

    if DEBUG:
        print "Attributedata Out: ", _attributeData

    return _attributeData


def readRunlist(_startoffset, _endOfAttribute):
    """
    :param _startoffset:    start of runlist
    :param _endOfAttribute: absolute end of attribute
    :return:
    """

    _lengthStartCluster =- 1
    _lengthClusterLength =- 1
    i = 0
    runlist = []
    _datarunpos = _startoffset

    while _lengthClusterLength != 0 and _lengthStartCluster != 0:

        if _lengthClusterLength > 8 or _lengthStartCluster > 8:
            break

        #read the length of startposition and length
        _clusterPosInfo     = struct.unpack_from("s", readBinary(_datarunpos, 1))[0]
        _lengthStartCluster = int(binascii.hexlify(_clusterPosInfo)[0], 16)
        _lengthClusterLength  = int(binascii.hexlify(_clusterPosInfo)[1], 16)

        # !!! Has to be changed if USN exchange is implemented
        if _datarunpos == _endOfAttribute or _lengthStartCluster == 0 or _lengthClusterLength == 0:
            break

        #if a runlist could find, read the datarun and append to runlist
        if (_lengthClusterLength + _lengthStartCluster) != 0:


            _clusterLengthHex   = LE(binascii.hexlify(readBinary((_datarunpos + 1), _lengthClusterLength)), 8)
            _startClusterHex    = LE(binascii.hexlify(readBinary((_datarunpos + 1 + \
                                                                  _lengthClusterLength), _lengthStartCluster)),8, True)

            if len(_clusterLengthHex) > 8:
                _clusterLengthHex="00000000"
            if len(_startClusterHex) > 8:
                _startClusterHex="00000000"

            if DEBUG:
                print "Datarun {:} Start {:} Length {:}".format(i, _startClusterHex, _clusterLengthHex)



            _startClusterDez  = struct.unpack('>i', _startClusterHex.decode('hex'))[0]
            _clusterLengthDez = int( _clusterLengthHex, 16 )

            datarun = {}
            datarun['nr'] = i
            datarun['start'] = _startClusterDez
            datarun['length'] = _clusterLengthDez

            runlist.append(datarun)

            i += 1

        _datarunpos = _datarunpos + 1 + _lengthClusterLength + _lengthStartCluster

    return runlist


def getPartitionFS(_startoffset):
    """	verify partition signature and compares with known Filesystem
    :_startoffset: startsector of partition
    :return: Name of found filesystem or unknown
    """

    i = 0
    _Filesystem = ""
    # loop for every entry in VBR Header list

    while i != len(VBRHEADER):

        _isheader = False
        _readpos = 0
        # declare actual variables on which position, which header could found
        _shift = VBRHEADER[i]["shift"]
        _header = VBRHEADER[i]["header"]
        _pos = VBRHEADER[i]["pos"]
        _length = len(str(_header))
        #calculate position
        _readpos = _startoffset + _pos + _shift
        #read position
        _partitionInfo = readBinary(_readpos, _length)

        structstring = "<" + str(_length / 2) + "s"
        #check if header is found; then break and return the filesystem
        try:
            _isheader = binascii.hexlify(struct.unpack_from(structstring, _partitionInfo)[0]) == _header
        except:
            _Filesystem = "Unknown"
            return (_Filesystem)
        if _isheader:
            _Filesystem = VBRHEADER[i]["name"]
            return (_Filesystem)
        #else, if the actual loop filesystem not found, use next entry to compare
        i += 1

    return _Filesystem


'''
Attributeparser
'''

def LISTattributes(_attributes):
    '''
    generate the attribute list
    :param _attributes:
    :return: outputvariable
    '''
    output="\t\t\t\tAttributelist:\n"

    for key in _attributes:

        output += ATTRIBUTELIST.substitute(atttype=key['type'], attname=key['name'], location=key['position'], size=key['size'])

    return output

def parseAttHeader(_attributedata):

    """
    parse the attributeHeader
    :param _attributedata:
    :return:
    """

    attribute={}

    for key in ATTRIBUTES:
        if key["hex"]==binascii.hexlify(_attributedata["attID"]):
            attribute["typenr"]=binascii.hexlify(_attributedata["attID"])[:2]
            attribute["type"]="$"+key["name"].upper()

    attribute["position"]   = POSITION_FLAG[_attributedata["resident"]]
    attribute["size"]       = _attributedata["attLen"]

    try:
        attribute["name"]   = unicode(_attributedata["StreamName"], encoding="utf-16le").encode("ascii", "ignore")
    except:
        attribute["name"]   =   "n/a"

    attribute['order']      =   _attributedata["attNr"]

    return attribute


def parseSID(_attributedata, _recorddata, _attoffset):
    """
    build the SID template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """

    #assign header information
    attribute   =   parseAttHeader(_attributedata)

    #assign flags
    try:
        allocflag = FILE_FLAG[_recorddata['flag']]
    except:
        allocflag = "Unknown"

    _startoffset= _attoffset - 56

    #assign SID data
    SIDHead = ENTRYHEADER.substitute(mftrec=_recorddata['mftRecNr'], offset=_startoffset, filetype=allocflag, linkcount=_recorddata['links'])

    SIDTitle = ATTRIBUTENAME.substitute(atttype=attribute['type'])

    #assign timestamps
    _creation   =   mfttime(_attributedata['creation'])
    _modified   =   mfttime(_attributedata['modified'])
    _mftmod     =   mfttime(_attributedata['mftmodified'])
    _access     =   mfttime(_attributedata['lastaccess'])

    SIDTime = TIMESTAMPS.substitute(created=_creation, modified=_modified, mftmodified=_mftmod, accessed=_access)

    #template assemble
    SIDTemp = SIDHead + SIDTitle + SIDTime

    return attribute, SIDTemp


def parseAttList(_attributedata, _recorddata, _attoffset):
    """
    build the AttributeList template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """

    attribute   = parseAttHeader(_attributedata)

    return attribute, ""


def parseFilename(_attributedata, _recorddata, _attoffset):
    """
     build the filename attribute template and return the attribute header data
     :param _attributedata:
     :param _recorddata:
     :return:
     """

    attribute   = parseAttHeader(_attributedata)

    FNTitle = ATTRIBUTENAME.substitute(atttype=attribute["type"])

    fullname        =   unicode(_attributedata["filename"], encoding="utf-16le").encode("ascii", "ignore")

    parentidhex     =   LE(binascii.hexlify(_attributedata["parentRec"]), 8)
    parentID        =   struct.unpack('>Q', parentidhex.decode('hex'))[0]

    realsize        =   _recorddata["usedbytes"]
    physize         =   _recorddata["allocbytes"]

    fntype          =   FILENAME_TYPE[ _attributedata['fntype']]

    FNHead = FILENAME.substitute(filename=fullname, filenametype=fntype, parent=parentID, physize=physize, realsize=realsize)

    # assign timestamps
    _creation = mfttime(_attributedata['creation'])
    _modified = mfttime(_attributedata['modified'])
    _mftmod = mfttime(_attributedata['mftmodified'])
    _access = mfttime(_attributedata['lastaccess'])

    FNTime = TIMESTAMPS.substitute(created=_creation, modified=_modified, mftmodified=_mftmod, accessed=_access)

    # build complete template

    FNTemp = FNTitle + FNHead + FNTime

    return attribute, FNTemp


def parseObjID(_attributedata, _recorddata, _attoffset):
    """
    build the ObjectID template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """
    attribute   = parseAttHeader(_attributedata)

    guid = buildGUID(_attributedata['GUID'])
    birthVol=buildGUID(_attributedata['birthVolGUID'])
    birthObj=buildGUID(_attributedata['birthObjGUID'])

    ObjIDTemp = ADDTEXT.substitute(text =  "ObjectID\t\t: ", value=guid)
    ObjIDTemp += ADDTEXT.substitute(text = "Birth Volume ID\t: ", value=birthVol)
    ObjIDTemp += ADDTEXT.substitute(text = "Birth Object ID\t: ", value=birthObj)


    return attribute, ObjIDTemp


def parseSecDes(_attributedata, _recorddata, _attoffset):
    """
    build the security descriptor attribute template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """
    attribute   = parseAttHeader(_attributedata)

    return attribute, ""


def parseVolName(_attributedata, _recorddata, _attoffset):
    """
    build the volume name attribute template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """
    attribute   = parseAttHeader(_attributedata)

    return attribute, ""


def parseVolInfo(_attributedata, _recorddata, _attoffset):
    """
    build the volume info attribute template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """
    attribute   = parseAttHeader(_attributedata)

    return attribute, ""


def parseDATA(_attributedata, _recorddata, _attoffset):
    """
    build the data attribute template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """
    attribute   = parseAttHeader(_attributedata)

    if _attributedata['resident']==0:

        # DATATEMP=ADDTEXT.substitute(text="\nResident Data:", value=_attributedata['res_data'])

        resdata=_attributedata['res_data']

        #strip non printable characters
        clean_resident = ''.join(filter(lambda x: x in printable, resdata))

        if clean_resident != "":

            DATATEMP = ADDTEXT.substitute(text="Resident Data:", value="(adjusted to printable characters)\n")
            DATATEMP += clean_resident

        else:
            DATATEMP = ADDTEXT.substitute(text="Resident Data:", value="No Content\n")


    else:
        _startrunlist  = _attoffset+64
        _endrunlist = _attoffset+_attributedata['attLen']

        _datarun = readRunlist(_startrunlist,_endrunlist)


        runlistheader = "\t\t\t\t$DATA Runlist:\n" \
                        "\t\t\t\t(Cluster rel. to partitionstart)\n" \
                        "\t\t\t\tChunk\tFirst\t\tLast\n"

        DATATEMP=runlistheader

        i=0
        _lastrecord=0
        while i < len(_datarun):
            _startrecord = 0
            _endrecord = 0

            _startrecord = (_datarun[i]['start'] ) + _lastrecord
            _endrecord = (_datarun[i]['start'] ) + \
                         (_datarun[i]['length'] ) + _lastrecord-1
            _lastrecord = _startrecord

            runlist = "\t\t\t\t{:>3}\t{:>012d}\t{:>012d}\n".format(i, _startrecord, _endrecord)

            DATATEMP += runlist
            i+=1


    return attribute, DATATEMP


def parseIndRoot(_attributedata, _recorddata, _attoffset):
    """
    build the index root attribute template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """
    attribute   = parseAttHeader(_attributedata)

    return attribute, ""


def parseIndAll(_attributedata, _recorddata, _attoffset):
    """
    build the index allocate attribute template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """
    attribute = parseAttHeader(_attributedata)

    _startrunlist = _attoffset + 72
    _endrunlist = _attoffset + _attributedata['attLen']

    _datarun = readRunlist(_startrunlist, _endrunlist)

    runlistheader = "\t\t\t\t $INDEX_ALLOCATION Runlist:\n" \
                    "\t\t\t\t(Cluster rel. to partitionstart)\n" \
                    "\t\t\t\tChunk\tFirst\t\tLast\n"

    DATATEMP = runlistheader

    i = 0
    _lastrecord = 0
    while i < len(_datarun):
        _startrecord = 0
        _endrecord = 0

        _startrecord = (_datarun[i]['start']) + _lastrecord
        _endrecord = (_datarun[i]['start']) + \
                     (_datarun[i]['length']) + _lastrecord - 1
        _lastrecord = _startrecord

        runlist = "\t\t\t\t{:>3}\t{:>012d}\t{:>012d}\n".format(i, _startrecord, _endrecord)

        DATATEMP += runlist
        i += 1

    return attribute, DATATEMP

    return attribute, ""


def parseBitmap(_attributedata, _recorddata, _attoffset):
    """
    build the bitmap attribute template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """
    attribute   = parseAttHeader(_attributedata)

    return attribute, ""


def parseSymLink(_attributedata, _recorddata, _attoffset):
    """
    build the symlink/reparse point attribute template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """
    attribute   = parseAttHeader(_attributedata)
    reparsecode = binascii.hexlify(_attributedata['reparseType']).upper()
    try:
        reparsetype = REPARSE_FLAG[reparsecode]
    except:
        reparsetype = "Unknown"

    REPARSETemp=ADDTEXT.safe_substitute(text="Reparse Point Type: ", value=reparsetype)
    return attribute, REPARSETemp


def parseEAInfo(_attributedata, _recorddata, _attoffset):
    """
    build the EA info attribute template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """
    attribute   = parseAttHeader(_attributedata)


    return attribute, ""


def parseEA(_attributedata, _recorddata, _attoffset):
    """
    build the EA attribute template and return the attribute header data
    :param _attributedata:
    :param _recorddata:
    :return:
    """
    attribute   = parseAttHeader(_attributedata)

    return attribute, ""


def notparsed(_attributedata, _recorddata, _attoffset):
    """
    placeholder for attributes which are not parsed yet; returns only the header template
    :param _attributedata:
    :param _recorddata:
    :return:
    """

    attribute = parseAttHeader(_attributedata)

    return attribute, ""


'''
Helper
'''

def LE(_string, _length=0, _signed=False):
    """turns pairs of characters from big to little endian
    :param _string: string to turn
    :param _length: length of expected string; rest filled with 0 or f
    :param _signed: signed or unsigned
    :return: turned string"""

    _newstring = ""
    i = 0

    if len(_string) % 2 != 0:
        _string = "0" + _string

    while i < len(_string):
        _newstring = _newstring + _string[-(i + 2)] + _string[-(i + 1)]
        i += 2

    _fillin = "0"

    if _signed == True and re.match(r'[8-9a-fA-F]', _newstring[0]):
        _fillin = "F"

    if _length != 0:
        while len(_newstring) % _length != 0:
            _newstring = _fillin + _newstring

    return _newstring


def mfttime(_miliseconds):
    '''
    Convert time in hex to human readable date and time for output
    :param _hextime:
    :return: mftdatetime
    '''
    _us = int(_miliseconds) / 10.
    _mftdatetime = datetime(1601,1,1) + timedelta(microseconds=_us)

    return _mftdatetime


def checkUSN(_recordarea):
    '''
    checks for update sequence number in read area
    :param _recordarea:
    :return:
    '''

    try:
        _USNposition = _recordarea.index(1022)
    except ValueError:
        try:
            _USNposition = _recordarea.index(511)
        except ValueError:
            return False,0
        else:
            return True, _USNposition
    else:
        return True, _USNposition


def buildGUID(_hex):
    """	buiding guid from hexvalue
    :param _hex: tuple with (00000000)-(0000)-(0000)-(0000)-(000000000000)
    :return: GUID
    """
    _guidchunk={}
    guidstring=binascii.hexlify(_hex)


    _guidchunk[0] = guidstring[:8]
    _guidchunk[1] = guidstring[8:-20]
    _guidchunk[2] = guidstring[12:-16]
    _guidchunk[3] = guidstring[16:-12]
    _guidchunk[4] = guidstring[20:]


    GUID = ""

    GUID =  LE(_guidchunk[0])     + "-"
    GUID += _guidchunk[1]         + "-"
    GUID += LE(_guidchunk[2])     + "-"
    GUID += _guidchunk[3]         + "-"
    GUID += _guidchunk[4]


    return GUID.upper()



if __name__ == "__main__":
    print"\nModule not executeable!\n"
    print"Please use the script 'mft.py'"