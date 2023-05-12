import sys
import os
import math
import binascii
#import csv
import time
import re
import unicodecsv as csv

from ctypes import *
from struct import *
from enum import Enum
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
from typing import List

from multiprocessing import Process, Manager

from datafile import *

@dataclass(order=True)
class VLFInfo:
    seqnum: int = 0
    vlfsize: int = 0
    vlfoffset: int = 0
    status: int = 0
    segments: List[int] = field(default_factory=list)

@dataclass(order=True)
class LogRecordInfo:
    vlfseqnum: int = 0
    blocknum: int = 0
    slotnum: int = 0
    fixedlength: int = 0
    length: int = 0
    previousLSN: List[bytes] = field(default_factory=list)
    flagbits: int = 0
    transactionid: List[bytes] = field(default_factory=list)
    op: int = 0
    context: int = 0
    offset: int = 0
    pageid: List[bytes] = field(default_factory=list)
    slotid: int = 0
    offsetinrow: int = 0
    begintime: str = ''
    endtime: str = ''
    #partitionid: List[bytes] = field(default_factory=list)
    partitionid: int = 0
    allocunitname: str = ''
    numelements: int = 0
    rowlogcontent: List[list] = field(default_factory=list)    
    
class Operation(Enum):
    LOP_UNKNOWN0 = 0
    LOP_FORMAT_PAGE = 1
    LOP_INSERT_ROWS = 2
    LOP_DELETE_ROWS = 3
    LOP_MODIFY_ROW = 4
    LOP_MODIFY_HEADER = 5
    LOP_MODIFY_COLUMNS = 6
    LOP_SET_BITS = 7
    LOP_UNKNOWN1 = 8
    LOP_DELTA_SYSIND = 9
    LOP_SET_FREE_SPACE = 10
    LOP_DELETE_SPLIT = 11
    LOP_UNDO_DELETE_SPLIT = 12
    LOP_EXPUNGE_ROWS = 13
    LOP_UNKNOWN2 = 14
    LOP_UNKNOWN3 = 15
    LOP_FILE_HDR_MODIFY = 16
    LOP_SET_GAM_BITS = 17
    LOP_UNKNOWN4 = 18
    LOP_UNKNOWN5 = 19
    LOP_UNKNOWN6 = 20
    LOP_UNKNOWN7 = 21
    LOP_INSYSXACT = 22
    LOP_BEGIN_XACT = 128
    LOP_COMMIT_XACT = 129
    LOP_ABORT_XACT = 130
    LOP_PREP_XACT = 131
    LOP_MARK_SAVEPOINT = 132
    LOP_FORGET_XACT = 133
    LOP_CREATE_FILE = 134
    LOP_DROP_FILE = 135
    LOP_MARK_DDL = 136
    LOP_UNKNOWN8 = 137
    LOP_HOBT_DELTA = 140
    LOP_LOCK_XACT = 141
    LOP_BEGIN_CKPT = 150
    LOP_XACT_CKPT = 152
    LOP_END_CKPT = 153
    LOP_BUF_WRITE = 154
    LOP_IDENTITY_TYPE = 155
    LOP_BEGIN_RECOVERY = 160
    LOP_END_RECOVERY = 161
    LOP_NONLOGGED_OP = 162
    LOP_SORT_BEGIN = 170
    LOP_SORT_END = 171
    LOP_SORT_EXTENT = 172
    LOP_CREATE_INDEX = 173
    LOP_DROP_INDEX = 174
    LOP_SORT_MEMORY = 175
    LOP_UNKNOWN10 = 176
    LOP_REPL_COMMAND = 200
    LOP_BEGIN_UPDATE = 201
    LOP_END_UPDATE = 202
    LOP_TEXT_POINTER = 203
    LOP_TEXT_INFO_BEGIN = 204
    LOP_TEXT_INFO_END = 205
    LOP_REPL_NOOP = 206
    LOP_TEXT_VALUE = 207
    LOP_SHINK_NOOP = 211
    
class Context(Enum):
    LCX_NULL = 0
    LCX_HEAP = 1
    LCX_CLUSTERED = 2
    LCX_INDEX_LEAF = 3
    LCX_INDEX_INTERIOR = 4
    LCX_GAM = 8
    LCX_IAM = 10
    LCX_PFS = 11
    LCX_BOOT_PAGE_CKPT = 23
    
class Logfile():
    def __init__(self):
        self.filepath = ''
        self.fHandle = ''
        self.fsize = 0
        self.blksize = 512
        self.vlfs = defaultdict(lambda: 0)
        
    def open(self, filepath):
        try:
            self.fHandle = open(filepath, 'rb')
        except:
            print('File open error: ' + filepath)
            return 1
        self.filepath = filepath
        self.fsize = os.path.getsize(filepath)
        print('Open ' + filepath)
        
    def read(self, offset, size):
        buf = ''
        try:
            self.fHandle.seek(offset)
            buf = self.fHandle.read(size)
        except:
            print('File read error')
        return buf
    
    def close(self):
        self.fHandle.close()
        
class CarvingProcess():
    def __init__(self, filepath, chunksize):
        super().__init__()
        
        self.fHandle = ''
        self.filepath = filepath
        self.chunksize = chunksize
        self.records = list()
        self.transactions = defaultdict(list)
        self.queries = []
        self.manager = Manager()
        self.rawdata = list()
        
    def open(self):
        try:
            self.fHandle = open(self.filepath, 'rb')
        except:
            print('File open error: ' + self.filepath)
            return 1
        print('Open ' + self.filepath)
        
    def read(self, offset, size):
        buf = ''
        try:
            self.fHandle.seek(offset)
            buf = self.fHandle.read(size)
        except:
            print('File read error')
        return buf
    
    def close(self):
        self.fHandle.close()
        
    def export(self, filename):
        if len(self.queries) != 0:
            header = ['Begin Time', 'End Time', 'Query']
            with open(filename, 'w', newline='') as f:
                wr = csv.writer(f, encoding='utf-8')
                wr.writerow(header)
                wr.writerows(self.queries)
    
    def process(self, offsetfile=None):
        start_time = int(time.time())
        
        object_list = []
        fsize = os.path.getsize(self.filepath)
        secsize = 512
        clustersize = secsize * 8
        numofcluster = fsize // clustersize
        numofprocess = 10
        unit = numofcluster // numofprocess
        
        threshold = 500000
        
        if offsetfile is None:
            hitOffset = self.manager.dict()
            for i in range(0 ,numofprocess):
                if i == (numofprocess - 1):
                    task = Process(target=carving, args=(self.filepath, i * unit, numofcluster + 1, self.chunksize, hitOffset))
                else:
                    task = Process(target=carving, args=(self.filepath, i * unit, (i + 1) * unit, self.chunksize, hitOffset))
                object_list.append(task)
                task.start()
            
            for task in object_list:
                task.join()
        else:
            hitOffset = defaultdict(int)
            with open(offsetfile, 'r') as f:
                data = f.read()
                iter = re.finditer("\d+: b\\\\?[\'\"]", data)
                start = []
                for matched in iter:
                    start.append(matched.start())
                    #if len(start) == threshold:
                    #    break
                    
                end = start[1:] + [len(data) + 1]
                #end = start[1:threshold + 1]
                
                for start, end in zip(start, end):
                    line = data[start:end-2]
                    offset = line[:re.match("\d+: b", line).end() - 3]
                    tranid = line[re.match("\d+: b", line).end() - 1:]
                    hitOffset[eval(offset)] = eval(tranid)
                    #if len(hitOffset) == threshold:
                    #    break
                
            
        end_time = int(time.time())
        print("***run time(sec): ", end_time-start_time)
        
        for offset, tranid in hitOffset.items():
            buf = self.read(offset, self.chunksize)
            recordlen = self._calcLogRecordLen(buf)
            del buf
            
            recordbuf = self.read(offset, recordlen)
            recordinfo = self._parseRecord(recordbuf)
            if recordinfo is None:
                continue
            recordinfo.offset = offset
            self.records.append(recordinfo)
            self.transactions[tranid].append(recordinfo)
        
        print('Complete')
        
    def recovery(self, mdf):
        print('Reconstruct Log Record')
        if mdf is None:
            print('[Error] Need insert matched data file')
            
        for tableinfo in mdf.tablelist:
            
            table_scheme = mdf.userschemesmap[tableinfo.tobjectid]
            table_scheme = sorted(table_scheme, key=lambda SchemeInfo: SchemeInfo.colorder)
            
            
            
            rowinfo = RowInfo()

            if len(table_scheme) == 0:
                continue

            for schema in table_scheme:
                mdf._tableSchemeAnalyzer(schema, rowinfo)
            
            #queries = []
            # log record in tableinfo
            records = [x for x in self.records if x.partitionid == tableinfo.partitionid]
            
            for record in records:
                record.allocunitname = tableinfo.tablename
                if record.op == Operation.LOP_INSERT_ROWS:
                    if len(record.rowlogcontent) > 0:
                        query = self._reconstructInsertDeleteRow(record.rowlogcontent[0], rowinfo, table_scheme, mdf.mssql.pagesize)
                    else:
                        query = False
                    if query is not False:
                        query = ','.join(query)
                        query = "insert into " + tableinfo.tablename + " values (" + query + ")"
                elif record.op == Operation.LOP_DELETE_ROWS:
                    if len(record.rowlogcontent) > 0:
                        query = self._reconstructInsertDeleteRow(record.rowlogcontent[0], rowinfo, table_scheme, mdf.mssql.pagesize)
                    else:
                        query = False
                    condition_str = []
                    if query is not False:
                        for i, schema in enumerate(table_scheme):
                            condition_str.append(schema.colname + "=" + query[i])
                        query = "delete from " + tableinfo.tablename + " where " + ' and '.join(condition_str)
                elif record.op == Operation.LOP_MODIFY_ROW:
                    query = self._reconstructUpdateRow(record, rowinfo, table_scheme, mdf)
                    set_str = []
                    condition_str = []
                    if query[0] and query[1]:
                        for i, schema in enumerate(table_scheme):
                            set_str.append(schema.colname + "=" + query[0][i])
                            condition_str.append(schema.colname + "=" + query[1][i])
                        query = "update " + tableinfo.tablename + " set " + ', '.join(set_str) + " where " + ' and '.join(condition_str)                            
                    else:
                        query = False
                transaction = self.transactions[record.transactionid]
                beginxact = [x for x in transaction if x.op == Operation.LOP_BEGIN_XACT]
                if len(beginxact) != 0:
                    begintime = beginxact[0].begintime
                else:
                    begintime = ''
                commitxact = [x for x in transaction if x.op == Operation.LOP_COMMIT_XACT]
                if len(commitxact) != 0:
                    endtime = commitxact[0].endtime
                else:
                    endtime = ''
                if query is not False:
                    self.queries.append([begintime, endtime, record.op, query])
                else:
                    self.rawdata.append([begintime, endtime, record.op, record])
            
    def _reconstructInsertDeleteRow(self, buf, rowinfo, schemlist, pagesize):
        recordlen = len(buf)
        if recordlen < 4:
            return False
        lenofnullbitmap = math.ceil(rowinfo.numoftotalcol/8)
        offsetoftotalnumofcol = unpack('<H', buf[0x02:0x04])[0]
        if offsetoftotalnumofcol > recordlen:
            return False
        
        totalnumofcol = unpack('<H', buf[offsetoftotalnumofcol:offsetoftotalnumofcol + 0x02])[0]
        
        if rowinfo.numoftotalcol != totalnumofcol:
            return False
        
        staticoffset = 1 + 1 + 2 # statusBit A + statusBit B + OffsetOfTotalNumberOfCol
        
        if rowinfo.numofvariablecol != 0:
            variableoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap
            numofvariablecol = unpack('<H', buf[variableoffset:variableoffset + 0x02])[0]
            variableoffset += 2
            variableoffset += (2 * numofvariablecol)
            variablecollenoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap + 2
            
        bitpos = 0
        numberofbitcol = 0
        
        coldata = []
        isLob = False
        
        for schema in schemlist:
            if schema.kindofcol == Columntype.STATIC_COLUMN:
                columnlength = schema.colsize
                if schema.datatype == 'bit':
                    if numberofbitcol % 8 == 0:
                        bitpos = staticoffset
                        columnbuff = buf[bitpos:bitpos + columnlength]
                        staticoffset += columnlength
                    else:
                        columnbuff = buf[bitpos:bitpos + columnlength]
                    numberofbitcol += 1
                else:
                    if (columnlength + staticoffset) > recordlen:
                        break
                    
                    if columnlength < pagesize:
                        columnbuff = buf[staticoffset:staticoffset + columnlength]
                    else:
                        break
                    staticoffset += columnlength
            elif schema.kindofcol == Columntype.VARIABLE_COLUMN:
                variablecollen = unpack('<H', buf[variablecollenoffset:variablecollenoffset + 0x02])[0]
                
                if variablecollen > 0x8000:
                    variablecollen -= 0x8000
                    isLob = True
                columnlength = variablecollen - variableoffset
                
                variablecollenoffset += 2
                if (variableoffset < pagesize) and (variablecollen < pagesize):
                    if (variableoffset + columnlength <= recordlen) and (columnlength < pagesize):
                        columnbuff = buf[variableoffset:variableoffset + columnlength]
                        variableoffset += columnlength
                        
            output = self._decodeValue(columnbuff, columnlength, schema, numberofbitcol, isLob)
            coldata.append(output)
            isLob = False
        
        return coldata
    
    def _reconstructUpdateRow(self, record, rowinfo, schemlist, mdf):
        if len(record.rowlogcontent) > 1:
            before = record.rowlogcontent[0]
            after = record.rowlogcontent[1]
        else:
            return False, False
        pageid, _ = unpack('<IH', record.pageid) # limitation fileid = 1
        buf = mdf.mssql.read(pageid * mdf.mssql.pagesize, mdf.mssql.pagesize)
        pageheader = mdf.mssql.getPageHeader(buf)
        
        if pageheader.flagbits & 0x100:
            buf = mdf._tornbits(buf)
            
        fmt = '<' + str(pageheader.slotcnt) + 'H'
        rowoffsetarray = list(reversed(unpack(fmt, buf[-pageheader.slotcnt * 2:])))
        if record.slotid >= len(rowoffsetarray):
            return False, False
        recordlen = self._calcDataRecordLen(buf[rowoffsetarray[record.slotid]:], rowinfo)
        recordbuf = buf[rowoffsetarray[record.slotid]:rowoffsetarray[record.slotid] + recordlen]
        
        after_coldata = self._reconstructInsertDeleteRow(recordbuf, rowinfo, schemlist, mdf.mssql.pagesize)
        before_recordbuf = recordbuf[:record.offsetinrow] + recordbuf[record.offsetinrow:record.offsetinrow+len(after)].replace(after, before) + \
            recordbuf[record.offsetinrow+len(after):]
        before_coldata = self._reconstructInsertDeleteRow(before_recordbuf, rowinfo, schemlist, mdf.mssql.pagesize)
        
        if after_coldata is False or before_coldata is False:
            return False, False
        
        return after_coldata, before_coldata 
    
    def _calcDataRecordLen(self, buf, rowinfo):
        offsetOftotalNumOfCol = unpack('<H', buf[0x02:0x04])[0]
        totalNumOfCol = unpack('<H', buf[offsetOftotalNumOfCol:offsetOftotalNumOfCol + 0x02])[0]
        
        if totalNumOfCol != rowinfo.numoftotalcol:
            return 0
        
        lenOfNullBitmap = math.ceil(rowinfo.numoftotalcol/8)
        
        recordLen = 0
        
        recordLen += 4 # StatusBit A(1 byte) + StatusBit B(1 byte) + Offset of number of column(2 bytes)
        recordLen += rowinfo.staticlength
        recordLen += (2 + lenOfNullBitmap)
        
        if (rowinfo.numofvariablecol == 0 or buf[0] == 0x10 or buf[0] == 0x1c):
            return recordLen
        else:
            numOfVariableCol = unpack('<H', buf[recordLen:recordLen + 0x02])[0]
            recordLen = unpack('<H', buf[recordLen + numOfVariableCol * 2:recordLen + (numOfVariableCol + 1) * 2])[0]
            if recordLen > 0x8000:
                recordLen -= 0x8000
            
            return recordLen            
        
    @classmethod
    def _calcLogRecordLen(self, buf):
        fixedlength = unpack('<H', buf[0x02:0x04])[0]
        numelements = buf[0x3E]
        
        retVal = fixedlength + 2 # fixed length + numelements(2 bytes)
        if numelements * 2 % 4 != 0:
            retVal += (numelements * 2 + (4 - numelements * 2 % 4))
        else:
            retVal += (numelements * 2)
        fmt = '<' + str(numelements) + 'H'
        rowlogcontentslength = unpack(fmt, buf[0x40:0x40 + numelements * 2])
        for len in rowlogcontentslength:
            if len != 0:
                retVal += (len + 4 - len % 4)
        
        return retVal
    
    @classmethod
    def _parseRecord(self, buf):
        if len(buf) < 24:
            return None
        recordinfo = LogRecordInfo()
        recordinfo.fixedlength = unpack('<H', buf[0x02:0x04])[0]
        recordinfo.previousLSN = unpack('<iih', buf[0x04:0x0E])
        recordinfo.flagbits = unpack('<H', buf[0x0E:0x10])[0]
        recordinfo.transactionid = buf[0x10:0x16]
        recordinfo.op = Operation(buf[0x16])
        recordinfo.context = buf[0x17]
        if recordinfo.op is Operation.LOP_BEGIN_XACT:
            try:
                begintime = datetime(1900, 1, 1, tzinfo=timezone.utc) + \
                    timedelta(days=unpack('<i', buf[0x2C:0x30])[0], seconds=unpack('<i', buf[0x28:0x2C])[0]/300)
                recordinfo.begintime = begintime.strftime("%m/%d/%Y %H:%M:%S.%f")
            except:
                pass
        elif recordinfo.op is Operation.LOP_COMMIT_XACT:
            try:
                endtime = datetime(1900, 1, 1, tzinfo=timezone.utc) + \
                    timedelta(days=unpack('<i', buf[0x1C:0x20])[0], seconds=unpack('<i', buf[0x18:0x1C])[0]/300)
                recordinfo.endtime = endtime.strftime("%m/%d/%Y %H:%M:%S.%f")
            except:
                pass            
        if recordinfo.op in [Operation.LOP_INSERT_ROWS, Operation.LOP_DELETE_ROWS, Operation.LOP_MODIFY_ROW]:
            recordinfo.pageid = buf[0x18:0x1E]
            recordinfo.slotid = unpack('<H', buf[0x1E:0x20])[0]
            recordinfo.offsetinrow = unpack('<H', buf[0x38:0x3A])[0]
            recordinfo.partitionid = unpack('<Q', buf[0x30:0x38])[0]
            recordinfo.numelements = buf[0x3E]
            fmt = '<' + str(recordinfo.numelements) + 'H'
            rowlogcontentslength = unpack(fmt, buf[0x40:0x40+recordinfo.numelements*2])
            if recordinfo.numelements * 2 % 4 != 0:
                rowlogcontentoffset = recordinfo.numelements * 2 + (4 - recordinfo.numelements * 2 % 4)
            else:
                rowlogcontentoffset = recordinfo.numelements * 2
            for length in rowlogcontentslength:
                recordinfo.rowlogcontent.append(buf[0x40 + rowlogcontentoffset:0x40 + rowlogcontentoffset + length])
                if length != 0:
                    rowlogcontentoffset += (length + 4 - length % 4)
            ## rowlogcontent 0~5            
        return recordinfo
    
    @classmethod
    def _decodeValue(self, buf, length, schema, numberofbitcol, isLob):
        output = ''
        if schema.datatype == "tinyint":
            output = str(unpack('<B', buf)[0])
        elif schema.datatype == "smallint":
            output = str(unpack('<H', buf)[0])
        elif schema.datatype == "int":
            output = "'" + str(unpack('<I', buf)[0]) + "'"
        elif schema.datatype == "bigint":
            output = str(unpack('<Q', buf)[0])
        elif schema.datatype == "real":
            output = str(unpack('<f', buf)[0])
        elif schema.datatype == "float":
            output = str(unpack('<d', buf)[0])
        elif schema.datatype in ("datetime", "smalldatetime", "money", "smallmoney"):
            output = "cast(0x" + binascii.b2a_hex(bytes(reversed(buf))).decode('utf8') + " as " + schema.datatype + ")"
        elif schema.datatype == "date":
            output = "cast(0x" + binascii.b2a_hex(buf).decode('utf8') + " as date)"
        elif "time" in schema.datatype:
            output = "cast(0x%02x" % schema.precisionoftime + binascii.b2a_hex(buf).decode('utf8') + " as time)"
        elif "numeric" in schema.datatype or "decimal" in schema.datatype:
            output = "convert(" + schema.datatype + ",0x%02x%02x0001" % (schema.precisionofnumeric, schema.scaleofnumeric) + \
                binascii.b2a_hex(buf[1:]).decode('utf8') + ")"
        elif schema.datatype == "char":
            output = "'" + buf.decode('utf8') + "'"
        elif schema.datatype == "varchar":
            if isLob: # Large object
                output = ""
                #output = "'" + self._parseLobRecord(buf).decode('utf8') + "'"
            else:
                output = "'" + buf.decode('utf8', errors="ignore") + "'"
        elif schema.datatype == "nchar":
            output = "'" + buf.decode('utf16') + "'" # xml, text, ntext, image
        elif schema.datatype == "nvarchar":
            if isLob: # Large object
                output = ""
                #output = "'" + self._parseLobRecord(buf).decode('utf16') + "'"
            else:
                output = "'" + buf.decode('utf16') + "'" # hierarchyid, geometry, geography, uniqueidentifier, sql_variant
        elif schema.datatype == "binary":
            output = '0x' + (binascii.b2a_hex(buf)).decode('utf8')
        elif schema.datatype == "varbinary":
            if isLob: # 8bytes => lob header (type(2 byptes) / level(1 byte) / unused(1 byte) / updateseq(4 bytes))              
                output = '0x'
                #output = '0x' + (binascii.b2a_hex(self._parseLobRecord(buf))).decode('utf8')
            else:
                output = '0x' + (binascii.b2a_hex(buf)).decode('utf8')
        # text, ntext, image
        return output

        
class LogfileParser():
    def __init__(self, ldf, mdf = None):
        self.ldf = ldf
        self.headerSize = 8192
        self.mdf = mdf
        self.vlfs = list()
        self.records = list()
        self.segments = defaultdict(int)
        self.transactions = defaultdict(list)
        self.queries = []
        
    def scanVLFs(self):
        print('LDF VLF(Virtual Log Files) Scan')
        vlfOffset = self.headerSize
        while True:
            buf = self.ldf.read(vlfOffset, 0x30)
            if not buf:
                break
            
            vlfinfo = VLFInfo()
            vlfinfo.seqnum = unpack('<I', buf[0x04:0x08])[0]
            vlfinfo.vlfsize = unpack('<I', buf[0x10:0x14])[0]
            vlfinfo.vlfoffset = vlfOffset
            if vlfinfo.seqnum != 0:
                self.vlfs.append(vlfinfo)
                self.ldf.vlfs[vlfinfo.seqnum] = vlfinfo
            vlfOffset += vlfinfo.vlfsize
            
    def scanLogSegment(self):
        print('Log Segment Scan')
        self.vlfs.sort(key=lambda x: x.vlfoffset)
        blkSize = self.ldf.blksize
        
        for vlfinfo in self.vlfs:
            offset = 0
            if vlfinfo.seqnum == 0:
                continue
            buf = self.ldf.read(vlfinfo.vlfoffset, vlfinfo.vlfsize)
            
            while offset < vlfinfo.vlfsize:
                if buf[offset] == 0x50 or buf[offset] == 0x58:
                    vlfinfo.segments.append(offset)
                offset += blkSize
                
    def parseVLF(self):
        self.vlfs.sort(key=lambda x: x.vlfoffset)
        blkSize = self.ldf.blksize # 512 bytes
        blkOffset = 0x2000 # 8192 bytes (vlf header)
        blkNum = int(blkOffset / blkSize)
        for vlfinfo in self.vlfs:
            if vlfinfo.seqnum == 0:
                continue
            buf = self.ldf.read(vlfinfo.vlfoffset, vlfinfo.vlfsize)
            
            segmentlen = vlfinfo.segments[1:] + [vlfinfo.vlfsize]
            for i, (offset, length) in enumerate(zip(vlfinfo.segments, segmentlen)):
                blkNum = int(offset/blkSize)
                self.parseSegment(buf[offset:length], vlfinfo, blkNum)
                
        print('Complete')
            
    def extractLogRecord(self):
        opids = [Operation.LOP_DELETE_ROWS, Operation.LOP_INSERT_ROWS, Operation.LOP_MODIFY_ROW]
        for record in self.records:
            if record.op not in opids:
                continue
            
            seq = record.vlfseqnum
            blknum = record.blocknum
            
            offset = self.ldf.vlfs[seq].vlfoffset + self.ldf.blksize * blknum + record.offset
            buf = self.ldf.read(offset, 0x40)
            with open(os.path.join(os.getcwd(), 'result', str(offset)), 'wb') as f:
                f.write(buf)
            
    def parseSegment(self, buf, vlfinfo, blkNum):
        buf = self._fixup(buf, self.ldf.blksize)
        slotNum = unpack('<H', buf[0x02:0x04])[0]
        segSize = unpack('<H', buf[0x04:0x06])[0]
        firstLsn = unpack('<iih', buf[0x0C:0x16])
        timestamp = datetime(1900, 1, 1, tzinfo=timezone.utc) + \
            timedelta(days=unpack('<i', buf[0x34:0x38])[0], seconds=unpack('<i', buf[0x30:0x34])[0]/300)
        recordoffsetarray = sorted(self._getRecordOffsetArray(buf[:segSize], slotNum))
        
        recordlen = recordoffsetarray[1:] + [segSize - len(recordoffsetarray) * 2]
        for i, (offset, length) in enumerate(zip(recordoffsetarray, recordlen)):
            recordinfo = self._parseRecord(buf[offset:])
            recordinfo.vlfseqnum = vlfinfo.seqnum
            recordinfo.blocknum = blkNum
            recordinfo.slotnum = i + 1
            recordinfo.length = length - offset
            recordinfo.offset = offset
            self.records.append(recordinfo)
            self.transactions[recordinfo.transactionid].append(recordinfo)

    @classmethod  
    def _fixup(self, buf, blksize):
        origin = bytearray(buf)
        offset = 0
        for i in range(int(len(buf)/blksize)):
            origin[offset] = buf[-(i + 1)]
            offset += blksize
            
        return bytes(origin)
    
    def recovery(self):
        print('Reconstruct Log Record')
        if self.mdf is None:
            print('[Error] Need insert matched data file')

        for tableinfo in self.mdf.tablelist:
            table_scheme = self.mdf.userschemesmap[tableinfo.tobjectid]
            table_scheme = sorted(table_scheme, key=lambda SchemeInfo: SchemeInfo.colorder)
            
            rowinfo = RowInfo()

            if len(table_scheme) == 0:
                continue

            for schema in table_scheme:
                self.mdf._tableSchemeAnalyzer(schema, rowinfo)
            
            #queries = []
            # log record in tableinfo
            records = [x for x in self.records if x.partitionid == tableinfo.partitionid]
            
            for record in records:
                if record.op == Operation.LOP_INSERT_ROWS:
                    query = self._reconstructInsertDeleteRow(record.rowlogcontent[0], rowinfo, table_scheme)
                    if query is not False:
                        query = ','.join(query)
                        query = "insert into " + tableinfo.tablename + " values (" + query + ")"
                elif record.op == Operation.LOP_DELETE_ROWS:
                    query = self._reconstructInsertDeleteRow(record.rowlogcontent[0], rowinfo, table_scheme)
                    condition_str = []
                    if query is not False:
                        for i, schema in enumerate(table_scheme):
                            condition_str.append(schema.colname + "=" + query[i])
                        query = "delete from " + tableinfo.tablename + " where " + ' and '.join(condition_str)
                elif record.op == Operation.LOP_MODIFY_ROW:
                    query = self._reconstructUpdateRow(record, rowinfo, table_scheme)
                    set_str = []
                    condition_str = []
                    if query[0] and query[1]:
                        for i, schema in enumerate(table_scheme):
                            set_str.append(schema.colname + "=" + query[0][i])
                            condition_str.append(schema.colname + "=" + query[1][i])
                        query = "update " + tableinfo.tablename + " set " + ', '.join(set_str) + " where " + ' and '.join(condition_str)                            
                transaction = self.transactions[record.transactionid]
                beginxact = [x for x in transaction if x.op == Operation.LOP_BEGIN_XACT]
                if len(beginxact) != 0:
                    begintime = beginxact[0].begintime
                else:
                    begintime = ''
                commitxact = [x for x in transaction if x.op == Operation.LOP_COMMIT_XACT]
                if len(commitxact) != 0:
                    endtime = commitxact[0].endtime
                else:
                    endtime = ''
                if query is not False:
                    self.queries.append([begintime, endtime, str(record.op), query])
                    
    def export(self, filename):
        if len(self.queries) != 0:
            header = ['Begin Time', 'End Time', 'Query']
            with open(filename, 'w', newline='') as f:
                wr = csv.writer(f)
                wr.writerow(header)
                wr.writerows(self.queries)
            
    def _reconstructInsertDeleteRow(self, buf, rowinfo, schemlist):
        recordlen = len(buf)
        if recordlen < 4:
            return False
        lenofnullbitmap = math.ceil(rowinfo.numoftotalcol/8)
        offsetoftotalnumofcol = unpack('<H', buf[0x02:0x04])[0]
        if offsetoftotalnumofcol > recordlen:
            return False
        
        totalnumofcol = unpack('<H', buf[offsetoftotalnumofcol:offsetoftotalnumofcol + 0x02])[0]
        
        if rowinfo.numoftotalcol != totalnumofcol:
            return False
        
        staticoffset = 1 + 1 + 2 # statusBit A + statusBit B + OffsetOfTotalNumberOfCol
        
        if rowinfo.numofvariablecol != 0:
            variableoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap
            numofvariablecol = unpack('<H', buf[variableoffset:variableoffset + 0x02])[0]
            variableoffset += 2
            variableoffset += (2 * numofvariablecol)
            variablecollenoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap + 2
            
        bitpos = 0
        numberofbitcol = 0
        
        coldata = []
        isLob = False
        
        for schema in schemlist:
            if schema.kindofcol == Columntype.STATIC_COLUMN:
                columnlength = schema.colsize
                if schema.datatype == 'bit':
                    if numberofbitcol % 8 == 0:
                        bitpos = staticoffset
                        columnbuff = buf[bitpos:bitpos + columnlength]
                        staticoffset += columnlength
                    else:
                        columnbuff = buf[bitpos:bitpos + columnlength]
                    numberofbitcol += 1
                else:
                    if (columnlength + staticoffset) > recordlen:
                        break
                    
                    if columnlength < self.mdf.mssql.pagesize:
                        columnbuff = buf[staticoffset:staticoffset + columnlength]
                    else:
                        break
                    staticoffset += columnlength
            elif schema.kindofcol == Columntype.VARIABLE_COLUMN:
                variablecollen = unpack('<H', buf[variablecollenoffset:variablecollenoffset + 0x02])[0]
                
                if variablecollen > 0x8000:
                    variablecollen -= 0x8000
                    isLob = True
                columnlength = variablecollen - variableoffset
                
                variablecollenoffset += 2
                if (variableoffset < self.mdf.mssql.pagesize) and (variablecollen < self.mdf.mssql.pagesize):
                    if (variableoffset + columnlength <= recordlen) and (columnlength < self.mdf.mssql.pagesize):
                        columnbuff = buf[variableoffset:variableoffset + columnlength]
                        variableoffset += columnlength
                        
            output = self._decodeValue(columnbuff, columnlength, schema, numberofbitcol, isLob)
            coldata.append(output)
            isLob = False
        
        return coldata
    
    def _reconstructUpdateRow(self, record, rowinfo, schemlist):
        before = record.rowlogcontent[0]
        after = record.rowlogcontent[1]
        pageid, _ = unpack('<IH', record.pageid) # limitation fileid = 1
        buf = self.mdf.mssql.read(pageid * self.mdf.mssql.pagesize, self.mdf.mssql.pagesize)
        pageheader = self.mdf.mssql.getPageHeader(buf)
        
        if pageheader.flagbits & 0x100:
            buf = self.mdf._tornbits(buf)
            
        rowoffsetarray = self.mdf.mssql.getRowOffsetArray(buf, pageheader)
        fmt = '<' + str(pageheader.slotcnt) + 'H'
        rowoffsetarray = list(reversed(unpack(fmt, buf[-pageheader.slotcnt * 2:])))
        recordlen = self._calcDataRecordLen(buf[rowoffsetarray[record.slotid]:], rowinfo)
        recordbuf = buf[rowoffsetarray[record.slotid]:rowoffsetarray[record.slotid] + recordlen]
        
        after_coldata = self._reconstructInsertDeleteRow(recordbuf, rowinfo, schemlist)
        before_recordbuf = recordbuf[:record.offsetinrow] + recordbuf[record.offsetinrow:record.offsetinrow+len(after)].replace(after, before) + \
            recordbuf[record.offsetinrow+len(after):]
        before_coldata = self._reconstructInsertDeleteRow(before_recordbuf, rowinfo, schemlist)
        
        if after_coldata is False or before_coldata is False:
            return False, False
        
        return after_coldata, before_coldata 
    
    def _calcDataRecordLen(self, buf, rowinfo):
        offsetOftotalNumOfCol = unpack('<H', buf[0x02:0x04])[0]
        totalNumOfCol = unpack('<H', buf[offsetOftotalNumOfCol:offsetOftotalNumOfCol + 0x02])[0]
        
        if totalNumOfCol != rowinfo.numoftotalcol:
            return 0
        
        lenOfNullBitmap = math.ceil(rowinfo.numoftotalcol/8)
        
        recordLen = 0
        
        recordLen += 4 # StatusBit A(1 byte) + StatusBit B(1 byte) + Offset of number of column(2 bytes)
        recordLen += rowinfo.staticlength
        recordLen += (2 + lenOfNullBitmap)
        
        if (rowinfo.numofvariablecol == 0 or buf[0] == 0x10 or buf[0] == 0x1c):
            return recordLen
        else:
            numOfVariableCol = unpack('<H', buf[recordLen:recordLen + 0x02])[0]
            recordLen = unpack('<H', buf[recordLen + numOfVariableCol * 2:recordLen + (numOfVariableCol + 1) * 2])[0]
            if recordLen > 0x8000:
                recordLen -= 0x8000
            
            return recordLen        
    
    def _calcLogRecordLen(self, buf):
        fixedlength = unpack('<H', buf[0x02:0x04])[0]
        numelements = buf[0x3E]
        
        retVal = fixedlength + 2 # fixed length + numelements(2 bytes)
        if numelements * 2 % 4 != 0:
            retVal += (numelements * 2 + (4 - numelements * 2 % 4))
        else:
            retVal += (numelements * 2)
        fmt = '<' + str(numelements) + 'H'
        rowlogcontentslength = unpack(fmt, buf[0x40:0x40 + numelements * 2])
        for len in rowlogcontentslength:
            if len != 0:
                retVal += (len + 4 - len % 4)
        
        return retVal
        
    @classmethod
    def _decodeValue(self, buf, length, schema, numberofbitcol, isLob):
        output = ''
        if schema.datatype == "tinyint":
            output = str(unpack('<B', buf)[0])
        elif schema.datatype == "smallint":
            output = str(unpack('<H', buf)[0])
        elif schema.datatype == "int":
            output = "'" + str(unpack('<I', buf)[0]) + "'"
        elif schema.datatype == "bigint":
            output = str(unpack('<Q', buf)[0])
        elif schema.datatype == "real":
            output = str(unpack('<f', buf)[0])
        elif schema.datatype == "float":
            output = str(unpack('<d', buf)[0])
        elif schema.datatype in ("datetime", "smalldatetime", "money", "smallmoney"):
            output = "cast(0x" + binascii.b2a_hex(bytes(reversed(buf))).decode('utf8') + " as " + schema.datatype + ")"
        elif schema.datatype == "date":
            output = "cast(0x" + binascii.b2a_hex(buf).decode('utf8') + " as date)"
        elif "time" in schema.datatype:
            output = "cast(0x%02x" % schema.precisionoftime + binascii.b2a_hex(buf).decode('utf8') + " as time)"
        elif "numeric" in schema.datatype or "decimal" in schema.datatype:
            output = "convert(" + schema.datatype + ",0x%02x%02x0001" % (schema.precisionofnumeric, schema.scaleofnumeric) + \
                binascii.b2a_hex(buf[1:]).decode('utf8') + ")"
        elif schema.datatype == "char":
            output = "'" + buf.decode('utf8') + "'"
        elif schema.datatype == "varchar":
            if isLob: # Large object
                output = ""
                #output = "'" + self._parseLobRecord(buf).decode('utf8') + "'"
            else:
                output = "'" + buf.decode('utf8', errors="ignore") + "'"
        elif schema.datatype == "nchar":
            output = "'" + buf.decode('utf16') + "'" # xml, text, ntext, image
        elif schema.datatype == "nvarchar":
            if isLob: # Large object
                output = ""
                #output = "'" + self._parseLobRecord(buf).decode('utf16') + "'"
            else:
                output = "'" + buf.decode('utf16') + "'" # hierarchyid, geometry, geography, uniqueidentifier, sql_variant
        elif schema.datatype == "binary":
            output = '0x' + (binascii.b2a_hex(buf)).decode('utf8')
        elif schema.datatype == "varbinary":
            if isLob: # 8bytes => lob header (type(2 byptes) / level(1 byte) / unused(1 byte) / updateseq(4 bytes))              
                output = '0x'
                #output = '0x' + (binascii.b2a_hex(self._parseLobRecord(buf))).decode('utf8')
            else:
                output = '0x' + (binascii.b2a_hex(buf)).decode('utf8')
        # text, ntext, image
        return output

    ## for fixup array test
    def maskingcheck(self):
        offset = 0
        firstbyte = defaultdict(int)
        while offset < self.ldf.fsize:
            firstbyte[offset] = self.ldf.read(offset, 1).hex()
            offset += self.ldf.blksize
            
        print('Check complete')
                    
    @classmethod
    def _addOffset(self, hitOffset, offsetList, offset):
        for _off, tranid in offsetList:
            hitOffset[offset + _off] = tranid
    
    @classmethod
    def _parseRecord(self, buf):
        recordinfo = LogRecordInfo()
        recordinfo.fixedlength = unpack('<H', buf[0x02:0x04])[0]
        recordinfo.previousLSN = unpack('<iih', buf[0x04:0x0E])
        recordinfo.flagbits = unpack('<H', buf[0x0E:0x10])[0]
        recordinfo.transactionid = buf[0x10:0x16]
        recordinfo.op = Operation(buf[0x16])
        recordinfo.context = buf[0x17]
        if recordinfo.op is Operation.LOP_BEGIN_XACT:
            begintime = datetime(1900, 1, 1, tzinfo=timezone.utc) + \
                timedelta(days=unpack('<i', buf[0x2C:0x30])[0], seconds=unpack('<i', buf[0x28:0x2C])[0]/300)
            recordinfo.begintime = begintime.strftime("%m/%d/%Y %H:%M:%S.%f")
        elif recordinfo.op is Operation.LOP_COMMIT_XACT:
            endtime = datetime(1900, 1, 1, tzinfo=timezone.utc) + \
                timedelta(days=unpack('<i', buf[0x1C:0x20])[0], seconds=unpack('<i', buf[0x18:0x1C])[0]/300)
            recordinfo.endtime = endtime.strftime("%m/%d/%Y %H:%M:%S.%f")
            
        if recordinfo.op in [Operation.LOP_INSERT_ROWS, Operation.LOP_DELETE_ROWS, Operation.LOP_MODIFY_ROW]:
            #recordinfo.partitionid = buf[0x30:0x38]
            recordinfo.pageid = buf[0x18:0x1E]
            recordinfo.slotid = unpack('<H', buf[0x1E:0x20])[0]
            recordinfo.offsetinrow = unpack('<H', buf[0x38:0x3A])[0]
            recordinfo.partitionid = unpack('<Q', buf[0x30:0x38])[0]
            #recordinfo.numelements = unpack('<H', buf[0x3E:0x40])[0]
            recordinfo.numelements = buf[0x3E]
            fmt = '<' + str(recordinfo.numelements) + 'H'
            rowlogcontentslength = unpack(fmt, buf[0x40:0x40+recordinfo.numelements*2])
            if recordinfo.numelements * 2 % 4 != 0:
                rowlogcontentoffset = recordinfo.numelements * 2 + (4 - recordinfo.numelements * 2 % 4)
            else:
                rowlogcontentoffset = recordinfo.numelements * 2
            for len in rowlogcontentslength:
                recordinfo.rowlogcontent.append(buf[0x40 + rowlogcontentoffset:0x40 + rowlogcontentoffset + len])
                if len != 0:
                    rowlogcontentoffset += (len + 4 - len % 4)
            ## rowlogcontent 0~5            
        return recordinfo
    
    @classmethod    
    def _getRecordOffsetArray(self, buf, slotNum):
        fmt = '<' + str(slotNum) + 'H'
        recordoffsetarray = reversed(unpack(fmt, buf[-slotNum * 2:]))
        recordoffsetarray = list(filter(lambda x: x!= 0, recordoffsetarray))
        return recordoffsetarray
            
def carving(filepath, start, end, chunksize, hitOffset):
    fHandle = open(filepath, 'rb')
    
    offset = start * chunksize
    while offset < end * chunksize:
        fHandle.seek(offset)
        buf = fHandle.read(chunksize)
        offsetList = scanSig(buf, chunksize)
        addOffset(hitOffset, offsetList, offset)
        offset += chunksize        
        
def scanSig(buf, size):
    sig1 = [b'\x00\x00\x3E\x00', b'\x40\x00\x3E\x00', b'\x48\x00\x3E\x00', b'\x80\x00\x3E\x00', b'\x88\x00\x3E\x00']
    op1 = [2, 3, 4] # INSERT_ROWS / DELETE_ROWS / MODIFY_ROW
    sig2 = [b'\x00\x00\x4C\x00', b'\x40\x00\x4C\x00', b'\x48\x00\x4C\x00', b'\x80\x00\x4C\x00', b'\x88\x00\x4C\x00']
    op2 = 128 # BEGIN_XACT
    sig3 = [b'\x00\x00\x50\x00', b'\x40\x00\x50\x00', b'\x48\x00\x50\x00', b'\x80\x00\x50\x00', b'\x88\x00\x50\x00']
    op3 = 129 # COMMIT_XACT
    opOffset = 0x16
    byteUnit = 4 # 4 바이트 단위로 파싱 진행
    offset = 0
    
    offsetList = []
    while offset + opOffset < size:
        if buf[offset:offset + 0x04] in sig1 and buf[offset + opOffset] in op1:
            offsetList.append([offset, buf[offset + 0x10:offset + 0x16]])  
        elif buf[offset:offset + 0x04] in sig2 and buf[offset + opOffset] == op2:
            offsetList.append([offset, buf[offset + 0x10:offset + 0x16]])
        elif buf[offset:offset + 0x04] in sig3 and buf[offset + opOffset] == op3:
            offsetList.append([offset, buf[offset + 0x10:offset + 0x16]])
        offset += byteUnit
        
    return offsetList

def addOffset(hitOffset, offsetList, offset):
    for _off, tranid in offsetList:
        hitOffset[offset + _off] = tranid
    
def main():
    print('MSSQL Log Record Parser Tool (version 1.0)')
    ldf = Logfile()
    ldf.open(sys.argv[2])
    
    parser = LogfileParser(ldf)
    #parser.scanVLFs()
    #parser.scanLogSegment()
    #parser.scanVLFs()
    #parser.parseVLF()
    #parser.extractLogRecord()
    
    #parser.carvingRecord()
    parser.maskingcheck()

if __name__ == "__main__":
    main()
            
        