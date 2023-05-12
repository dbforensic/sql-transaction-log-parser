import os
import enum
import math
import json

from ctypes import *
from struct import *
from dataclasses import dataclass
from collections import defaultdict

class _MSSQLPageHeaer(LittleEndianStructure):
    _fields_ = [
        ('headerversion', c_uint8),
        ('type', c_uint8),
        ('typeflagbits', c_uint8),
        ('level', c_uint8),
        ('flagbits', c_uint16),
        ('indexid', c_uint16),
        ('previouspageid', c_uint32),
        ('previousfileid', c_uint16),
        ('pminlen', c_uint16),
        ('nextpageid', c_uint32),
        ('nextfileid', c_uint16),
        ('slotcnt', c_uint16),
        ('objectid', c_uint32),
        ('freecnt', c_uint16),
        ('freedata', c_uint16),
        ('pageid', c_uint32),
        ('fileid', c_uint16),
        ('reservedcnt', c_uint16),
        ('lsn1', c_uint32),
        ('lsn2', c_uint32),
        ('lsn3', c_uint16),
        ('xactreserved', c_uint16),
        ('xdesidpart2', c_uint32),
        ('xdesidpart1', c_uint16),
        ('ghostreccnt', c_uint16),
        ('tornbits', c_uint32)
    ]

def _memcpy(buf, fmt):
    return cast(c_char_p(buf), POINTER(fmt)).contents

@dataclass(order=True)
class SchemeInfo:
    tobjectid: int = 0
    colorder: int = 0
    xtype: int = 0
    utype: int = 0
    colsize: int = 0
    colname: str = ''
    datatype: str = ''
    kindofcol: int = 0
    ismax: bool = False
    precisionofnumeric: int = 0
    scaleofnumeric: int = 0
    precisionoftime: int = 0

class Columntype(enum.Enum):
    STATIC_COLUMN = 1
    VARIABLE_COLUMN = 2

@dataclass(order=True)
class RowInfo:
    staticlength: int = 0
    numoftotalcol: int = 0
    numofstaticcol: int = 0
    numofvariablecol: int = 0
    checklastcolumn: bool = False
    numofbitcol: int = 0

@dataclass(order=True)
class TableInfo:
    tobjectid: int = 0
    tablename: str = ''
    numofcolumns: int = 0
    pobjectid: int = 0
    partitionid: int = 0

class Datafile():
    def __init__(self):
        self.filepath = ''
        self.fHandle = ''
        self.fbuf = ''
        self.pagesize = 8192

    def open(self, filepath):
        try:
            self.fHandle = open(filepath, 'rb')
        except:
            print('File open error : ' + filepath)
            return 1
        self.filepath = filepath
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

    def getPageHeader(self, buf):
        pageheader = _memcpy(buf[:sizeof(_MSSQLPageHeaer)], _MSSQLPageHeaer)
        return pageheader
    
    def getRowOffsetArray(self, buf, pageheader):
        fmt = '<' + str(pageheader.slotcnt) + 'H'
        rowoffsetarray = reversed(unpack(fmt, buf[-pageheader.slotcnt * 2:]))
        rowoffsetarray = list(filter(lambda x: x != 0, rowoffsetarray))
        return rowoffsetarray
    
class DatafileParser():
    def __init__(self, mssql):
        self.mssql = mssql
        self.pages = defaultdict(lambda : 0) # pageMap
        self.systemschemesmap = defaultdict(list)
        self.userschemesmap = defaultdict(list)
        self.tablelist = []
        self.of = None

    def scanPages(self, filename):
        print('MDF Page Scan')
        pagenumber = 0
        jsonFilename = os.path.abspath(os.path.splitext(filename)[0] + '.json')

        if os.path.isfile(jsonFilename):
            pages = json.load(open(jsonFilename))
            for pagenumber, objectid in pages.items():
                self.pages[int(pagenumber)] = objectid
        else:
            while True:
                buf = self.mssql.read(self.mssql.pagesize * pagenumber, self.mssql.pagesize)
                if not buf:
                    break

                if buf[0x01] != 0x01:
                    pagenumber += 1
                    continue

                pageheader = self.mssql.getPageHeader(buf)
                self.pages[pagenumber] = pageheader.objectid
                pagenumber += 1

                del buf
            
            json.dump(self.pages, open(jsonFilename, 'w'))

    def getSystemTableColumnInfo(self):
        print('Get System Table Column Information')

        systemTable = [('sysschobjs', 0x22), ('sysiscols', 0x37), ('sysrowsets', 0x05), ('sysallocunits', 0x07)]

        syscol_page = defaultdict(list, {k: v for k, v in self.pages.items() if v == 0x29})
        for _, t_objectID in systemTable:
            for k, v in syscol_page.items():
                buf = self.mssql.read(k * self.mssql.pagesize, self.mssql.pagesize)
                pageheader = self.mssql.getPageHeader(buf)

                if pageheader.flagbits & 0x100:
                    buf = self._tornbits(buf)
                
                rowoffsetarray = sorted(self.mssql.getRowOffsetArray(buf, pageheader))

                for offset in rowoffsetarray:
                    tboID = unpack('<I', buf[offset + 0x04 : offset + 0x08])[0]

                    if tboID != t_objectID:
                        continue

                    colRecordLen = unpack('<H', buf[offset + 0x33 : offset + 0x35])[0]
                    if colRecordLen <= 0:
                        continue

                    colData = buf[offset : offset + colRecordLen]

                    scInfo = SchemeInfo()
                    scInfo.ismax = False
                    scInfo.tobjectid = t_objectID
                    scInfo.colorder = unpack('<H', colData[0x0A:0x0C])[0]
                    scInfo.xtype = colData[0x0E]
                    scInfo.utype = unpack('<I', colData[0x0F:0x13])[0]
                    scInfo.colsize = unpack('<H', colData[0x13:0x15])[0]
                    if scInfo.colsize >= 0xFFFF:
                        scInfo.colsize = 0x10
                        scInfo.ismax = True
                    scInfo.colname = colData[0x35:].decode('utf-16')
                    scInfo.datatype = self._getTypeName(scInfo.xtype, scInfo.utype)
                    if scInfo.datatype in ['numeric', 'decimal']:
                        scInfo.precisionofnumeric = colData[0x15]
                        scInfo.scaleofnumeric = colData[0x16]
                        scInfo.datatype = scInfo.datatype + '({}, {})'.format(str(scInfo.precisionofnumeric), str(scInfo.scaleofnumeric))
                    elif scInfo.datatype in ['time', 'datetime2', 'datetimeoffset']:
                        scInfo.precisionoftime = colData[0x16]
                        scInfo.datatype = scInfo.datatype + '({})'.format(str(scInfo.precisionoftime))
                    self.systemschemesmap[t_objectID].append(scInfo)
                del buf

    def getTableInfo(self):
        print('Get Table Information')

        sysschobjs_page = defaultdict(list, {k: v for k, v in self.pages.items() if v == 0x22}) # sysschobjs
        sysschobjs_schemes = self.systemschemesmap[0x22] # sysschobjs
        sysschobjs_schemes = sorted(sysschobjs_schemes, key=lambda SchemeInfo: SchemeInfo.colorder)

        rowinfo = RowInfo()

        if len(sysschobjs_schemes) == 0:
            return False
        
        for schema in sysschobjs_schemes:
            self._tableSchemeAnalyzer(schema, rowinfo)

        if len(sysschobjs_schemes) != rowinfo.numoftotalcol:
            return False
        
        for k, v in sysschobjs_page.items():
            buf = self.mssql.read(k * self.mssql.pagesize, self.mssql.pagesize)
            pageheader = self.mssql.getPageHeader(buf)

            if pageheader.flagbits & 0x100:
                buf = self._tornbits(buf)

            rowoffsetarray = sorted(self.mssql.getRowOffsetArray(buf, pageheader))

            recordlen = rowoffsetarray[1:] + [self.mssql.pagesize - len(rowoffsetarray) * 2]
            for offset, length in zip(rowoffsetarray, recordlen):
                tbinfo = TableInfo()

                if self._parseTableInfoRecord(buf[offset:], length - offset, tbinfo, sysschobjs_schemes, rowinfo) == True:
                    self.tablelist.append(tbinfo)
            del buf

        if len(self.tablelist) == 0:
            return False
        else:
            return True
        
    def getColumnInfo(self):
        print('Get Column Information')

        syscolpars_page = defaultdict(list, {k: v for k, v in self.pages.items() if v == 0x29})

        for tableinfo in self.tablelist:
            tobjectid = tableinfo.tobjectid

            for k, v in syscolpars_page.items():
                buf = self.mssql.read(k * self.mssql.pagesize, self.mssql.pagesize)
                pageheader = self.mssql.getPageHeader(buf)

                if pageheader.flagbits & 0x100:
                    buf = self._tornbits(buf)

                rowoffsetarray = sorted(self.mssql.getRowOffsetArray(buf, pageheader))

                for offset in rowoffsetarray:
                    tboId = unpack('<I', buf[offset + 0x04:offset + 0x08])[0]
                    if tboId != tobjectid:
                        continue
                    
                    colRecordLen = unpack('<H', buf[offset + 0x33:offset + 0x35])[0]
                    if colRecordLen <= 0:
                        continue

                    colData = buf[offset:offset + colRecordLen]

                    scinfo = SchemeInfo()
                    scinfo.ismax = False
                    scinfo.tobjectid = tobjectid
                    scinfo.colorder = unpack('<H', colData[0x0A:0x0C])[0]
                    scinfo.xtype = colData[0x0E]
                    scinfo.utype = unpack('<I', colData[0x0F:0x13])[0]
                    scinfo.colsize = unpack('<H', colData[0x13:0x15])[0]
                    if scinfo.colsize >= 0xFFFF:
                        scinfo.colsize = 0x10
                        scinfo.ismax = True
                    scinfo.colname = colData[0x35:].decode('utf-16')
                    scinfo.datatype = self._getTypeName(scinfo.xtype, scinfo.utype)
                    if scinfo.datatype == 'numeric' or scinfo.datatype == 'decimal':
                        scinfo.precisionofnumeric = colData[0x15]
                        scinfo.scaleofnumeric = colData[0x16]
                        scinfo.datatype = scinfo.datatype + '({}, {})'.format(str(scinfo.precisionofnumeric), str(scinfo.scaleofnumeric))
                    elif scinfo.datatype == 'time' or scinfo.datatype == 'datetime2' or scinfo.datatype == 'datetimeoffset':
                        scinfo.precisionoftime = colData[0x16]
                        scinfo.datatype = scinfo.datatype + '({})'.format(str(scinfo.precisionoftime))
                    self.userschemesmap[tobjectid].append(scinfo)
                del buf

    def getKeyColumninfo(self):
        print('Get Key Column Information')

        sysiscols_page = defaultdict(list, {k: v for k, v in self.pages.items() if v == 0x37})
        sysiscols_schemes = self.systemschemesmap[0x37]
        sysiscols_schemes = sorted(sysiscols_schemes, key=lambda SchemeInfo: SchemeInfo.colorder)

        rowinfo = RowInfo()

        if len(sysiscols_schemes) == 0:
            return False
        
        for schema in sysiscols_schemes:
            self._tableSchemeAnalyzer(schema, rowinfo)

        if len(sysiscols_schemes) != rowinfo.numoftotalcol:
            return False
        
        for tableinfo in self.tablelist:
            tobjectid = tableinfo.tobjectid

            for k, v in sysiscols_page.items():
                buf = self.mssql.read(k * self.mssql.pagesize, self.mssql.pagesize)
                pageheader = self.mssql.getPageHeader(buf)

                if pageheader.flagbits & 0x100:
                    buf = self._tornbits(buf)

                rowoffsetarray = sorted(self.mssql.getRowOffsetArray(buf, pageheader))

                recordlen = rowoffsetarray[1:] + [self.mssql.pagesize - len(rowoffsetarray) * 2]
                for offset, length in zip(rowoffsetarray, recordlen):
                    indexcolumnid = 0
                    columnid = 0
                    if self._parseIndexInfoRecord(buf[offset:], length - offset, sysiscols_schemes, rowinfo, tobjectid, indexcolumnid, columnid) == True:
                        if (indexcolumnid != 0) and (columnid != 0) and (indexcolumnid != columnid):
                            self._changeOrdinal(indexcolumnid, columnid, '', tobjectid)

                del buf
        
        return True
    
    def getPageObjectId(self):
        print('Get Page Object Id')

        sysrowsets_page = defaultdict(list, {k: v for k, v in self.pages.items() if v == 0x05})
        sysrowsets_schemes = self.systemschemesmap[0x05]
        sysrowsets_schemes = sorted(sysrowsets_schemes, key=lambda SchemeInfo: SchemeInfo.colorder)

        rowinfo = RowInfo()

        if len(sysrowsets_schemes) == 0:
            return False

        for schema in sysrowsets_schemes:
            self._tableSchemeAnalyzer(schema, rowinfo)

        if len(sysrowsets_schemes) != rowinfo.numoftotalcol:
            return False

        for tableinfo in self.tablelist:
            tobjectid = tableinfo.tobjectid
            isFindId = False

            for k, v in sysrowsets_page.items():
                if isFindId:
                    break

                buf = self.mssql.read(k * self.mssql.pagesize, self.mssql.pagesize)
                pageheader = self.mssql.getPageHeader(buf)

                if pageheader.flagbits & 0x100:
                    buf = self._tornbits(buf)

                rowoffsetarray = sorted(self.mssql.getRowOffsetArray(buf, pageheader))

                recordlen = rowoffsetarray[1:] + [self.mssql.pagesize - len(rowoffsetarray) * 2]
                for offset, length in zip(rowoffsetarray, recordlen):
                    tableinfo.partitionid = self._parseObjectInfoRecord(buf[offset:], length - offset, sysrowsets_schemes, rowinfo, tobjectid)
                    if tableinfo.partitionid != 0:
                        if (self._searchSysallocunits(tableinfo)):
                            isFindId = True
                            break

                del buf
        
        return True

    def _tornbits(self, buf):
        origin = bytearray(buf)
        tornbit = unpack('<I', buf[0x3c:0x40])[0]
        tornbit = tornbit >> 2
        offset = 0x3ff
        while offset < self.mssql.pagesize:
            changeData = tornbit & 0x03
            origin[offset] = origin[offset] & 0xfc
            origin[offset] = origin[offset] | changeData
            tornbit = tornbit >> 2
            offset += 0x200
            
        return bytes(origin)

    def _getTypeName(self, xtype, utype):
        if xtype == 0x7F:
            return 'bigint'
        elif xtype == 0x68:
            return 'bit'
        elif xtype == 0x28:
            return 'date'
        elif xtype == 0x2A:
            return 'datetime2'
        elif xtype == 0x6A:
            return 'decimal'
        elif xtype == 0xF0:
            if utype == 0x80:
                return 'hierarchyid'
            elif utype == 0x81:
                return 'geometry'
            elif utype == 0x82:
                return 'geography'
            else:
                return 'unknown'
        elif xtype == 0x38:
            return 'int'
        elif xtype == 0xEF:
            return 'nchar'
        elif xtype == 0x6C:
            return 'numeric'
        elif xtype == 0x3A:
            return 'smalldatetime'
        elif xtype == 0x7A:
            return 'smallmoney'
        elif xtype == 0xBD:
            return 'timestamp'
        elif xtype == 0x24:
            return 'uniqueidentifier'
        elif xtype == 0xAD:
            return 'binary'
        elif xtype == 0xAF:
            return 'char'
        elif xtype == 0x3D:
            return 'datetime'
        elif xtype == 0x2B:
            return 'datetimeoffset'
        elif xtype == 0x3E:
            return 'float'
        elif xtype == 0x3C:
            return 'money'
        elif xtype == 0x3B:
            return 'real'
        elif xtype == 0x34:
            return 'smallint'
        elif xtype == 0x62:
            return 'sql_variant'
        elif xtype == 0x29:
            return 'time'
        elif xtype == 0x30:
            return 'tinyint'
        elif xtype == 0xF1:
            return 'xml'
        elif xtype == 0xA5:
            return 'varbinary'
        elif xtype == 0x22:
            return 'image'
        elif xtype == 0xE7:
            if utype == 0xE7:
                return 'nvarchar'
            elif utype == 0x100:
                return 'sysname'
            else:
                return 'unknown'
        elif xtype == 0xA7:
            return 'varchar'
        elif xtype == 0x23:
            return 'text'
        elif xtype == 0x63:
            return 'ntext'
        else:
            return 'unknown'
        
    def _tableSchemeAnalyzer(self, schema, rowinfo):
        if schema.datatype == 'bigint' or schema.datatype == 'date' or \
            schema.datatype == 'geography' or schema.datatype == 'geometry' or \
            schema.datatype == 'real' or schema.datatype == 'int' or \
            schema.datatype == 'float' or schema.datatype == 'char' or \
            schema.datatype == 'nchar' or schema.datatype == 'binary' or \
            schema.datatype == 'tinyint' or schema.datatype == 'smallint' or \
            schema.datatype == 'rowversion' or schema.datatype == 'money' or \
            schema.datatype == 'smallmoney' or schema.datatype == 'uniqueidentifier' or \
            schema.datatype.find('numeric') != -1 or schema.datatype.find('decimal') != -1 or \
            schema.datatype.find('time') != -1:
            schema.kindofcol = Columntype.STATIC_COLUMN
            rowinfo.numofstaticcol += 1
            rowinfo.staticlength += schema.colsize
        elif schema.datatype == 'bit':
            schema.kindofcol = Columntype.STATIC_COLUMN
            if rowinfo.numofbitcol % 8 == 0:
                rowinfo.staticlength += 1
            rowinfo.numofstaticcol += 1
            rowinfo.numofbitcol += 1
        elif schema.datatype == 'varchar' or schema.datatype == 'nvarchar' or \
            schema.datatype == 'varbinary' or schema.datatype == 'hierarchyid' or \
            schema.datatype == 'sql_variant' or schema.datatype == 'xml' or \
            schema.datatype == 'sysname':
            schema.kindofcol = Columntype.VARIABLE_COLUMN
            rowinfo.numofvariablecol += 1
            rowinfo.checklastcolumn = True
        elif schema.datatype == 'text' or schema.datatype == 'image' or \
            schema.datatype == 'ntext':
            schema.kindofcol = Columntype.VARIABLE_COLUMN
            rowinfo.numofvariablecol += 1
            rowinfo.checklastcolumn = False
        rowinfo.numoftotalcol = schema.colorder

    def _parseTableInfoRecord(self, buf, recordlen, tableinfo, schemlist, rowinfo):
        lenofnullbitmap = math.ceil(rowinfo.numoftotalcol/8)
        offsetoftotalnumofcol = unpack('<H', buf[0x02 : 0x04])[0]
        totalnumofcol = unpack('<H', buf[offsetoftotalnumofcol:offsetoftotalnumofcol + 0x02])[0]

        if rowinfo.numoftotalcol != totalnumofcol:
            return False

        staticoffset = 1 + 1 + 2 # statusBit A + statusBit B + OffsetOfTotalNumOfCol

        if rowinfo.numofvariablecol != 0:
            variableoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap
            numofvariablecol = unpack('<H', buf[variableoffset : variableoffset + 0x02])[0]
            variableoffset += 2
            variableoffset += (2 * numofvariablecol)
            variablecollenoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap + 2
        
        bitpos = 0
        numberofbitcol = 0

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
                    
                    if columnlength < self.mssql.pagesize:
                        columnbuff = buf[staticoffset : staticoffset + columnlength]
                    else:
                        break
                    staticoffset += columnlength
            elif schema.kindofcol == Columntype.VARIABLE_COLUMN:
                variablecollen = unpack('<H', buf[variablecollenoffset:variablecollenoffset + 0x02])[0]

                if variablecollen > 0x8000:
                    variablecollen -= 0x8000
                columnlength = variablecollen - variableoffset

                variablecollenoffset += 2
                if (variableoffset < self.mssql.pagesize) and (variablecollen < self.mssql.pagesize):
                    if (variableoffset + columnlength <= recordlen) and (columnlength < self.mssql.pagesize):
                        columnbuff = buf[variableoffset:variableoffset + columnlength]
                        variableoffset += columnlength
            
            # add nullbit check

            if schema.colname == 'id':
                tableinfo.tobjectid = unpack('<I', columnbuff[:4])[0]
            elif schema.colname == 'name':
                tableinfo.tablename = columnbuff.decode('utf-16')
            elif schema.colname == 'type':
                tabletype = columnbuff.decode('utf-8')[0]
            elif schema.colname == 'intprop':
                tableinfo.numofcolumns = unpack('<I', columnbuff[:4])[0]

            del columnbuff
        
        if tableinfo.tobjectid != 0 and tableinfo.tablename != '' and tabletype == 'U':
            return True
        else:
            return False
        
    def _changeOrdinal(self, indexcolumnid, columnid, colname, objectid):
        table_schemes = self.userschemesmap[objectid]

        for schema in table_schemes:
            if colname != '':
                if schema.colname == colname:
                    tmpOrdinal = schema.colorder
                    schema.colorder = indexcolumnid
            else:
                if schema.colorder == columnid:
                    tmpOrdinal = columnid
                    schema.colorder = indexcolumnid
        
        for schema in table_schemes:
            if (schema.colorder < tmpOrdinal) and (schema.colData > indexcolumnid):
                schema.colorder += 1

    def _parseIndexInfoRecord(self, buf, recordlen, schemlist, rowinfo, objectid, indexcolumnid, columnid):
        lenofnullbitmap = math.ceil(rowinfo.numoftotalcol/8)
        offsetoftotalnumofcol = unpack('<H', buf[0x02 : 0x04])[0]
        totalnumofcol = unpack('<H', buf[offsetoftotalnumofcol:offsetoftotalnumofcol + 0x02])[0]

        if rowinfo.numoftotalcol != totalnumofcol:
            return False

        staticoffset = 1 + 1 + 2 # statusBit A + statusBit B + OffsetOfTotalNumOfCol

        if rowinfo.numofvariablecol != 0:
            variableoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap
            numofvariablecol = unpack('<H', buf[variableoffset : variableoffset + 0x02])[0]
            variableoffset += 2
            variableoffset += (2 * numofvariablecol)
            variablecollenoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap + 2
        
        bitpos = 0
        numberofbitcol = 0

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
                    
                    if columnlength < self.mssql.pagesize:
                        columnbuff = buf[staticoffset : staticoffset + columnlength]
                    else:
                        break
                    staticoffset += columnlength
            elif schema.kindofcol == Columntype.VARIABLE_COLUMN:
                variablecollen = unpack('<H', buf[variablecollenoffset:variablecollenoffset + 0x02])[0]

                if variablecollen > 0x8000:
                    variablecollen -= 0x8000
                columnlength = variablecollen - variableoffset

                variablecollenoffset += 2
                if (variableoffset < self.mssql.pagesize) and (variablecollen < self.mssql.pagesize):
                    if (variableoffset + columnlength <= recordlen) and (columnlength < self.mssql.pagesize):
                        columnbuff = buf[variableoffset:variableoffset + columnlength]
                        variableoffset += columnlength
            
            # add nullbit check
            if schema.colname == 'idmajor':
                tboId = unpack('<I', columnbuff[:4])[0]
            elif schema.colname == 'status':
                tbStatus = unpack('<I', columnbuff[:4])[0]
            elif schema.colname == 'subid':
                indexcolumnid = unpack('<I', columnbuff[:4])[0]
            elif schema.colname == 'intprop':
                columnid = unpack('<I', columnbuff[:4])[0]

            del columnbuff

        if (tboId != objectid) or ~(tbStatus & 2):
            return False
        else:
            return True

    def _parseObjectInfoRecord(self, buf, recordlen, schemlist, rowinfo, objectid):
        lenofnullbitmap = math.ceil(rowinfo.numoftotalcol/8)
        offsetoftotalnumofcol = unpack('<H', buf[0x02 : 0x04])[0]
        totalnumofcol = unpack('<H', buf[offsetoftotalnumofcol:offsetoftotalnumofcol + 0x02])[0]
        partitionid = 0

        if rowinfo.numoftotalcol != totalnumofcol:
            return False

        staticoffset = 1 + 1 + 2 # statusBit A + statusBit B + OffsetOfTotalNumOfCol

        if rowinfo.numofvariablecol != 0:
            variableoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap
            numofvariablecol = unpack('<H', buf[variableoffset : variableoffset + 0x02])[0]
            variableoffset += 2
            variableoffset += (2 * numofvariablecol)
            variablecollenoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap + 2
        
        bitpos = 0
        numberofbitcol = 0

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
                    
                    if columnlength < self.mssql.pagesize:
                        columnbuff = buf[staticoffset : staticoffset + columnlength]
                    else:
                        break
                    staticoffset += columnlength
            elif schema.kindofcol == Columntype.VARIABLE_COLUMN:
                variablecollen = unpack('<H', buf[variablecollenoffset:variablecollenoffset + 0x02])[0]

                if variablecollen > 0x8000:
                    variablecollen -= 0x8000
                columnlength = variablecollen - variableoffset

                variablecollenoffset += 2
                if (variableoffset < self.mssql.pagesize) and (variablecollen < self.mssql.pagesize):
                    if (variableoffset + columnlength <= recordlen) and (columnlength < self.mssql.pagesize):
                        columnbuff = buf[variableoffset:variableoffset + columnlength]
                        variableoffset += columnlength
            
            # add nullbit check

            if schema.colname == 'rowsetid':
                partitionid = unpack('<Q', columnbuff[:8])[0]
            elif schema.colname == 'idmajor':
                tboId = unpack('<I', columnbuff[:4])[0]

            #del columnbuff
        
        if (partitionid == 0) or (tboId != objectid):
            return 0
        else:
            return partitionid
        
    def _searchSysallocunits(self, tableinfo):
        sysallocunits_page = defaultdict(list, {k: v for k, v in self.pages.items() if v == 0x07})
        sysallocunits_schemes = self.systemschemesmap[0x07]
        sysallocunits_schemes = sorted(sysallocunits_schemes, key=lambda SchemeInfo: SchemeInfo.colorder)

        rowinfo = RowInfo()

        if len(sysallocunits_schemes) == 0:
            return False

        for schema in sysallocunits_schemes:
            self._tableSchemeAnalyzer(schema, rowinfo)

        if len(sysallocunits_schemes) != rowinfo.numoftotalcol:
            return False
        
        for k, v in sysallocunits_page.items():
            buf = self.mssql.read(k * self.mssql.pagesize, self.mssql.pagesize)
            pageheader = self.mssql.getPageHeader(buf)

            if pageheader.flagbits & 0x100:
                buf = self._tornbits(buf)

            rowoffsetarray = sorted(self.mssql.getRowOffsetArray(buf, pageheader))

            recordlen = rowoffsetarray[1:] + [self.mssql.pagesize - len(rowoffsetarray) * 2]
            for offset, length in zip(rowoffsetarray, recordlen):
                allocationid = self._parseAllocUnitInfoRecord(buf[offset:], length - offset, sysallocunits_schemes, rowinfo, tableinfo)
                if allocationid != 0:
                    tableinfo.pobjectid = ((allocationid) - ((allocationid >> 48) << 48)) >> 16

        return True
                

    def _parseAllocUnitInfoRecord(self, buf, recordlen, schemlist, rowinfo, tableinfo):
        lenofnullbitmap = math.ceil(rowinfo.numoftotalcol/8)
        offsetoftotalnumofcol = unpack('<H', buf[0x02 : 0x04])[0]
        if offsetoftotalnumofcol > recordlen:
            return False
        
        totalnumofcol = unpack('<H', buf[offsetoftotalnumofcol:offsetoftotalnumofcol + 0x02])[0]
        allocationid = 0

        if rowinfo.numoftotalcol != totalnumofcol:
            return False

        staticoffset = 1 + 1 + 2 # statusBit A + statusBit B + OffsetOfTotalNumOfCol

        if rowinfo.numofvariablecol != 0:
            variableoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap
            numofvariablecol = unpack('<H', buf[variableoffset : variableoffset + 0x02])[0]
            variableoffset += 2
            variableoffset += (2 * numofvariablecol)
            variablecollenoffset = staticoffset + rowinfo.staticlength + 2 + lenofnullbitmap + 2
        
        bitpos = 0
        numberofbitcol = 0

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
                    
                    if columnlength < self.mssql.pagesize:
                        columnbuff = buf[staticoffset : staticoffset + columnlength]
                    else:
                        break
                    staticoffset += columnlength
            elif schema.kindofcol == Columntype.VARIABLE_COLUMN:
                variablecollen = unpack('<H', buf[variablecollenoffset:variablecollenoffset + 0x02])[0]

                if variablecollen > 0x8000:
                    variablecollen -= 0x8000
                columnlength = variablecollen - variableoffset

                variablecollenoffset += 2
                if (variableoffset < self.mssql.pagesize) and (variablecollen < self.mssql.pagesize):
                    if (variableoffset + columnlength <= recordlen) and (columnlength < self.mssql.pagesize):
                        columnbuff = buf[variableoffset:variableoffset + columnlength]
                        variableoffset += columnlength
            
            # add nullbit check

            if schema.colname == 'ownerid':
                pid = unpack('<Q', columnbuff[:8])[0]
            elif schema.colname == 'type':
                flag = columnbuff[0]
            elif schema.colname == 'auid':
                allocationid = unpack('<Q', columnbuff[:8])[0]

            del columnbuff
        
        if (pid == 0) or (pid != tableinfo.partitionid) or (flag != 0x01):
            return 0
        else:
            return allocationid