import sys
import argparse

from datafile import Datafile, DatafileParser
from logfile import Logfile, LogfileParser, CarvingProcess


def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--data", dest="datafile", action="store")
    parser.add_argument("-l", "--log", dest="logfile", action="store")
    parser.add_argument("-m", "--mode", dest="mode", action="store") 
    # 0b00 = only LDF, 0b01 = LDF with MDF, 0b10 = only unallocated area, 0b11 = unallocated area with MDF
    args = parser.parse_args()
    mode = int(args.mode)
    
    if mode & 1:
        df = Datafile()
        df.open(args.datafile)
        dp = DatafileParser(df)
        dp.scanPages(args.datafile)
        dp.getSystemTableColumnInfo()
        if dp.getTableInfo() != True:
            sys.exit()
        dp.getColumnInfo()
        dp.getKeyColumninfo()
        dp.getPageObjectId() # Extract table information
        if mode & 2:
            cp = CarvingProcess(args.logfile, 4096)
            cp.open()
            cp.process()
            cp.recovery(dp)
        else:
            lf = Logfile()
            lf.open(args.logfile)
            lp = LogfileParser(lf, dp)
            lp.scanVLFs()
            lp.scanLogSegment()
            lp.parseVLF()
            lp.recovery()
    else:
        if mode & 2:
            cp = CarvingProcess(args.logfile, 4096)
            cp.open()
            cp.process()
        else:
            lf = Logfile()
            lf.open(args.logfile)
            lp = LogfileParser(lf)
            lp.scanVLFs()
            lp.scanLogSegment()
            lp.parseVLF()
    print('Complete')


if __name__ == "__main__":
    main()
