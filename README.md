# Microsoft SQL Server Transaction log Parser
Parsing Module of Microsoft SQL Server (MSSQL) Transaction log 

## Main features
- Parse Microsoft SQL Server Transaction log file (.ldf)
- Identify transaction log record from unallocated area (raw data)
- Reconstruct queries with database data file (.mdf)

## Usage
python main.py -d [datafile(.mdf)] -l [logfile|unallocated] -m [mode]
Options:
-   -d, --data [datafile] input MSSQL database data file (.mdf)
-   -l, --log [logfile|unallocated] input MSSQL transaction log file (.ldf) or unallocated area data
-   -m, --mode [mode]

Mode:
-   0: Only transaction log file (.ldf)
-   1: Transaction log file with data file (.mdf)
-   2: Only unallocated area data
-   3: Unallocated area data with data file (.mdf)
