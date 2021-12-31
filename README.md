# vt_upload
A python tool to scan files at virustotal.com.
Сonnection is made using the key received during registration on the VT.  

Installing dependencies:
```
pip install vt-py colorama
```

### Principle of operation:
---

* creates a copy of the file from the source directory;
* puts the created copy into a temporary directory ("-buf" key);
* changes the file name to anonymized (like "test.exe");
* sends a hash of the file to check for previous results;
* if the previous result is absent or older than the specified number of days ("-d" key) uploads the file;
* displays the received information and writes it to the log.

---

Help:
```
usage: vt_ez.py [-h] [-names] [-src path/to/source] [-key path/to/key.txt] [-log path/to/log.txt]
                [-buf path/to/tmp/dir] [-t target_AV] [-e .ext] [-d int]

optional arguments:
  -h, --help            show this help message and exit.
  -names                print all target AV names and exit.
  -src path/to/source   path to source file or directory.
  -key path/to/key.txt  path to key file. "*script_dir/key.txt" is default.
  -log path/to/log.txt  path to log file. "*script_dir/vt_logs/log*.txt" is default.
  -buf path/to/tmp/dir  path to tmp dir. "*source/file/dir" is default.
  -t target_AV          highlight selected AV names. Multiple "-t" supported.
  -e .ext               file extension to process. Omit for all, multiple "-e" supported.
  -d int                days allowed since last scan to not upload. 3 is default.
```

---
