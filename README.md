BETA LDAP-Scan - for identifying LDAP devices
========

Python-based LDAP scanner -- Scans a bunch of device to try to figure out LDAP/LDAPS devices.


Lesson Learned
===

Example:

```bash
root@docker# ./ldapscanner.py -ip 192.168.10.5
attempting to scan 192.168.10.5
root@docker#
```

```
root@docker# ./ldapscanner.py -ip 192.168.10.5
attempting to scan 192.168.10.5
```

If you use the "-results_file" flag, you should get a nice parseable output:  (This does not work yet.)

The file should look like the following:

Dependencies:
=============

python-ldap

Usage:
======

```bash
./ldapscanner.py -h
```

LDAP Checker
  
Example
===

```bash
./ldapscanner.py -ip 192.168.10.5 -port 1104

./ldapscanner.py -netrange 192.168.10.0/24 -port 1104 -results_file results.txt
```

Bugs
====

- LDAP server down messages may make the scanner stop if scanning a range.  Need to fix this.

TODO
===

- suppress LDAP Server Down messages
- add printing to a file
- add banner grabbing
- add the ability to input actual LDAP information

If you find other bugs that I haven't mentioned, please report them to gmail (rlastinger) or create a ticket, and I will get to it when I can.  

Help or improvement suggestions are also welcome.  Just email me at gmail (rlastinger).
Enjoy.
