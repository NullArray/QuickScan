# QuickScan

QuickScan is a simple port scanning utility with some useful supporting features. As such it comes with functionality to query DNS in order to resolve domains and has a built in WHOIS lookup. Conveniently the program saves the results of your scans and assorted operations to an application log in the current working directory for future reference and/or further processing. 

## Usage 

Starting the program from the terminal `python quickscan.py` without arguments, will show you a quick introduction message and some usage information. The full set of options available to you are as follows.

```
usage: quickscan.py [-h] [-r RESOLVE] [-w WHOIS] [-s SCAN] [-v]

optional arguments:
  -h, --help                show this help message and exit
  -r RESOLVE, --resolve     enter a domain to resolve
  -w WHOIS, --whois WHOIS   query WHOIS on target host
  -s SCAN, --scan SCAN      specify the host(IP) you wish to perform a port scan on
  -v, --verbose             toggle verbosity
```

For clarity please see some examples below.

```
quickscan.py --help
quickscan.py --resolve google.com 
quickscan.py --scan 192.168.55.88 -v 
```

## Dependencies

QuickScan depends on the following Python2.7 modules.

```
blessings
ipwhois
```
Should you find you do not have these installed you can use Python's build in package manager to install them like so.

```
pip install blessings
pip install ipwhois
```
Or feel free to use the requirements file i have made for this program like so `pip install -r requirements.txt`.
