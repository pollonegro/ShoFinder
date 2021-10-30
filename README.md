# ShoFinder
Bulk scanning of Hosts and IPs using the Shodan API

![](https://github.com/pollonegro/ShoFinder/blob/master/img/ShoFinderImg.png)

This script allows us to search in Shodan for a single host, a domain, a range or to pass a txt file with ips, hosts and ranges for batch processes, it has options available as silent mode, customization of own API and export of results to Excel file.

NOTICE: IT IS NECESSARY TO SET THE KEY API IN THE CODE OR USE THE PARAMETER ONCE


Install:

    git clone https://github.com/pollonegro/ShoFinder.git

    pip3 install -r requirements.txt


--------------------------------------------------------------------------------------

usage: python3 ShoFinder.py [-h] [-t TARGET] [-f FILE] [-s] [-a API] [-ex EXPORTXLS] 
Version: 1.4 - This script intend to obtain information with Shodan 
optional arguments: 

    -h, --help              show this help message and exit 
  
    -t TARGET, --target TARGET 
                            Indicate ip/domain/range to process 
                        
    -f FILE, --file FILE    Indicate ip list file to process 
  
    -s, --silent            Dont show nothing in screen 
  
    -a API, --api API       Set a custom Shodan API key - NEEDED ONCE FOR SET!!!
  
    -ex EXPORTXLS, --exportXLS EXPORTXLSX 
                            Export the results to a XLSX file 

    Ej:
    python3 ShoFinder.py -t 172.217.17.14
    python3 ShoFinder.py -t google.com
    python3 ShoFinder.py -t 172.217.17.0/24
    python3 ShoFinder.py -f ip.txt -a 1a2b3c4d5e6f7g8h9i10j11k12l13m14 -ex archivoExcel -s
