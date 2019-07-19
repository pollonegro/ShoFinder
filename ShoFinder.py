# -*- coding: utf-8 -*-
#!/usr/bin/env python
import shodan
import re
import socket
import os, sys
import requests # PUT IN REQUIREMENTS !!!!!!!!
import urllib
import dns.resolver # PUT IN REQUIREMENTS !!!!!!!!
import xlsxwriter
from time import sleep
import argparse
from ipaddress import ip_address
import struct
from functools import reduce
import urllib.request, json 
from termcolor import colored # PUT IN REQUIREMENTS !!!!!!!!
api_key = ''  # <-------- HARCODED API KEY HERE --------<     
hostnames3 = ''
puertosLimpios3 = ''
cveLimpio3 = ''
product = ''
parser = argparse.ArgumentParser(description='Version: 1.4 - This script intend to obtain information with Shodan')
parser.add_argument('-t','--target', help="Indicate ip/domain/range to process \n\n",required=False)
parser.add_argument('-f','--file', help='Indicate ip list file to process\n\n', required=False)
parser.add_argument('-s','--silent', help="Dont show nothing in screen \n\n",required=False, action='store_true')
parser.add_argument('-a','--api', help="Set a custom Shodan API key - NEEDED ONCE FOR SET!!! \n\n",required=False)
parser.add_argument('-ex','--exportXLSX', help='Export results to a XLSX file\n\n', required=False)
args = parser.parse_args()
if args.exportXLSX is not None:
    fileoutXLSX = xlsxwriter.Workbook(args.exportXLSX + '.xlsx')  
    fileout_sheet = fileoutXLSX.add_worksheet()
    bold = fileoutXLSX.add_format({'bold': True})
    fileout_sheet.write(0, 0, 'IP', bold)
    fileout_sheet.write(0, 1, 'ISP', bold)
    fileout_sheet.write(0, 2, 'ASN', bold)
    fileout_sheet.write(0, 3, 'LOCATION', bold)
    fileout_sheet.write(0, 4, 'PORTS', bold)
    fileout_sheet.write(0, 5, 'DETECTED PRODUCTS', bold)
    fileout_sheet.write(0, 6, 'CVEs', bold)  
    fileout_sheet.write(0, 7, 'UPDATED', bold)
    contador = 1
if args.api is not None:
    api_key = args.api
    if not os.path.exists("API.txt"):
        archive_api = open("API.txt","w+")
        archive_api.write(args.api)
        api_key = (archive_api.readline())[0:32]
        print(colored('Shodan API Key stored !!!'), 'yellow')
if api_key == '':
    try:
        if os.path.exists("API.txt"):
            archive_api = open('API.txt', 'r')
            api_key = (archive_api.readline())[0:32]
        else:
            print(colored('Cant found API.txt file, please create "API.txt" with a valid Shodan API Key inside or use -a argument'), 'yellow')
            sys.exit(1)
    except Exception as e:
        pass
api = shodan.Shodan(api_key)  
def formatParams (results):
    global hostnames3
    global puertosLimpios3
    global cveLimpio3

    hostnames1 =  str(results.get('hostnames')).replace("', '", " | ")
    hostnames2 =  hostnames1.replace("['", "")
    hostnames3 =  hostnames2.replace("']", "")
    puertosLimpios =  str(results['ports']).replace("[", "")
    puertosLimpios2 =  str(puertosLimpios).replace("]", "")
    puertosLimpios3 =  str(puertosLimpios2).replace(",", " |")
    cveLimpio =  str(results.get('vulns')).replace("', '", " | ")
    cveLimpio2 =  cveLimpio.replace("['", "")
    cveLimpio3 =  cveLimpio2.replace("']", "")

def process (results):    
    formatParams (results)
    global hostnames3
    global puertosLimpios3
    global cveLimpio3
    global product
    global prodList
    if args.silent is False:
        print(colored(' -------------------------------- ', 'white'))
        print(colored(' IP:           {}'.format(results['ip_str']), 'white'))                       
        print(colored(' Hostnames:    {}'.format(hostnames3), 'green'))
        print(colored(' ISP:          {}'.format(results['isp']), 'green'))
        print(colored(' ASN:          {}'.format(results['asn']), 'green'))    
        
        try:
            location = '{} {} {} {}'.format(
            check(results['country_code3']),
            check(results['country_name']),
            check(results['city']),
            check(results['postal_code'])
            )
            print(colored(' Location:     {}'.format(location), 'green'))
        except Exception as e:
            pass
        
        print(colored(' Ports:        {}'.format(puertosLimpios3), 'white'))
        print(colored(' CVEs:         {}'.format(cveLimpio3), 'red'))
        print(colored(' Updated:      {}'.format(results.get('last_update')[0:10]), 'blue'))
        print(colored(' ---------------- ', 'white'))
        prodList = ''
        first = 0
        for data in results['data']:
            puerto = data['port']
            
            print(colored(' -*- Port:     ' + str(data['port']), 'white'))
            print(colored('     Protocol: ' + str(data['transport']), 'cyan'))
            try:
                if str(data['os']) == "None":
                    data['os'] = "N/A"
                else:
                    print(colored('     OS:       ' + str(data['os']), 'orange'))
            
            except Exception as e:
                continue
            try:
                print(colored('     Product:  ' + str(data['product']), 'red'))
                prod = str(data['product'])
                if not prodList:
                   prodList = prod
                    
                elif prod not in prodList:
                    prodList = prodList + ', ' + prod
            
            except Exception as e:
                data['product'] = "N/A"
                continue
            try:
                print(colored('     Version:  ' + str(data['version']), 'red'))
                prodVer = product + ', ' + str(data['product']) + '(' + str(data['version']) + ')'
                if prodVer not in prodList:
                    prodList = prodList + '' + prodVer
                
            except Exception as e:
                data['version'] = "N/A"
                continue

        if not prodList:
            pass
        else:
            print(colored('\n' + ' Detected products:  {}'.format(prodList), 'yellow'))
    print('\n')

def check(param):
    if param==None:
        return ''
    else:
        return param
def excelWriter (results):
    formatParams (results)
    global hostnames3
    global puertosLimpios3
    global contador
    #global prodList
    global cveLimpio3
    fileout_sheet.write(contador, 0, results['ip_str'])
    fileout_sheet.write(contador, 1, hostnames3)
    if str(results['isp']) == " ":
        fileout_sheet.write(contador, 2, 'N/A')
    else:
        fileout_sheet.write(contador, 2, str(results['isp']))
    location = '{} {} {} {}'.format(
        check(results['country_code3']),
        check(results['country_name']),
        check(results['city']),
        check(results['postal_code'])
    )
    fileout_sheet.write(contador, 3, location)
    fileout_sheet.write(contador, 4, puertosLimpios3)
    fileout_sheet.write(contador, 5, prodList)
    fileout_sheet.write(contador, 6, cveLimpio3)
    fileout_sheet.write(contador, 7, results.get('last_update')[0:10])
    contador += 1
print(colored(' **************************************************** ', 'yellow'))
       
if api_key == '':
    print(colored(' Shodan API key not defined, edit the script or use (-a) option.', 'yellow'))
    sys.exit(1)
else:
    try:
        if args.target is not None: 
            cleanParam = args.target
            if 'http://' in cleanParam:
                cleanParam =  cleanParam.replace("http://", "")
                cleanParam =  socket.gethostbyname(cleanParam)
            if 'https://' in cleanParam:
                args.target =  args.target.replace("https://", "")
                args.target =  socket.gethostbyname(cleanParam)
            
            if 'www.' in cleanParam:
                cleanParam =  cleanParam.replace("www.", "")
                cleanParam =  socket.gethostbyname(cleanParam)
            args.target = cleanParam
            if '/' in args.target:
                with urllib.request.urlopen('https://api.shodan.io/shodan/host/search?key=' + api_key + '&query=net:' + args.target) as url:
                    data = json.loads(url.read().decode())
                    
                    total_ip = data.get('total')
                    print(colored(' Processing range {} - {} IPs found on Shodan'.format(args.target, total_ip), 'yellow'))
                    results = data.get('matches')
                    
                    for info in results:
                        if 'ip_str' in info:
                            ip = info.get('ip_str')
                            try:
                                #ipv4 = socket.gethostbyname(ip)
                                ipv4 = ip
                                results = api.host(ipv4)
                                process(results)
                                sleep(1)
                                if args.exportXLSX is not None:           
                                    excelWriter(results)  
                            except Exception as e:
                                print(colored(' Warning: {} {}'.format(ip, e), 'yellow'))
                                sleep(1)
            else:
                print(colored(' Processing IP / Host: ' + args.target, 'yellow'))
                try:
                    ipv4 = socket.gethostbyname(args.target)
                    results = api.host(ipv4)
                    process(results)
                    if args.exportXLSX is not None:           
                        excelWriter(results)  
                except Exception as e:
                    print(colored(' Warning: {} {}'.format(args.target, e), 'yellow'))
        elif args.file is not None:
            print(colored(' Processing file: ' + str(args.file), 'yellow'))
            with open(args.file, 'r') as file:
                for line in file.readlines():   
                    line_ip = line.split('\n')[0]
                    if 'http://' in line_ip:
                        line_ip =  line_ip.replace("http://", "")
                        line_ip =  socket.gethostbyname(line_ip)
                    if 'https://' in line_ip:
                        line_ip =  line_ip.replace("https://", "")
                        line_ip =  socket.gethostbyname(line_ip)
                    
                    if 'www.' in line_ip:
                        line_ip =  line_ip.replace("www.", "")
                        line_ip =  socket.gethostbyname(line_ip)
                    if '/' in line_ip:
                        with urllib.request.urlopen('https://api.shodan.io/shodan/host/search?key=' + api_key + '&query=net:' + line_ip) as url:
                            data = json.loads(url.read().decode())
                            
                            total_ip = data.get('total')
                            print(colored(' Processing range {} - {} IPs found on Shodan'.format(line_ip, total_ip), 'yellow'))
                            results = data.get('matches')
                            
                            for info in results:
                                if 'ip_str' in info:
                                    ip = info.get('ip_str')
                                    try:
                                        ipv4 = socket.gethostbyname(ip)
                                        results = api.host(ipv4)
                                        process(results)
                                        sleep(1)
                                        if args.exportXLSX is not None:           
                                            excelWriter(results)  
                                    except Exception as e:
                                        print(colored('Warning: {} - {}'.format(ipv4, e), 'yellow'))
                                        sleep(1)
                            print(colored(' Range processed, continuing... ', 'yellow'))
                    else:
                        
                        try:
                            ipv4 = socket.gethostbyname(line_ip)
                            results = api.host(ipv4)
                            process(results)
                            sleep(1)
                            if args.exportXLSX is not None:
                                excelWriter(results)
                        except Exception as e:
                            print(colored(' Warning: {} {}'.format(ipv4, e), 'yellow'))
                            sleep(1)               
                                    
        else:
            print(colored(' Warning: Need indicate ip/domain/range or file to process, use -h for help', 'yellow'))
            sys.exit(1)
        if args.exportXLSX is not None: 
            print(colored(' --- Excel file ' + str(args.exportXLSX) + ' has been generated ---' + '\n', 'yellow'))
        print(colored(' --- The execution has been completed --- ', 'yellow'))
    except Exception as e:
        print(colored(' Fatal Error: {}'.format(e), 'yellow'))
        sys.exit(1)
    finally:
        if args.exportXLSX is not None:
            fileoutXLSX.close()