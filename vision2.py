import os
import argparse
from util import utils

def arguments():
    parser = argparse.ArgumentParser(description = utils.banner())
    parser.add_argument('-f', '--nmap-file', action = 'store', dest = 'nmapfile',required = True, help = 'Nmap XML file')
    parser.add_argument('-l', '--limit', action = 'store', dest = 'limit', default='1', required = False, help = 'Limit CVEs per CPE to get')
    parser.add_argument('-o', '--output', action = 'store', dest = 'output',default='txt',required = False, help = 'Type of output xml or txt default is txt')
    args = parser.parse_args()
    if args.nmapfile:
        if os.path.isfile(args.nmapfile):
            return os.path.abspath(args.nmapfile),args.limit,args.output
        else:
            print 'File does not exist!'
            exit(1)
    else:
        parser.print_help()

nmapfile,limit,output = arguments()
utils.parser(nmapfile,int(limit))
