#!/usr/bin/env python
import os
import sys
sys.path.append("%s/lib" % ( os.path.dirname(os.path.realpath(__file__) ) ) )
from Atlas import MeasurementFetch,MeasurementPrint,IPInfoCache
import json
import ripe.atlas.sagan
import requests
import ipaddress
import re
#import random

ipinfo = {}


def get_asnmeta( asn ):
    meta = {'asn': asn,
            'as_name': '<unknown>',
            'as_description': '<unknown>',
            'as_country': 'XX',
            'ips_v4': None,
            '48s_v6': None}
    ### find long name and asn-size
    ## call https://stat.ripe.net/data/as-overview/data.json?resource=%s
    ## and https://stat.ripe.net/data/routing-status/data.json?resource=%s
    payload = {'resource': "AS%s" % asn}
    name_url = "https://stat.ripe.net/data/as-overview/data.json"
    size_url = "https://stat.ripe.net/data/routing-status/data.json"

    nreq = requests.get(name_url, params=payload)

    try:
        ndata = nreq.json()
        holder = ndata['data']['holder']
        name_desc,cc = holder.rsplit(",",1)
        nd_list = name_desc.split(" ",1)
        name = nd_list[0]
        desc = None
        if len(nd_list) == 1:
            desc = nd_list[0]
        else:
            desc = nd_list[1]
        meta['as_name'] = name
        meta['as_description'] = desc
        meta['as_country'] = cc
    except:
         print "asn name extraction failed for %s (%s)" % ( asn, ndata )

    nreq = requests.get(size_url, params=payload)
    try:
        sdata = nreq.json()
        meta['ips_v4'] = sdata['data']['announced_space']['v4']['ips']
        meta['48s_v6'] = sdata['data']['announced_space']['v6']['48s']
    except:
        print "asn size extraction failed for %s (%s)" % ( asn, sdata )

    return meta


def main():
    ips = set()
    with open('measurementset.json', 'r') as infile:
        msms = json.load(infile)
        msm_list = msms['v4'] + msms['v6']
        msm_idx = 0
        while msm_idx < len(msm_list):
            m = msm_list[msm_idx]
            print >>sys.stderr, "(%d/%d) msm gathering, now fetching %s" % (
                msm_idx+1, len(msm_list), m)
            try:
                msm_data = MeasurementFetch.fetch(m['msm_id'])
                for data in msm_data:
                    tr = ripe.atlas.sagan.TracerouteResult(data)
                    for hop in tr.hops:
                        for pkt in hop.packets:
                            ip = pkt.origin
                            if pkt.arrived_late_by: ## these are 'weird' packets ignore ehm (better would be to filter out pkts with 'edst')
                                continue
                            if ip is not None:
                                ips.add( ip )
                msm_idx += 1
            except:
                print "Error fetching msm %d, will retry" % m['msm_id']

    no_ips = len(ips)
    print >>sys.stderr, "IP gathering finished, now analysing. IP count: %s" % ( no_ips )
    ipcache = IPInfoCache.IPInfoCache()
    counter = 1
    ips = list(ips)
    ips.sort()
    asns = set()
    for ip in ips:
        res = ipcache.findIPInfo(ip)
        print "(%d/%d) %s / %s" % ( counter, no_ips, ip, res )
        counter += 1
        if 'asn' in res and res['asn'] is not None and res['asn'] != '':
            asns.add( res['asn'] )

    # writes this file
    ipcache.toJsonFragments('ips.json-fragments')

# If it's called as a program
if __name__ == "__main__":
    main()
