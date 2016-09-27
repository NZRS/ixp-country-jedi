#!/usr/bin/env python
import os
import sys
sys.path.append("%s/lib" % ( os.path.dirname(os.path.realpath(__file__) ) ) )
from Atlas import MeasurementFetch,MeasurementPrint,IPInfoCache
import json
import ripe.atlas.sagan
import requests
from progressbar import ProgressBar
from multiprocessing import Pool

ipinfo = {}
ips = set()
ipset_pbar = ProgressBar()
ipset_res = []
ip_info_pbar = ProgressBar()
ip_info_res = []
asns = set()
ipcache = IPInfoCache.IPInfoCache()


def fetch_msm(msm_id):
    unique_ips = set()
    msm_data = MeasurementFetch.fetch(msm_id)
    for data in msm_data:
        tr = ripe.atlas.sagan.TracerouteResult(data)
        for hop in tr.hops:
            for pkt in hop.packets:
                ip = pkt.origin
                if pkt.arrived_late_by: ## these are 'weird' packets ignore ehm (better would be to filter out pkts with 'edst')
                    continue
                if ip is not None:
                    unique_ips.add(ip)

    return unique_ips


def log_ip_set(ip_set):
    ips.union(ip_set)
    ipset_res.append(ip_set)
    ipset_pbar.update(len(ipset_res))


def find_ip_info(ip):
    res = ipcache.findIPInfo(ip)
    res.update({'ip': ip})

    return res


def log_ip_info_res(res):
    ip_info_res.append(res)
    ip_info_pbar.update(len(ip_info_res))
    if 'asn' in res and res['asn'] is not None and res['asn'] != '':
        asns.add(res['asn'])


def get_asnmeta(asn):
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
    with open('measurementset.json', 'r') as infile:
        msms = json.load(infile)
        msm_list = msms['v4'] + msms['v6']
        ipset_pbar.start(max_value=len(msm_list))
        ipset_pool = Pool(processes=4) # Fetch two measurements at a time
        for msm in msm_list:
            ipset_pool.apply_async(fetch_msm, args=(msm['msm_id'],),
                                   callback=log_ip_set)
        ipset_pool.close()
        ipset_pool.join()
        ipset_pbar.finish()

    ips = set()
    for partial_ips in ipset_res:
        ips = ips.union(partial_ips)

    no_ips = len(ips)
    ip_info_pool = Pool(processes=4)
    ip_info_pbar.start(max_value=no_ips)
    print >>sys.stderr, "IP gathering finished, now analysing. IP count: %s" % ( no_ips )
    for ip in list(ips):
        ip_info_pool.apply_async(find_ip_info, args=(ip,),
                                 callback=log_ip_info_res)

    ip_info_pool.close()
    ip_info_pool.join()
    ip_info_pbar.finish()

    # NOTE: As the ipcache is shared among multiple processes, the look ups
    # are not save in their internal cache, but returned as messages to the
    # main process. The list ip_info_res contains all the results, so we feed
    #  those results into the internal cache to save them in the right format
    # Load the internal cache with the results of the lookups
    ipcache.updateCache(ip_info_res)

    # writes this file
    ipcache.toJsonFragments('ips.json-fragments')

# If it's called as a program
if __name__ == "__main__":
    main()
