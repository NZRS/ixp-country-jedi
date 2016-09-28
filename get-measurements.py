#!/usr/bin/env python
import os
import sys
sys.path.append("%s/lib" % ( os.path.dirname(os.path.realpath(__file__) ) ) )
from Atlas import MeasurementInfo
from Atlas import MeasurementFetch
from Atlas import MeasurementPrint
from Atlas import MeasurementEnhance
from Atlas import ProbeInfo
import json
import ripe.atlas.sagan
from radix import Radix

### static definitions
MAX_PARALLEL_PROCESSES=10
RESULTDIR='./results'
###


def check_if_via_ixp(tr, ixp_radix):
    ips = set()
    ip2minhop = {}
    ixps = []
    for h in tr.ip_path:
        for ip in h:
            if isinstance(ip, str):
                ips.add(ip)
                if ip not in ip2minhop:
                    ip2minhop[ip] = h.index
                elif ip2minhop[ip] > h.index:
                    ip2minhop[ip] = h.index
    # ips lowest to highest hop (so lan that was encountered first is listed
    #  first)
    sorted_ips = sorted(ips, key=lambda x: ip2minhop[x])
    last = None
    for ip in sorted_ips:
        rnode = ixp_radix.search_best(ip)
        if rnode is not None:
            ixp = rnode.data['name']
            if last is None or last != ixp:
                ixps.append(ixp)
                last = ixp
    return ixps


def create_ixp_radix(basedata):
    ixp_radix = Radix()
    for ixp_name, ixp_entry in basedata['ixps'].iteritems():
        for prefix in ixp_entry['peeringlans']:
            node = ixp_radix.add(prefix)
            node.data['name'] = ixp_name
    return ixp_radix


def check_if_is_in_country(countries, locs):
    for loc in locs:
        if loc is not None:
            cc_in_loc = loc.rsplit(',', 1)[1]
            if cc_in_loc not in countries:
                return False
    return True


def get_destination_rtts(tr):
    rtts = []
    for hop in tr.hops:
        for packet in hop.packets:
            if packet.origin and tr.destination_address == packet.origin:
                if isinstance(packet.rtt, float):
                    rtts.append(packet.rtt)
    return rtts


def filter_cruft(data):
    # removes garbage that is known to be bugs in ripe atlas traceroutes
    # https://atlas.ripe.net/docs/bugs/ (find 'edst')
    if 'result' in data:
        res = data['result']
        for hop_idx, hop in enumerate(res):
            if 'result' in hop:
                hop['result'] = [hr for hr in hop['result'] if 'edst' not in hr]

    return data


def process_msm(msm_spec, protocol, probes_by_id={}, basedata={},
                probes_by_ip={}, ixp_radix=None):
    # msm_spec has msm_id
    msm_id = msm_spec['msm_id']
    print >>sys.stderr, "starting processing of %s" % msm_id
    # exit if .msm.%s file already exists
    outfilename = "%s/msm.%s.json" % (RESULTDIR, msm_id)
    if os.path.exists(outfilename):
        print >>sys.stderr, "file already exists %s" % outfilename
        return
    outdata = []
    for data in MeasurementFetch.fetch(msm_id):
        data = filter_cruft(data)
        assert 'edst' not in repr(data), data
        tr = ripe.atlas.sagan.TracerouteResult(data)
        tracetxt = MeasurementPrint.trace2txt(data)
        src_prb_id = data['prb_id']
        src_prb = probes_by_id[src_prb_id]
        dst_prb_id = None
        dst_prb = None
        try:
            dst_prb_id = probes_by_ip[data['dst_addr']]
            dst_prb = probes_by_id[dst_prb_id]
        except:
            pass
        if src_prb_id == dst_prb_id:
            # probe to itself is not interesting/useful
            # TODO filter this out in the measurement creation
            continue
        ixps = check_if_via_ixp(tr, ixp_radix)
        via_ixp = False
        if len(ixps) > 0:
            via_ixp = True
        locs = MeasurementPrint.trace2locs(data)
        as_links = MeasurementEnhance.aslinksplus(data, ixp_radix)
        geojson = MeasurementEnhance.togeojson(data, src_prb, dst_prb)
        # print as_links
        countries = basedata['countries']
        is_in_country = check_if_is_in_country(countries, locs)
        # print "INCOUNTRY: %s" % (is_in_country)
        dst_rtts = get_destination_rtts(tr)
        outdata.append({
            'ts': data['timestamp'],
            'result': data['result'],
            'protocol': protocol,
            'msm_id': msm_id,
            'as_links': as_links,
            'src_prb_id': src_prb_id,
            'dst_prb_id': dst_prb_id,
            'dst_rtts': dst_rtts,
            'geojson': geojson,
            'in_country': is_in_country,
            'via_ixp': via_ixp,
            'ixps': ixps,
            'tracetxt': tracetxt,
            'locations': list(locs)
        })

    with open(outfilename, 'w') as outfile:
        json.dump(outdata, outfile, indent=2)


def main():
    msms = {}
    with open('measurementset.json', 'r') as infile:
        msms = json.load(infile)
    probes = {}
    with open('probeset.json', 'r') as infile:
        probes = json.load(infile)
    probes_by_ip = {}
    probes_by_id = {}
    for p in probes:
        probes_by_id[p['probe_id']] = p
        if 'address_v4' in p and p['address_v4'] is not None:
            probes_by_ip[p['address_v4']] = p['probe_id']
        if 'address_v6' in p and p['address_v6'] is not None:
            probes_by_ip[p['address_v6']] = p['probe_id']
    # NOTE: there are IPs with multiple probes behind them, this just picks one.
    # all auxilliary data should come from 'basedata' prepare-step should
    # put it there this is so we can fill out the blanks in prepare-stage
    basedata = {}
    with open('basedata.json', 'r') as infile:
        basedata = json.load (infile)
    ixp_radix = create_ixp_radix(basedata)
    MeasurementPrint.IPInfoCacheFromFile('ips.json-fragments')
    MeasurementPrint.setCacheOnly(True)
    MeasurementEnhance.IPInfoCacheFromFile('ips.json-fragments')
    MeasurementEnhance.setCacheOnly(True)
    if not os.path.exists(RESULTDIR):
        os.makedirs(RESULTDIR)
    # loop over measurements
    for m in msms['v4']:
        process_msm(m, 4, probes_by_id, basedata, probes_by_ip, ixp_radix)
    for m in msms['v6']:
        process_msm(m, 6, probes_by_id, basedata, probes_by_ip, ixp_radix)

if __name__ == '__main__':
    main()
