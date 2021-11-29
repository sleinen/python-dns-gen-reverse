import ipaddress
import re


import gen_reverse.ZoneFileSyntaxError
from gen_reverse.DNSRRSource import DNSZoneFileSource, DNSDigPipeSource


def inverse_name_to_prefix(name):
    name = name.lower()
    if name.endswith('.in-addr.arpa'):
        tokens = list(reversed(name[:-len('.in-addr.arpa')].split('.')))
        preflen = len(tokens) * 8
        tokens.extend(['0'] * (4-len(tokens)))
        return ipaddress.ip_network('.'.join(tokens) + '/' + str(preflen))
    elif name.endswith('.ip6.arpa'):
        tokens = list(reversed(name[:-len('.ip6.arpa')].split('.')))
        preflen = len(tokens)*4
        tokens.extend(['0'] * (32 - len(tokens)))
        nyb = ''.join(tokens)
        nyb = ':'.join([nyb[i:i+4] for i in range(0, 32, 4)])
        return ipaddress.ip_network(nyb + '/' + str(preflen))
    else:
        raise Exception("Incomprehensible inverse name {}".format(
            name))

def absolute_name(namespec, origin):
    if (namespec == '@'):
        return origin
    elif (namespec.endswith('.')):
        return namespec[:-1]
    return namespec+'.'+origin


class AddressCollector:
    def __init__(self, directory=None, verbose=False, out_zones=[],
                 skip_pipes=False):
        self.verbose = verbose
        self.directory = directory
        self.skip_pipes = skip_pipes
        self.out_zones = out_zones
        self.prefix_to_zone = dict()
        for out_zone in out_zones:
            origin = out_zone['origin']
            out_zone['addr_to_hostname_ttl_prio'] = dict()
            prefix = inverse_name_to_prefix(origin)
            self.prefix_to_zone[prefix] = out_zone

    def find_closest_zone_for_address(self, addr):
        bestpref = -1
        best_zone = None
        for prefix in self.prefix_to_zone.keys():
            # print('  trying prefix {}'.format(prefix))
            if prefix.prefixlen > bestpref and addr in prefix:
                best_zone = self.prefix_to_zone[prefix]
                bestpref = prefix.prefixlen
        return best_zone

    def note_record(self, name, ttl, cl, typ, value, priority):
        if typ == 'A' or typ == 'AAAA' or typ == 'PTR':
            addr = ipaddress.ip_address(value)
            zone = self.find_closest_zone_for_address(addr)
            if zone is None:
                if self.verbose:
                    print('  no zone found for {} ({})'.format(
                        addr, name))
            else:
                tbl = zone['addr_to_hostname_ttl_prio']
                new = {
                    'name': name,
                    'ttl': ttl,
                    'priority': priority
                }
                if addr in tbl:
                    tbl[addr].append(new)
                else:
                    tbl[addr] = [new]
            if self.verbose:
                print('found {} record {} -> {} (TTL {} priority {})'.format(
                    typ, name, addr, ttl, priority))

    def parse_zone(self, in_zone):

        def collect_record(source, name, ttl, cl, typ, value, priority):
            if cl is None or cl == 'IN':
                if typ == 'A' or typ == 'AAAA':
                    self.note_record(name, ttl, cl, typ, value, priority)
                elif typ == 'PTR' and re.match(r'\d+\.\d+\.\d+\.\d+\.', value):
                    # Note these with slightly lower priority
                    self.note_record(name,
                                     ttl, cl, typ,
                                     absolute_name(value, source.origin),
                                     priority)
            else:
                raise ZoneFileSyntaxError('unknown class {}'.format(
                    cl),
                                          source=source)
        assert (in_zone is not None)
        assert ('origin' in in_zone)
        source = None
        if 'file' in in_zone:
            source = DNSZoneFileSource(origin=in_zone['origin'],
                                       file=in_zone['file'],
                                       directory=self.directory,
                                       verbose=self.verbose)
        elif 'dig' in in_zone:
            source = DNSDigPipeSource(origin=in_zone['origin'],
                                      cmd=in_zone['dig'],
                                      skip_pipes=self.skip_pipes,
                                      verbose=self.verbose)
        else:
            raise SyntaxError()
        source.parse_zone(collect_record)
