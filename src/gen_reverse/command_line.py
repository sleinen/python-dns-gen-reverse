#!/usr/bin/python3

import argparse
import yaml
import os

from gen_reverse.AddressCollector import AddressCollector
from gen_reverse.GenReverseConfig import GenReverseConfig


def relative_name(name, origin):
    if (name.endswith(origin)):
        return name[:-(len(origin)+1)]
    return name+'.'


def main():
    parser = argparse.ArgumentParser(description='Generate reverse records.')
    parser.add_argument('--directory', type=str, default='/etc/bind/zones',
                        help='Directory under which zone files are stored')
    parser.add_argument('--in-zones', type=str, nargs='*',
                        help='Zone files or other sources of information')
    parser.add_argument('--out-zones', type=str, nargs='*',
                        help='Zone files or other sources of information')
    parser.add_argument('--config', '-c', type=str,
                        help='YAML configuration file')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='verbose mode')
    parser.add_argument('--skip-pipes', action='store_true',
                        help='skip pipe sources')

    args = parser.parse_args()

    config = GenReverseConfig(args)

    ac = AddressCollector(out_zones=config.out_zones,
                          directory=config.directory,
                          verbose=config.verbose,
                          skip_pipes=config.skip_pipes)
    for in_zone in config.in_zones:
        ac.parse_zone(in_zone)

    for out_zone in ac.out_zones:
        print('zone {}: collected {} addresses'.format(
            out_zone['origin'],
            len(out_zone['addr_to_hostname_ttl_prio'].keys())))
        with open(os.path.join(args.directory,
                               out_zone['file']+'.new'), 'w') as of:
            for addr in sorted(out_zone['addr_to_hostname_ttl_prio'].keys()):
                ents = out_zone['addr_to_hostname_ttl_prio'][addr]
                maxprio = max(ents, key=lambda ent: ent['priority'])['priority']
                maxents = [ent for ent in ents if ent['priority'] == maxprio]
                if maxprio >= 0:
                    if len(list(maxents)) != 1:
                        print('  {} entries for {} with high priority {}'.format(
                            len(list(maxents)), addr, maxprio))
                    ent = maxents[0]
                    of.write('{}\t{}\tPTR\t{}\n'.format(
                        relative_name(addr.reverse_pointer, out_zone['origin']),
                        '' if ent['ttl'] is None else ent['ttl'],
                        relative_name(ent['name'], out_zone['origin'])))

    print('{}'.format(ac))


if __name__ == '__main__':
    main()
