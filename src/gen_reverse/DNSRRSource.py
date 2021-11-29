import re
import os
import pipes


import gen_reverse.ZoneFileSyntaxError


class DNSRRSource:
    def __init__(self, origin, priority=0, verbose=False):
        self.origin = origin
        self.verbose = verbose
        self.priority = priority
        self.RE_RR = re.compile(r'''
            ^(\S+)?
            (?:\s+([0-9]+[a-zA-Z]?))?
            (?:\s+(IN|HS))?
            \s+(A|AAAA|APL|CNAME|PTR|LOC|MX|TXT|SOA|SRV|SSHFP|NS|CAA|TLSA|DS|HTTPS|NAPTR|SPF)
            \s+([^;]*\S)
            (?:\s+;\s*(.*))?
            $
        ''', re.VERBOSE | re.IGNORECASE)
        self.RE_DIR = re.compile(r'''
            ^\s*\$(INCLUDE|ORIGIN|TTL|GENERATE)\s+(\S.*\S)\s*$
        ''', re.VERBOSE | re.IGNORECASE)
        self.RE_COMMENTONLY = re.compile(r'^\s*(?:;.*)?$')
        self.RE_LOWPRIO = re.compile(r'''
            (?:secondary\ (?:A|AAAA)\ RR|
            shutdown|
            duplicated\ entry,\ loopback\ missing)
        ''', re.VERBOSE | re.IGNORECASE)

    def __str__(self):
        return '{} from {}'.format(type(self), self.source)

    def map_lines_open_file(self, file, fn):
        self.lineno = 0
        for line in file:
            fn(self, line)
            self.lineno += 1
        return self.lineno

    def allow_includes(self): return False

    def parse_zone(self, fn):

        self.name = None
        self.qclass = None
        self.qtype = None
        self.include_count = 0
        self.ttl = None
        self.default_ttl = None

        def process_directive(line, cmd, arg):
            if cmd == 'INCLUDE':
                if self.allow_includes():
                    included_file = arg
                    if re.match(r'.*/dnssec/.*', included_file):
                        if self.verbose:
                            print('  skipping dnssec include file {}'.format(
                                included_file))
                    else:
                        included_source = DNSIncludedZoneFileSource(
                            origin=self.origin,
                            parent=self,
                            file=included_file,
                            directory=self.directory)
                        self.include_count += included_source.parse_zone(fn)
            elif cmd == 'ORIGIN':
                new_origin = arg
                if new_origin.endswith('.'):
                    self.origin = new_origin[:-1]
                else:
                    self.origin = new_origin + '.' + self.origin
            elif cmd == 'TTL':
                self.default_ttl = arg
            elif cmd == 'GENERATE':
                pass

        def process_line(self, line):
            if re.match(self.RE_COMMENTONLY, line):
                pass
            else:
                if line.startswith('$'):
                    m = re.match(self.RE_DIR, line)
                    if m:
                        cmd = m.group(1)
                        arg = m.group(2)
                        process_directive(line, cmd, arg)
                    else:
                        raise ZoneFileSyntaxError('Unknown directive'.format(
                            line),
                                                  source=self)
                else:
                    m = re.match(self.RE_RR, line)
                    if m:
                        priority = self.priority
                        if m.group(1):
                            name = m.group(1)
                            if name == '@':
                                self.name = self.origin
                            elif name.endswith('.'):
                                self.name = name[:-1]
                            else:
                                self.name = name + '.' + self.origin
                        else:
                            pass
                        if m.group(2):
                            self.ttl = m.group(2)
                        if m.group(3):
                            self.qclass = m.group(3)
                        self.qtype = m.group(4)
                        value = m.group(5)
                        if m.group(6):
                            comment = m.group(6)
                            if re.match(self.RE_LOWPRIO,
                                        comment):
                                priority = priority - 10
                            else:
                                if self.verbose:
                                    print('  COMMENT: {}'.format(comment))
                        if self.verbose:
                            print('  {} {} {} {} value {} priority {}'.format(
                                self.name,
                                '' if self.ttl is None else self.ttl,
                                self.qclass, self.qtype, value, priority))
                        fn(self, self.name,
                           self.ttl, self.qclass, self.qtype,
                           value, priority)
                    else:
                        if self.verbose:
                            print(' no match {}'.format(line))

        counter = self.map_lines(process_line)
        if self.verbose:
            print('source {}: {} lines'.format(
                self.source, counter))
        return counter


class DNSZoneFileSource(DNSRRSource):
    def __init__(self, file=None, directory=None, *args, **kwargs):
        super(DNSZoneFileSource, self).__init__(*args, **kwargs)
        self.file = file
        self.directory = directory
        self.source = 'zone file ' + file

    def allow_includes(self): return True

    def map_lines(self, fn):

        with open(os.path.join(self.directory, self.file)) as file:
            return self.map_lines_open_file(file, fn)


class DNSIncludedZoneFileSource(DNSZoneFileSource):
    def __init__(self, file, parent=None, *args, **kwargs):
        super(DNSIncludedZoneFileSource, self).__init__(
            file=file, *args, **kwargs)
        self.parent = parent
        self.source = 'zone file {} included from {}'.format(
            file, parent.source)


class DNSDigPipeSource(DNSRRSource):
    def __init__(self, cmd, skip_pipes=False, *args, **kwargs):
        super(DNSDigPipeSource, self).__init__(*args, **kwargs)
        self.cmd = cmd
        self.source = 'dig pipe: ' + cmd
        self.skip_pipes = skip_pipes

    def map_lines(self, fn):
        if not self.skip_pipes:
            t = pipes.Template()
            t.prepend('dig ' + self.cmd, '.-')
            with t.open('foo', 'r') as file:
                return self.map_lines_open_file(file, fn)
