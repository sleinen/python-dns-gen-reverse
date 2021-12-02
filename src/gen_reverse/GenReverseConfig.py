import yaml


class GenReverseConfig:

    def __init__(self, args):
        self.in_zones = args.in_zones
        self.out_zones = args.out_zones
        self.directory = args.directory
        self.verbose = args.verbose
        self.skip_pipes = args.skip_pipes

        if args.config is not None:
            with open(args.config) as args.config:
                from_yaml = yaml.load(args.config, Loader=yaml.Loader)
                if 'in_zones' in from_yaml:
                    self.in_zones = from_yaml['in_zones']
                if 'out_zones' in from_yaml:
                    self.out_zones = from_yaml['out_zones']
                if 'directory' in from_yaml:
                    self.directory = from_yaml['directory']
                if 'verbose' in from_yaml:
                    self.verbose = from_yaml['verbose']
                if 'skip_pipes' in from_yaml:
                    self.skip_pipes = from_yaml['skip_pipes']
