import yaml


class GenReverseConfig:

    def __init__(self, config_file=None):
        if config_file is not None:
            with open(config_file) as config_file:
                from_yaml = yaml.load(config_file, Loader=yaml.Loader)
                self.in_zones = from_yaml['in_zones']
                self.out_zones = from_yaml['out_zones']
