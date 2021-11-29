class ZoneFileSyntaxError(Exception):
    def __init__(self, error, source=None):
        super(ZoneFileSyntaxError, self).__init__(error)
        self.error = error
        self.source = source

    def __str__(self):
        return "{}\n  source {} line {}".format(
            self.error,
            self.source.source,
            self.source.lineno)
