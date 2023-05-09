class ChangeCipherSpecMessage(object):

    def __init__(self):
        self.bytes = b''

    def value(self):
        return ord(self.bytes[0])

    @classmethod
    def create(cls):
        self = cls()
        self.bytes = b'\1'

        return self

    @classmethod
    def from_bytes(cls, provided_bytes):
        self = cls()
        self.bytes = provided_bytes
        return self

    def __len__(self):
        return len(self.bytes)
