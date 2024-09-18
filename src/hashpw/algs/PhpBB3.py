from .Phpass import Phpass
from .. import errors


class PhpBB3(Phpass):
    name = "phpBB3"
    option = "B"
    prefix = "$H$"
    suffix = ""


    def hash(self, plaintext):
        ## raise errors.BadAlgException(self.name + " not implemented")

        phpass_hash = self.hasher.hash(plaintext)
        return self.prefix + phpass_hash[3:]
