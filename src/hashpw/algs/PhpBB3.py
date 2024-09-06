from .Phpass import Phpass
from .. import errors


class PhpBB3(Phpass):
    name = "phpBB3"
    option = "B"
    prefix = "$H$"
    suffix = ""


    def hash(self, plaintext):
        raise errors.BadAlgException(self.name + " not implemented")
