from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import base64

from .. import errors
from ..structure import Algorithm


class HTTPBasic(Algorithm):
    """Generates HTTP basic authentication header contents"""

    name = "http-basic"
    option = "H"
    prefix = ""
    suffix = ""
    min_length = 5
    takes_username = True


    def __init__(self, *, username: str):
        if not username:
            raise errors.InvalidArgException("Username missing; specify with -u")
        self.username = username


    def recognise(self, s: str):
        return False


    def hash(self, plaintext: str):
        auth_string = "%s:%s" % (self.username, plaintext)
        output_byte_str = base64.b64encode(auth_string.encode("UTF-8"))
        return output_byte_str.decode('ascii')
