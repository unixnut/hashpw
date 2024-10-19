from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

from dataclasses import dataclass

from .YescryptFlags import YescryptFlags
from .utils import B64StringReader, B64StringWriter


# *** CLASSES ***
@dataclass
class YescryptParams:
    HAVE_PARALLELISM     = 0x01
    HAVE_TIME_FACTOR     = 0x02
    HAVE_UPGRADED_COUNT  = 0x04
    HAVE_NROM            = 0x08

    flags: int = YescryptFlags.YESCRYPT_RW_DEFAULTS
    N: int = 4096
    r: int = 32
    p: int = 1
    t: int = 0
    g: int = 0
    ROM: int = 0


    @classmethod
    def decode_hash(context, s: str): # -> YescryptParams
        parts = s.split('$')

        # check for correct marker prefix
        if len(parts) != 5:
            raise ValueError("Invalid encoding. Valid yescrypt encoding should have 4 values separated by '$'")

        # we only support "y" (not "7")
        if parts[1] != "y":
            raise ValueError("Unsupported prefix: " + parts[1])

        return context.decode(parts[2])


    @classmethod
    def decode(context, s: str): # -> YescryptParams
        reader = B64StringReader(s)

        # Decode flavor (which fits 10 bits into 8 with a magic algorithm)
        flavor = reader.readUint32Min(0)

        if flavor < YescryptFlags.YESCRYPT_RW:
            flags = flavor
        elif flavor <= YescryptFlags.YESCRYPT_RW + YescryptFlags.YESCRYPT_RW_FLAVOR_MASK >> 2:
            flags = YescryptFlags.YESCRYPT_RW + ((flavor - YescryptFlags.YESCRYPT_RW) << 2)
        else:
            raise ValueError("Invalid flavor")

        # Decode N
        nlog2: int = reader.readUint32Min(1)
        if nlog2 > 31:
            raise ValueError("Invalid N.  Nlog2 must be < 32")
        N: int = 1 << nlog2

        # Decode r
        r = reader.readUint32Min(1)

        # Decode p, t, and g and ROM (if they exist)
        p: int = 1
        t: int = 0
        g: int = 0
        if reader.hasMore():
            have: int = reader.readUint32Min(1)

            if (have & context.HAVE_PARALLELISM) != 0:
                # floor value is 2 because if not present, will default to 1
                p = reader.readUint32Min(2)
            if (have & context.HAVE_TIME_FACTOR) != 0:
                t = reader.readUint32Min(1)
            if (have & context.HAVE_UPGRADED_COUNT) != 0:
                g = reader.readUint32Min(1)
            if (have & context.HAVE_NROM) != 0:
                raise NotImplementedError("ROM is not supported")

        return YescryptParams(flags, N, r, p, t, g, ROM=0)


    def encode(self) -> str:
        """
        Encode the params to a string, not including the "$y$" prefix, any
        delimeters or a salt.
        """

        writer = B64StringWriter()

        flavor: int
        if self.flags < YescryptFlags.YESCRYPT_RW:
            flavor = self.flags
        elif (self.flags & YescryptFlags.YESCRYPT_MODE_MASK) == YescryptFlags.YESCRYPT_RW and \
             self.flags <= (YescryptFlags.YESCRYPT_RW | YescryptFlags.YESCRYPT_RW_FLAVOR_MASK):
            flavor = YescryptFlags.YESCRYPT_RW + (self.flags >> 2)
        else:
            raise ValueError("Invalid flavor")

        nlog2: int = N2log2(self.N)
        if nlog2 == 0:
            raise ValueError("N must be power of 2")

        if self.r * self.p >= (1 << 30):
            raise ValueError("Invalid r")

        writer.writeUint32Min(flavor, 0)
        writer.writeUint32Min(nlog2, 1)
        writer.writeUint32Min(self.r, 1)

        optional_params_writer = B64StringWriter()
        h: int = 0
        if self.p > 1:
            optional_params_writer.writeUint32Min(self.p, 2)
            h = h | self.HAVE_PARALLELISM
        if self.t > 0:
            optional_params_writer.writeUint32Min(self.t, 1)
            h = h | self.HAVE_TIME_FACTOR
        if self.g > 0:
            optional_params_writer.writeUint32Min(self.g, 1)
            h = h | self.HAVE_UPGRADED_COUNT
        if self.ROM > 0:
            optional_params_writer.writeUint32Min(self.ROM, 1)
            h = h | self.HAVE_NROM
        if h > 0:
            writer.writeUint32Min(h, 1)   # Even the 'have' value is floor-converted
            writer.appendString(str(optional_params_writer))

        return str(writer)


    def __str__(self) -> str:
        return self.encode()


    # Can't define __repr__() or it uglifies test output, e.g. if defined:
    #    AssertionError: <hashpw.algs.yescrypt.YescryptSettings.YescryptParams object at 0x7f0c673e9100> != <hashpw.algs.yescrypt.YescryptSettings.YescryptParams object at 0x7f0c66e2ab50> : params are wrong
    # vs. this if not:
    #    AssertionError: YescryptParams(flags=182, N=16384, r=32, p=1, t=0, g=0, ROM=0) != YescryptParams(flags=182, N=16384, r=32, p=1, t=0, g=1, ROM=0) : params are wrong
    ## def __repr__(self) -> str:
    ##     return "YescryptParams(flags=%03x, N=%d, p=%d, t=%d, g=%d, ROM=%dA)" % (self.flags, self.N, self.r, self.p, self.t, self.g, self.ROM)


# *** FUNCTIONS ***
def N2log2(N: int) -> int:
    if N < 2: return 0

    nlog2 = 2
    while N >> nlog2 != 0: nlog2 += 1
    nlog2 -= 1
    if N >> nlog2 != 1: return 0
    return nlog2
