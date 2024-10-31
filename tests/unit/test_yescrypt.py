#!/usr/bin/env python

"""Tests for `hashpw` package."""


from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import logging
import os
import unittest
import re

## from hashpw import hashpw
import hashpw
## from ..scaffolding.algorithms import AlgorithmGenericTests
from hashpw.algs.yescrypt.YescryptSettings import YescryptParams, Yescrypt7Params
from hashpw.algs.yescrypt.YescryptSettings import N2log2
from hashpw.algs.yescrypt.YescryptFlags import YescryptFlags


# *** CLASSES ***
class TestYesCrypt(unittest.TestCase):
    def test_encode_logN12(self):
        t = YescryptParams(N=4096)
        result = t.encode()
        self.assertEqual("j9T", result, msg="Encoded params are wrong")

    def test_encode_logN13(self):
        t = YescryptParams(N=8192)
        result = t.encode()
        self.assertEqual("jAT", result, msg="Encoded params are wrong")

    def test_encode_logN13_t1(self):
        t = YescryptParams(N=8192, t=1)
        result = t.encode()
        self.assertEqual("jAT/.", result, msg="Encoded params are wrong")

    def test_encode_logN13_t4(self):
        t = YescryptParams(N=8192, t=4)
        result = t.encode()
        self.assertEqual("jAT/1", result, msg="Encoded params are wrong")

    def test_encode_logN13_p1(self):
        t = YescryptParams(N=8192, p=1)
        result = t.encode()
        self.assertEqual("jAT", result, msg="Encoded params are wrong")

    def test_encode_logN13_p2(self):
        t = YescryptParams(N=8192, p=2)
        result = t.encode()
        self.assertEqual("jAT..", result, msg="Encoded params are wrong")

    def test_encode_logN13_p2_t4(self):
        t = YescryptParams(N=8192, p=2, t=4)
        result = t.encode()
        self.assertEqual("jAT0.1", result, msg="Encoded params are wrong")

    def test_decode_j9T(self):
        params = YescryptParams.decode_hash('$y$j9T$LdJMENpBABJJ3hIHjB1Bi.$')
        self.assertEqual(YescryptFlags.YESCRYPT_RW_DEFAULTS, params.flags, msg="flags are wrong")
        self.assertEqual(4096,  params.N, msg="N is wrong")
        self.assertEqual(32,    params.r, msg="r is wrong")
        self.assertEqual(1,     params.p, msg="p is wrong")
        self.assertEqual(0,     params.t, msg="t is wrong")
        self.assertEqual(0,     params.g, msg="g is wrong")
        self.assertEqual(0,     params.ROM, msg="ROM is wrong")

    def test_decode_jAT_1(self):
        params = YescryptParams.decode_hash('$y$jAT/1$LdJMENpBABJJ3hIHjB1Bi.$')
        self.assertEqual(YescryptFlags.YESCRYPT_RW_DEFAULTS, params.flags, msg="flags are wrong")
        self.assertEqual(8192,  params.N, msg="N is wrong")
        self.assertEqual(32,    params.r, msg="r is wrong")
        self.assertEqual(1,     params.p, msg="p is wrong")
        self.assertEqual(4,     params.t, msg="t is wrong")
        self.assertEqual(0,     params.g, msg="g is wrong")
        self.assertEqual(0,     params.ROM, msg="ROM is wrong")

    def test_decode_jAT0_1(self):
        params = YescryptParams.decode_hash('$y$jAT0.1$LdJMENpBABJJ3hIHjB1Bi.$')
        self.assertEqual(YescryptFlags.YESCRYPT_RW_DEFAULTS, params.flags, msg="flags are wrong")
        self.assertEqual(8192,  params.N, msg="N is wrong")
        self.assertEqual(32,    params.r, msg="r is wrong")
        self.assertEqual(2,     params.p, msg="p is wrong")
        self.assertEqual(4,     params.t, msg="t is wrong")
        self.assertEqual(0,     params.g, msg="g is wrong")
        self.assertEqual(0,     params.ROM, msg="ROM is wrong")

    def test_decode_jD5_7(self):
        params = YescryptParams.decode_hash('$y$jD5.7$LdJMENpBABJJ3hIHjB1Bi.$')
        self.assertEqual(YescryptFlags.YESCRYPT_RW_DEFAULTS, params.flags, msg="flags are wrong")
        self.assertEqual(65536, params.N, msg="N is wrong")
        self.assertEqual(8,     params.r, msg="r is wrong")
        self.assertEqual(11,    params.p, msg="p is wrong")
        self.assertEqual(0,     params.t, msg="t is wrong")
        self.assertEqual(0,     params.g, msg="g is wrong")
        self.assertEqual(0,     params.ROM, msg="ROM is wrong")

    def test_decode_jBT1_(self):
        params = YescryptParams.decode_hash('$y$jBT1.$LdJMENpBABJJ3hIHjB1Bi.$')
        expected_params = YescryptParams(N=16384, g=1)
        self.assertEqual(expected_params, params, msg="params are wrong")



class TestYesCrypt7(unittest.TestCase):
    def test_encode_logN14(self):
        """Default params as used by mkpasswd(1)"""

        t = Yescrypt7Params(N=16384)
        result = t.encode()
        self.assertEqual("CU..../....", result, msg="Encoded params are wrong")

    def test_encode_logN15(self):
        t = Yescrypt7Params(N=32768)
        result = t.encode()
        self.assertEqual("DU..../....", result, msg="Encoded params are wrong")

    def test_encode_logN15_p2(self):
        t = Yescrypt7Params(N=32768, p=2)
        result = t.encode()
        self.assertEqual("DU....0....", result, msg="Encoded params are wrong")

    def test_decode(self):
        params = Yescrypt7Params.decode_hash('$7$CU..../....bUMwNqEOZzE9RqPZH5o9W0$')
        expected_params = Yescrypt7Params(N=16384)
        self.assertEqual(expected_params, params, msg="params are wrong")



class TestLog2(unittest.TestCase):
    def test_4096(self):
        result = N2log2(4096)
        self.assertEqual(12, result, msg="N2log2 math error")

    def test_8192(self):
        result = N2log2(8192)
        self.assertEqual(13, result, msg="N2log2 math error")
