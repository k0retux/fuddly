################################################################################
#
#  Copyright 2014-2016 Eric Lacombe <eric.lacombe@security-labs.org>
#
################################################################################
#
#  This file is part of fuddly.
#
#  fuddly is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  fuddly is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with fuddly. If not, see <http://www.gnu.org/licenses/>
#
################################################################################

import sys
import random
import string
import array

from framework.global_resources import convert_to_internal_repr

def rand_string(size=None, mini=1, maxi=10, str_set=string.printable):

    out = ""
    if size is None:
        size = random.randint(mini, maxi)
    while len(out) < size:
        val = random.choice(str_set)
        out += val

    return out


def corrupt_bytes(s, p=0.01, n=None, ctrl_char=False):
    """Corrupt a given percentage or number of bytes from a string"""
    s = bytearray(s)
    l = len(s)
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(range(l), n):
        if ctrl_char:
            s[i] = random.choice([x for x in range(0,32)] + [0x7f])
        else:
            s[i] = (s[i]+random.randint(1,255))%256

    return bytes(s)

def corrupt_bits(s, p=0.01, n=None, ascii=False):
    """Flip a given percentage or number of bits from a string"""
    s = bytearray(s)
    l = len(s)*8
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(range(l), n):
        s[i//8] ^= 1 << (i%8)
        if ascii:
            s[i//8] &= 0x7f

    return bytes(s)

def calc_parity_bit(x):
    """return 0 if the number of bits is even, otherwise returns 1"""
    bit = 0
    num_bits = 0
    while x:
        bitmask = 1 << bit
        bit += 1
        if x & bitmask:
            num_bits += 1
        x &= ~bitmask
    return num_bits % 2

if __name__ == "__main__":

    for i in range(10):
        print(corrupt_bits(b'testing', p=0.05))

    for i in range(10):
        print(corrupt_bytes(b'testing', p=0.05))

    for i in range(4):
        print(rand_string(10))
        print(rand_string(mini=15, maxi=30))
        print(rand_string())
        print(rand_string(mini=15, maxi=30, str_set='RXVZ'))
