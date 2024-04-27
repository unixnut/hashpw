#!/usr/bin/python
# Source: https://djangosnippets.org/snippets/1508/
#
# Converted to Python 3 on 2023-07-02 22:20 by Alastair Irvine


def mysql_hash_password(password):
    nr = 1345345333
    add = 7
    nr2 = 0x12345671

    for c in (ord(x) for x in password if x not in (' ', '\t')):
        nr^= (((nr & 63)+add)*c)+ (nr << 8) & 0xFFFFFFFF
        nr2= (nr2 + ((nr2 << 8) ^ nr)) & 0xFFFFFFFF
        add= (add + c) & 0xFFFFFFFF

    return "%08x%08x" % (nr & 0x7FFFFFFF,nr2 & 0x7FFFFFFF)


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print('Python Implementation of MySQL\'s old password hash', file=sys.stderr)
        print('Usage: %s password' % sys.argv[0], file=sys.stderr)
        sys.exit(1)
    print(mysql_hash_password(sys.argv[1]))
