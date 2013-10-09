#!/usr/bin/python

import subprocess
import sys
import getopt


class Error(Exception):
    """addr2line exception."""

    def __init__(self, str):
        Exception.__init__(self, str)

class IllegalFileError(Error):
    def __init__(self, addr):
        Error.__init__(self,
                       "The address '0x%x' lacks a valid file mapping." % addr)

class IllegalLineError(Error):
    def __init__(self, addr):
        Error.__init__(self,
                       "The address '0x%x' lacks a line mapping." % addr)

class addr2line:
    def __init__(self, binary, addr2line = "/usr/bin/addr2line"):
        self.process = subprocess.Popen(
            [addr2line, "-e", binary],
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE)

    def lookup(self, addr):
        dbg_info = None
        try:
            print >> self.process.stdin, "0x%x" % addr
            dbg_info = self.process.stdout.readline().rstrip("\n")
        except IOError:
            raise Error(
                "Communication error with addr2line.")
        finally:
            ret = self.process.poll();
            if ret != None:
                raise Error(
                    "addr2line terminated unexpectedly (%i)." % (ret))
            

        (file, line) = dbg_info.rsplit(":", 1)
        if file == "??":
            raise IllegalFileError(addr);
        if line == "0":
            raise IllegalLineError(addr);

        return (file, int(line))

def usage():
    pass

def main():
    exe = "a.out"

    try:
        opts, args = getopt.getopt( \
            sys.argv[1:], \
                "he:", \
                ["help", "exe="])
    except getopt.GetoptError, err:
        print >> sys.stderr, str(err)
        usage()
        sys.exit(1)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif o in ("-e", "--exe"):
            exe = a
        else:
            assert False, "unhandled option"

    a = addr2line(exe)
    try:
        while True:
            l = raw_input()
            if l == "":
                continue

            try:
                addr = int(l, 0)
                print a.lookup(addr)

            except ValueError, e:
                print e

    except EOFError:
        exit(0)

if __name__ == "__main__":
    main()
