#!/usr/bin/python

import sys
import getopt
import addr2line

def usage():
    print >> sys.stderr, "%s [OPTION]..." % sys.argv[0]
    print >> sys.stderr, "-h, --help         Display usage and exit."
    print >> sys.stderr, "-e, --exe=BINARY   Executable to lookup line numbers in"

def main():
    try:
        opts, args = getopt.getopt( \
            sys.argv[1:], \
                "he:", \
                ["help", "exe="])
    except getopt.GetoptError, err:
        print >> sys.stderr, str(err)
        usage()
        sys.exit(1)

    patch_file = sys.stdin
    exe_file = None
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-e", "--exe"):
            exe = a
        else:
            assert False, "unhandled option"

    if exe == None:
        print >> sys.stderr, "No executable specified."
        sys.exit(1)

    try:
        a = addr2line.addr2line(exe)
        while True:
            l = raw_input().strip()
            if l == "" or l[0] == "#":
                print l
                continue

            (s_addr, s_type) = l.split(":")

            try:
                addr = int(s_addr, 0)
                print "# %s:%i" % a.lookup(addr)
            except ValueError, e:
                print >> sys.stderr, "Invalid patch: %s" % e
                sys.exit(2)
            except addr2line.IllegalLineError, e:
                print "# 00"
            except addr2line.IllegalFileError, e:
                print "# ??"

            print l

    except EOFError:
        exit(0)


if __name__ == "__main__":
    main()
