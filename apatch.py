#!/usr/bin/python
#
# Patches an assembler file using a patch file of the following format:
#  file:line:type
#  ...
#
# Where 'line' is the line number in the assembler file.
#
# If an executable is specified the following patch format is used:
#  addr:type
#
# Type is one of the following:
#  nta - Insert a prefetch nta for the memory op on the line
#
# Entire lines may be turned into comments using the '#' comment character.
#

import getopt
import sys
import re
import addr2line
import os

from itertools import tee, izip

class IllegalPatch(Exception):
    def __init__(self, file, line, str):
        Exception.__init__(self, "%s:%i %s" % (file, line, str))

class apatch:
    
    def __init__(self, patch, exe_file = None, log = None):
        self.patches = { }
        self.sources = [ ]
        self.re_memop = re.compile("(?:0[xX][0-9a-fA-F]+|0[bB][01]*|\d+|[a-zA-Z_.$][0-9a-zA-Z_.$]*)?\([^)]*\)")
        self.re_offset = re.compile("[\s]+0[xX][0-9a-fA-F]+|[\s]+\d+")
        self.re_regs = re.compile("\([^)]*\)")
        self.ind_regs = re.compile("\%r[0-9a-zA-z]+")
        self.addr2line = addr2line.addr2line(exe_file) if exe_file != None else None
        self.log = log
        self.line_size = 64
        self.skipopt_num = 1

        self.__log("Reading patches from '%s'" % (patch))
        file = open(patch, "r")
        if self.addr2line != None:
            self.__log("Patch type: binary")
            self.__read_patches_binary(file)
        else:
            self.__log("Patch type: asm line")
            self.__read_patches(file)
        file.close()

    def __str__(self):
        return str(self.patches)

    def __log(self, msg):
        if self.log != None:
            print >> self.log, msg

    def __warn(self, msg):
        print >> sys.stderr, msg
        self.__log(msg)

    def __err(self, exception):
        self.__log(exception)
#        raise exception

    def __add_patch(self, patch_line, name, line, type, pref_dist, clob_reg=None, base_reg=None, mem_dis=None, update_addr=None, update_reg=None, score=None):
        self.__log("  %i: %s:%i %s" % (patch_line, name, line, type))
        if not type in ("nta", "pf", "ptr", "ptradj", "ptrnta", "ptradjnta", "ptradjonly", "ptrnchild", "ptrnchildadj", "ptrnchildadjnta", "ptrcyc", "ptrcycadj", "ptrcycadjnta", "ptrwt", "ptrwtnta", "ptrind", "ptrindadj", "ptrindnta", "ptrindadjnta", "ptrupr", "ptruprcyc", "ptruprcycnta", "ptruprnta", "ptraddind", "push", "pop"):
            self.__err(IllegalPatch(
                    "%i: Patch type '%s' for line %i is unknown." % ( \
                        patch_line, type, line)))

        if name not in self.sources:
            self.sources += [ name ]

        id = (name, line)
        if id in self.patches:
            if type in self.patches[id]:
                self.__warn(
                    "%i: Warning: Patch type '%s' already set for line %i" % ( \
                        patch_line, type, line))
            else:
                self.patches[id] += [type, pref_dist, clob_reg, base_reg, mem_dis, update_addr, update_reg, score]
        else:
            self.patches[id] = [type, pref_dist, clob_reg, base_reg, mem_dis, update_addr, update_reg, score]

    def __trim_line(self, line):
        trimmed = line.strip()
        if trimmed == "" or trimmed[0] == "#":
            return None
        else:
            return trimmed

    def __read_patches(self, patch):
        self.patches = { }
        line = 0

        for patch_line in patch:
            line += 1
            trimmed = self.__trim_line(patch_line)
            if trimmed == None:
                continue

            (file, st_line, type, sd) = trimmed.split(":")
            self.__add_patch(line,
                             file,
                             int(st_line, 0),
                             type,
                             sd, 
                             clob_reg, 
                             base_reg, 
                             mem_dis, 
                             update_addr, 
                             update_reg, 
                             score)

        
    def __read_patches_binary(self, patch):
        self.patches = { }
        line = 0

        for patch_line in patch:
            line += 1
            trimmed = self.__trim_line(patch_line)
            if trimmed == None:
                continue

            sd = 0
            clob_reg = None 
            base_reg = None 
            mem_dis = None
            update_addr = None
            update_reg = None
            score = None

            tok_list = trimmed.split(":")
            if "ptr" in tok_list[1]:
                (addr, type, clob_reg, base_reg, mem_dis, update_addr, update_reg, score) =  tok_list
            elif "push" in tok_list[1] or "pop" in tok_list[1]:
                (addr, type, base_reg) = tok_list
            else:
                (addr, type, sd) = tok_list
            try:
                (file, target_line) = self.addr2line.lookup(int(addr, 0))
                self.__add_patch(line,
                                 os.path.basename(file),
                                 target_line,
                                 type,
                                 sd, 
                                 clob_reg, 
                                 base_reg, 
                                 mem_dis, 
                                 update_addr, 
                                 update_reg, 
                                 score)

            except addr2line.Error:
                self.__warn("Failed to lookup source line for '0x%x', skipping patch site." % int(addr, 0))

    def __patch_line(self, filename, linenr, line):
        id = (filename, linenr)
        if id not in self.patches:
            return line

        output = ""

        print self.patches[id]

        for t, sd, clob_reg, base_reg, mem_dis, update_addr, update_reg, score \
                in izip(self.patches[id][::8], self.patches[id][1::8], self.patches[id][2::8], self.patches[id][3::8], \
                            self.patches[id][4::8], self.patches[id][5::8], self.patches[id][6::8], self.patches[id][7::8]):
            self.__log("  %i:%s" % (id[1], t))
            memop = self.re_memop.findall(line)
            regs_list = self.ind_regs.findall(line)
            
            print regs_list

#            for reg in regs_list:
#                if memop[0].count(reg) > 0:
#                    regs_list.remove(reg)

#            wr_pointer_reg = None
            if len(regs_list) > 0:
                index = len(regs_list) - 1
                wr_pointer_reg = regs_list[index]

            if len(memop) == 1:

                offset = self.re_offset.findall(line)
                regs = self.re_regs.findall(memop[0])

                if len(offset) == 0:
                    offset = ['0']

                off = int(offset[0]) + int(sd)
                    
                pref_reg_off = str(off)+regs[0]

                if t == "nta":
                    output += "\tprefetchnta %s\n%s" % (pref_reg_off, line) #(memop[0], line)
                elif t == "pf":
                    output += "\tprefetcht0 %s\n%s" % (pref_reg_off, line) #(memop[0], line)
                elif t == "push":
                    output += "\t%s\n" % (line)
                    base_reg = "%"+base_reg
                    output += "\t push %s\n" % (base_reg)
                elif t == "pop":
                    base_reg = "%"+base_reg
                    output += "\t pop %s\n" % (base_reg)
                    output += "\t%s\n" % (line)
                elif "ptr" in t:
                    if "ptrnchild" in t:
                        mem_op = str(mem_dis)+"(%"+(base_reg)+")"
                        dst_reg = "%"+clob_reg
                        mov_instr = "mov %s, %s" % (mem_op, dst_reg)
                        child_ptr_offset = score  #This is a hack. Please fix it
                        test_instr = "test %s, %s" % (dst_reg, dst_reg)
                        label = ".SKIP_MOPT%d"%(self.skipopt_num)
                        jump_instr = "je %s" % (label)
                        self.skipopt_num = self.skipopt_num + 1
                        obj_mem_op = str(child_ptr_offset)+"("+(dst_reg)+")"
                        obj_ptr_access_instr = "mov %s, %s" % (obj_mem_op, dst_reg)
                        pref_addr = "("+dst_reg+")"

                        output += "\t%s\n" % (line)
                        output += "\t%s\n" % (mov_instr)
                        output += "\t%s\n" % (test_instr)
                        output += "\t%s\n" % (jump_instr)
                        if "adj" in t:
                            pref_adj_addr = str(self.line_size) + pref_addr
                            if "nta" in t:
                                output += "prefetchnta %s\n" % (pref_adj_addr)
                            else:
                                output += "prefetcht0 %s\n" % (pref_adj_addr)
                        output += "\t%s\n" % (obj_ptr_access_instr)
                        output += "%s:\n" % (label)
                        if "nta" in t:
                            output += "prefetchnta %s\n" % (pref_addr)
                        else:
                            output += "prefetcht0 %s\n" % (pref_addr)
                        continue

                    if "ptradjonly" in t:
                        output += "\t%s\n" % (line)
                        pref_addr = "(%"+(update_reg)+")"
                        pref_adj_addr = str(self.line_size) + pref_addr
                        if "nta" in t:
                            output += "prefetchnta %s\n" % (pref_adj_addr)
                        else:
                            output += "prefetcht0 %s\n" % (pref_adj_addr)
                        continue

                    if "ptrcyc" in t:
                        mem_op = str(mem_dis)+"(%"+(base_reg)+")"
                        dst_reg = "%"+clob_reg
                        mov_instr = "mov %s, %s" % (mem_op, dst_reg)
                        pref_addr = "("+dst_reg+")"
                        output += "\t%s\n" % (line)
                        output += "\t%s\n" % (mov_instr)
                        test_instr = "test %s, %s" % (dst_reg, dst_reg)
                        label = ".SKIP_MOPT%d"%(self.skipopt_num)
                        jump_instr = "je %s" % (label)
                        self.skipopt_num = self.skipopt_num + 1
                        mem_op = str(mem_dis)+"("+(dst_reg)+")"
                        mov_instr = "mov %s, %s" % (mem_op, dst_reg)
                        output += "\t%s\n" % (test_instr)
                        output += "\t%s\n" % (jump_instr)
                        output += "\t%s\n" % (mov_instr)
                        output += "%s:\n" % (label)
                        if "nta" in t:
                            output += "prefetchnta %s\n" % (pref_addr)
                        else:
                            output += "prefetcht0 %s\n" % (pref_addr)
                        if "adj" in t:
                            pref_adj_addr = str(self.line_size) + pref_addr
                            if "nta" in t:
                                output += "prefetchnta %s\n" % (pref_adj_addr)
                            else:
                                output += "prefetcht0 %s\n" % (pref_adj_addr)
                        continue                    
                    
                    if "ptraddind" in t:
                        dst_reg = "%"+clob_reg
                        base_reg = "%"+base_reg
                        update_reg = "%"+update_reg
                        mov_instr = "mov %s, %s"%(base_reg, dst_reg)
                        add_instr = "add %s, %s"%(update_reg, dst_reg)
                        output += "\t%s\n" % (line)
                        output += "\t%s\n" % (mov_instr)
                        output += "\t%s\n" % (add_instr)
                        pref_addr = str(mem_dis)+"("+(dst_reg)+")"
                        if "nta" in t:
                            output += "prefetchnta %s\n" % (pref_addr)
                        else:
                            output += "prefetcht0 %s\n" % (pref_addr)
                        continue


                    if "ptrind" in t:
                        dst_reg = "%"+clob_reg
                        idx_reg = update_reg          # This is a hack, please fix it
                        scale = score                 # This is a hack, please fix it
                        mem_op = str(mem_dis)+"(%"+(base_reg)+", %"+idx_reg+", "+scale+")"
                        mov_instr = "mov %s, %s" % (mem_op, dst_reg)
                        pref_addr = "("+dst_reg+")"
                        output += "\t%s\n" % (line)
                        output += "\t%s\n" % (mov_instr)
                        if "nta" in t:
                            output += "prefetchnta %s\n" % (pref_addr)
                        else:
                            output += "prefetcht0 %s\n" % (pref_addr)
                        continue

                    if "ptrupr" in t:
                        update_reg = "%"+update_reg
                        dst_reg = "%"+clob_reg
                        test_instr = "test %s, %s" % (update_reg, update_reg)
                        label = ".SKIP_MOPT%d"%(self.skipopt_num)
                        jump_instr = "je %s" % (label)
                        self.skipopt_num = self.skipopt_num + 1
                        mem_op = str(mem_dis)+"("+(update_reg)+")"
                        mov_instr = "mov %s, %s" % (mem_op, dst_reg)
                        pref_addr = str(mem_dis)+"("+dst_reg+")"
                        output += "\t%s\n" % (line)
                        output += "\t%s\n" % (test_instr)
                        output += "\t%s\n" % (jump_instr)
                        output += "\t%s\n" % (mov_instr)
                        if "cyc" in t:
                            test_instr = "test %s, %s" % (dst_reg, dst_reg)
                            output += "\t%s\n" % (test_instr)
                            output += "\t%s\n" % (jump_instr)
                            mem_op = str(mem_dis)+"("+(dst_reg)+")"
                            mov_instr = "mov %s, %s" % (mem_op, dst_reg)
                            output += "\t%s\n" % (mov_instr)
                        if "nta" in t:
                            output += "prefetchnta %s\n" % (pref_addr)
                        else:
                            output += "prefetcht0 %s\n" % (pref_addr)
                        output += "%s:\n" % (label)
                        continue

                    if clob_reg != "None":
                        mem_op = str(mem_dis)+"(%"+(base_reg)+")"
                        dst_reg = "%"+clob_reg
                        mov_instr = "mov %s, %s" % (mem_op, dst_reg)
                        pref_addr = "("+dst_reg+")"

                        output += "\t%s\n" % (mov_instr)
                        if "nta" in t:
                            output += "prefetchnta %s\n" % (pref_addr)
                        else:
                            output += "prefetcht0 %s\n" % (pref_addr)
                        output += "\t%s\n" % (line)
                    else:
#                        mem_op = str(mem_dis)+"(%"+(update_reg)+")"
                        pref_addr = str(mem_dis)+"(%"+(update_reg)+")"
                        output += "\t%s\n" % (line)
                        if "nta" in t:
                            output += "prefetchnta %s\n" % (pref_addr)
                        else:
                            output += "prefetcht0 %s\n" % (pref_addr)
                    
                    if "ptradj" in t:
                        pref_adj_addr = str(self.line_size) + pref_addr
                        if "nta" in t:
                            output += "prefetchnta %s\n" % (pref_adj_addr)
                        else:
                            output += "prefetcht0 %s\n" % (pref_adj_addr)
                else:
                    assert False, "unhandled patch type"
            elif len(memop) == 0:
                output += "%s" % (line)
                self.__err(IllegalPatch(filename, linenr,
                                        "Can't find operand."))
            else:
                output += "%s" % (line)
                self.__err(IllegalPatch(filename, linenr,
                                        "Matched more than one operand."))
        return output

    def patch(self, name, input, output):
        self.__log("Patching %s..." % (name))
        line = 0
        for input_line in input:
            line += 1
            output.write(self.__patch_line(name, line, input_line))

def usage():
    print >> sys.stderr, "%s [OPTION]..." % sys.argv[0]
    print >> sys.stderr, "-h, --help         Display usage and exit."
    print >> sys.stderr, "-p, --patch=FILE   Patch file"
    print >> sys.stderr, "-e, --exe=BINARY   Executable to lookup line numbers in"
    print >> sys.stderr, "-b, --base=FILE    Override patch base name"
    print >> sys.stderr, "-i, --input=FILE   Assembly file to patch (default: use stdin)"

def main():
    try:
        opts, args = getopt.getopt( \
            sys.argv[1:], \
                "hp:e:vi:b:", \
                ["help", "patch=", "exe=", "verbose", "input=", "base="])
    except getopt.GetoptError, err:
        print >> sys.stderr, str(err)
        usage()
        sys.exit(2)
    patch_file = None
    exe_file = None
    log_handle = None
    patch_base = None
    input_file = None
    input_handle = None
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-p", "--patch"):
            patch_file = a
        elif o in ("-e", "--exe"):
            exe_file = a
        elif o in ("-v", "--verbose"):
            log_handle = sys.stderr
        elif o in ("-i", "--input"):
            input_file = a
        elif o in ("-b", "--base"):
            patch_base = a
        else:
            assert False, "unhandled option"

    if patch_file == None:
        print >> sys.stderr, "No patch file specified."
        sys.exit(2)

    try:
        input_handle = open(input_file, 'r') if input_file else sys.stdin
    except IOError, err:
        print >> sys.stderr, "Failed to open input: %s" % str(err)
        sys.exit(2)

    if patch_base == None:
        patch_base = os.path.basename(input_file) if input_file else ""

    try:
        patch = apatch(patch_file, exe_file)
        # XXX: Base name
        patch.patch(patch_base, input_handle, sys.stdout)
    except IOError, err:
        print >> sys.stderr, "Failed to open patch file: %s" % str(err)
        sys.exit(2)
    except IllegalPatch, err:
        print >> sys.stderr, "Error: %s" % str(err)
        sys.exit(3)


if __name__ == "__main__":
    main()
