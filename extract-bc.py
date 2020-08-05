#!/usr/bin/env python

WLLVM_EXT="/users/vikram/.local/bin/extract-bc"
BC_FILES_REPO="/local/device/bc-files"
LIBLCD_PATH="/local/device/linux-llvm/lcd-domains/liblcd"

import os, sys
import subprocess
from shutil import copy

def get_kernel_modules():
    kmod_list = subprocess.Popen(['find . -name "*.ko"'], stdout=subprocess.PIPE, shell=True).communicate()[0].split('\n')
    return [ko for ko in kmod_list if ko != ""]

def get_undefined_syms(kmod):
    cmd = "nm " + kmod + " | grep -i ' u ' | awk '{print $NF}'"
    sym_list = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True).communicate()[0].split('\n')
    return [sym for sym in sym_list if sym != ""]

def get_liblcd_exports():
    with open("./liblcd_funcs.txt", 'r') as f:
        d = f.read().split()
        return d
    # bash grep (Warn: use raw text)
    #cmd = r"grep -ohrI 'EXPORT_SYMBOL(\w\+)' " + LIBLCD_PATH + r" | sed 's/EXPORT_SYMBOL(\(\w\+\))/\1/g' | sort | uniq "
    #sym_list = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True).communicate()[0].split('\n')
    #return [sym for sym in sym_list if sym != ""]

def get_definitions():
    kmods = get_kernel_modules()
    print kmods

    liblcd_syms = get_liblcd_exports()
    liblcd_syms.append('vzalloc_node')
    liblcd_syms.append('memset')
    liblcd_syms.append('memcpy')

    #print liblcd_syms
    #sys.exit(1)

    log_files = []
    for k in kmods:
        print "=> Collecting undefined functions for " + k
        _undef_syms = get_undefined_syms(k)

        # TODO replace with set operations
        undef_syms = [s for s in _undef_syms if s not in liblcd_syms]
        if not undef_syms:
            continue

        fname = k + '.log'
        f = open(fname, 'w+');
        #print k, undef_syms
        for s in undef_syms:
            #cmd = "cscope -d -f./cscope.out -R -L1 " + s + " | head -1"
            cmd = "cscope -d -f./cscope.out -R -L1 " + s + " | grep '" + s + "(' | head -1"
            f.write(subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True).communicate()[0])
        log_files.append(fname)
    return log_files

def get_obj_files(log):
    obj_files = set()
    f = open(log, 'r')
    for line in f.readlines():
        def_file = line.split()[0]
        if def_file.endswith('.h') or def_file.endswith('.S'):
            continue
        obj_files.add(def_file.replace('.c', '.o'))
    return obj_files

def extract_bitcode(obj):
    try:
        stat = os.stat(obj)
    except:
        print 'Unable to get info about', obj
        return ""
    else:
        cmd = WLLVM_EXT + ' ' + obj
        subprocess.Popen([cmd], stdout=subprocess.PIPE, shell = True).communicate()
        return obj + '.bc'


def generate_bc_files(log_files):
    for log in log_files:
        driver_name = log.split('/')[-1].replace('.ko.log', '')
        driver_obj = log.replace('.log', '')
        driver_bc = driver_obj + '.bc'
        kernel_bc = driver_name + '_kernel.bc'
        bc_input = ""

        print "=> Assembling bitcode files for " + kernel_bc

        # read the log and get the object files for functions defined on the
        # kernel side
        obj_files = get_obj_files(log)

        # if obj is present, extract the bc file
        for obj in obj_files:
            bc_input += extract_bitcode(obj)
            bc_input += " "

        # link .bc files to driver_kernel.bc
        cmd = "llvm-link -o " + kernel_bc + ' ' +  bc_input
        print cmd
        subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True).communicate()

        # extract .bc files from driver.ko
        cmd = WLLVM_EXT + ' ' + driver_obj + ' --output ' + driver_bc
        subprocess.Popen([cmd], stdout=subprocess.PIPE, shell = True).communicate()

        try:
            os.mkdir(BC_FILES_REPO + '/' + driver_name)
        except:
            pass
        print driver_bc
        copy(driver_bc, BC_FILES_REPO + '/' + driver_name)
        copy(kernel_bc, BC_FILES_REPO + '/' + driver_name)

if __name__ == '__main__':
    log_files = get_definitions()
    generate_bc_files(log_files)
