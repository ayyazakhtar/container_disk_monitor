#!/usr/bin/python
# This code reads BPF maps that have TCP, HTTP and disk read/write data
#    for all containers provided in the command line.
# Maps data is subsequently written to a log file---one logfile per container.

from __future__ import print_function
from bcc import BPF
from pyroute2 import IPRoute, IPDB
from ctypes import c_uint,c_int, c_ulong
import socket
import time
import subprocess
import struct
import traceback
import pdb
import os
import argparse

# Writing the current time to the logfile
def write_time_to_log(logfile):
    logfile.write('---------------------------------------------------\n')
    logfile.write('time=%s:\n' % time.time())
    logfile.write('time=%s:\n' % time.strftime("%H:%M:%S - %d/%m/%Y"))

def get_lxc_info(lxc_name):
    info_cmd = [ 'bash', '-c', 'lxc-info --name ' + lxc_name ]
    cmd_output = subprocess.check_output(info_cmd).split('\n')
    pid = filter(bool, cmd_output[2].split(' '))[1]
    veth = filter(bool, cmd_output[8].split(' '))[1]
    return {'pid':pid, 'veth':veth}


def get_disk_access_type(number):
    return {1:'VFS_READ',
            2:'VFS_WRITE',
            }[number]

def write_disk_table_and_reset(disk_map, tracefile):
    for key in disk_map:
        try:
            tracefile.write('%s, %s: %d, %d\n' %(get_disk_access_type(key.disk_type), key.process_id, disk_map[key].bytes, 
                                disk_map[key].count))
        except Exception:
            traceback.print_exc()
    disk_map.clear()
# main
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("container_name", help="Name of the container to monitor.")
    parser.add_argument("-i", help="interval between each poll (default 30 seconds).", type=int)
    parser.add_argument("-o", help="output file to store logs(default is <container_name>.log.")
    args = parser.parse_args()
    container_details = get_lxc_info(args.container_name)
    log_interval = 30
    if args.i:
        log_interval = args.i;

    logfile_name = args.container_name + '.log'
    if args.o:
        logfile_name = args.o

    logfile = open(logfile_name, 'a', 0)
    with open('get_disk_info.c', 'r') as content_file:
        bpf_text = content_file.read()

    bpf_text = bpf_text.replace('CONTAINER_PARENT_PID', '%d' % int(container_details['pid']))
    bpf_disk_t = BPF(text=bpf_text)

    bpf_disk_t.attach_kprobe(event='vfs_read', fn_name='vfs_read_func')
    bpf_disk_t.attach_kprobe(event='vfs_write', fn_name='vfs_write_func')

    try:
        while (1):
            # 30 second time interval between polling
            time.sleep(log_interval)
            write_time_to_log(logfile)
            disk_map = bpf_disk_t['disk_map']
            if len(disk_map) > 0:
                write_disk_table_and_reset(disk_map, logfile)
    except Exception as e:
        traceback.print_exc()
    finally:
        logfile.close()


if __name__ == "__main__":
    main()
