#!/usr/bin/python
#-*-coding:utf-8 -*-

import subprocess, time, os
 
class Shell(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.ret_code = None
        self.ret_info = None
        self.err_info = None
 
    def run_background(self):
        os.popen(self.cmd)
        # self._process = subprocess.Popen(self.cmd, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
 
    def get_status(self):
        retcode = self._process.poll()
        if retcode == None:
            status = "RUNNING"
        else:
            status = "FINISHED"
        return status
 
    def print_output(self):
        for _ in range(6):
            line = self._process.stdout.readline() # 这儿会阻塞
            if line:
                print "output:", line
            else: # 只有子进程结束后, 才会有readline返回""的情况
                print "no ouput yet"