#!/usr/bin/python
#-*-coding:utf-8 -*-

import os, os.path, sys
import win32process, win32event


try :
	handle = win32process.CreateProcess('test.exe','', None, None, 0,win32process.CREATE_NO_WINDOW, None , None,win32process.STARTUPINFO())
	running = True        
except Exception, e:
	print "Create Error!"
	handle = None
	running = False

while running :
	rc = win32event.WaitForSingleObject(handle[0], 1000)
	if rc == win32event.WAIT_OBJECT_0:
		running = False
		
#end while
print "GoodBye"