#!/usr/bin/python
"""
    Tails lines from a log file (an Apache2 logfile with wanted format).
    Checks if the log file contains a decoytoken from another file.
    If yes, writes an alert to syslog. 

    Test it out:

import logparser
accesslog = "/var/log/apache2/access.log"
tokens = "/home/foobar/siikrets.txt"
toparse = "%h - - %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
timer = 2
try:
	x = logparser.Logparser(accesslog, tokens, toparse, timer)
	x.start_parser(10) # ten times
except:
	print "Parser stopped.."


    Syslog priority levels (high to low):
        LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG.

    THANKS TO:
     * https://stackoverflow.com/questions/8009882/how-to-read-large-file-line-by-line-in-python
     * https://docs.python.org/2/library/syslog.html
     * https://github.com/bgreenlee/pygtail
     * https://github.com/rory/apache-log-parser
    TODO:
     * https://stackoverflow.com/questions/3389574/check-if-multiple-strings-exist-in-another-string

"""

from pygtail import Pygtail
import sys
import apache_log_parser
from pprint import pprint
import syslog
import time
import os.path

class Logparser:
	'Parser class...'
	
	def __init__(self, accesslog, tokenfile, parser, timelimit):
		'Init'
		try:
			self.accesslog = str(accesslog)
			self.tokenfile = str(tokenfile)
			self.parser = str(parser)
			self.TIME_LIMIT = int(timelimit)
		except ValueError as v:
			print v

		if self.TIME_LIMIT <= 1:
			self.TIME_LIMIT = 1 # time to wait between rounds unless the round takes more than this..

		try:
			fp = open(self.accesslog) 
		except IOError as e:
			print e
			exit()
		try:
			fp = open(self.tokenfile)
		except IOError as e:
			print e
			exit()


	def parse(self):
		'Parsing the stuff'
		start = time.clock()
		try:
			for line in Pygtail(self.accesslog):
				line_parser = apache_log_parser.make_parser(self.parser)
				log_line_data = line_parser(line)
				with open(self.tokenfile) as f:
					for token in f:
						if token.strip() in log_line_data['request_url']:
							#pprint(log_line_data)
							syslog.syslog(syslog.LOG_ALERT, "Decoytoken '" + token.strip() + "' accessed from " + log_line_data['remote_host'] + " at " + log_line_data['time_received'] + ":")
							syslog.syslog(syslog.LOG_ALERT, line.strip())	
		except ValueError as v:
			print v
		except IOError as e:
			print e
			exit() # if someone deletes files or changes permissions of them during the run
		end = time.clock()
		if (end - start) < self.TIME_LIMIT:
			time.sleep(self.TIME_LIMIT)
		
		
	def start_parser(self, checks):
		'Starting the parser'
		if checks <= 0:
			while True:
				self.parse()
		else:
			for i in xrange(0, checks):
				self.parse()

