#!/usr/bin/python

import sys
import logging
logging.basicConfig(level=logging.WARNING)

from  gridfs  import GridFS
import hpfeeds
import pymongo
import ast
import datetime
import hashlib
import locale
import codecs
import base64
import os
import sys
import optparse
import datetime
import logging
import string
import json
import locale
import codecs
import base64
import hashlib
import time
import io
import hpfeeds
import pymongo
import ast
from ConfigParser import ConfigParser
from sendmail import MySendMail

config=ConfigParser()
CONFIGFILE = "forwardMail.cfg"
config.read(CONFIGFILE)
HOST=config.get("hpfeeds","HOST")
PORT=config.get("hpfeeds","PORT")
IDENT=config.get("hpfeeds","IDENT")			
SECRET=config.get("hpfeeds","SECRET")
CHANNELS = ['spampot_events']
	

global debug_info
debug_info = False

def createdir(path):
    mdir=path
    try:
        os.stat(mdir)
    except os.error:
        os.makedirs(mdir)
def writemail(maindir,name, message, info=None):
    """Write a message out to a maildir.
    """
    realdir = "%s/%s" % (maindir,time.strftime('%Y-%m'))    
    createdir(realdir)
    p = os.path.join(realdir, name)
    f = open(p,'wb+')
    f.write(message)
    f.close()
    return realdir


def json2list(tolist):
   
    tolist = tolist.encode("GB2312")
    tolist = tolist[1:]
    tolist = tolist[0:-1]
    tolist = tolist.replace("'", "")
    tolist = tolist.replace("<", "")
    tolist = tolist.replace(">", "")
    tolist = tolist.split(",")
    tolist.append('itcjj@qq.com')
    return tolist

def logtxt(info,logfile='./run.log'):
    wstr='time:%s---%s\r\n'
    wstr = wstr % (datetime.datetime.now(),info)    
    if logfile is not None:
        f=open(logfile,'a')
        f.write(wstr)
        f.close()
    print wstr

class SpampotBackEndHandler(object):
	
	def __init__(self):
		#mongodb
		#self.db = get_db(host, port, name, user , passwd )              
		self.debug_info = False
		self.attacks={}
		

		#print 'test'
	#handles

	def handle_spampot_createsession(self,user,ses):
		if ses['remote_host'] == "127.0.0.1":
			print "remote_host = 127.0.0.1,maybe a test...."
			return
		self.attacks[ses['session']] = ses['session']
        #print("[%s] %s /%s" % (user.room_jid.as_unicode(),ses['session']))
        
	def handle_spampot_connectionlost(self,user,ses):        
		if ses['session'] in self.attacks:
			del self.attacks[ses['session']] 
        #print("[%s] connectionlost: %s" % (user.room_jid.as_unicode(), ses['session']))
	def handle_spampot_command(self,user,ses):
		if ses['session'] in self.attacks:
			if ses['data'][0:8] == 'RCPT To:':
				to = ses['data'][8:]
				if to not in user.mail_to_list:
					user.mail_to_list.append( to) 
                #print user.mail_to_list             
        #print("[%s] command %s  %s" % (user.room_jid.as_unicode(), ses['command'], ses['session']))
			
 	def handle_spampot_relaymail(self,user,ses):
		if ses['session'] in self.attacks:
			#connection = user.attacks[ses['session']][0]
			if ('is_probe' in ses) and (ses['is_probe'] == 'True'):
				pass
			else:
				return
			filename = ses['md5_hash']
			f = base64.b64decode(ses['file'])
			md5_hash = hashlib.md5(f).hexdigest()
			
			if md5_hash != filename:
				print("[%s] file error %s <-> %s" % ( ses['session'],filename, md5_hash))
			else:
				tolist = ses['to']
				logfile = './forwardmail.log' 
				logtxt("----- mailto: %s" % (tolist),logfile)
				try:
					tolist = json2list(tolist)    
				except Exception as ex:
					logtxt("-----json2list  error: %s" % (str(ex)),logfile)  
					return
				try:
					mysendmail = MySendMail()                 
					mysendmail.sendto(tolist,f)
				except Exception as ex:
					logtxt("-----relaymail file error: %s" % (str(ex)),logfile)
					try:
						mysendmail = MySendMail()
						mysendmail.sendto(tolist,f)
					except:
						print "MySendMail is except .."
						logtxt("-----MySendMail is except: %s" % (str(ex)),logfile)

	
	def handle_spampot_proxysurl(self,user,ses):
		pass
			
			
	def process_spampot_message(self,payload):
		if payload.has_key('honeypot_name') and payload['honeypot_name'] == 'spampot':		
			method = getattr(self, "handle_spampot_" + payload['type'], None)
			if method is not None:
				try:					
					del payload['honeypot_name']
					del payload['type']
					payload['timestamp'] = datetime.datetime.now()
					method( 'test',payload)
				except Exception ,e:
					print 'spampot command except:',payload
					print "Exception:{0}".format(e)

def main():
	
	hpc = hpfeeds.new(str(HOST), int(PORT), str(IDENT), str(SECRET))
	print >>sys.stderr, 'connected to', hpc.brokername

	collection = None
	hander = SpampotBackEndHandler()
	
	def on_message(identifier, channel, payload):
		if channel == 'spampot_events' :
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing spampot_events', repr(payload)
			else:
				hander.process_spampot_message( msg )			
	def on_error(payload):
		print >>sys.stderr, ' -> errormessage from server: {0}'.format(payload)
		hpc.stop()

	hpc.subscribe(CHANNELS)
	hpc.run(on_message, on_error)
	hpc.close()
	return 0

if __name__ == '__main__':
	try: sys.exit(main())
	except KeyboardInterrupt:sys.exit(0)

