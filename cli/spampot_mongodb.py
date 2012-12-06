
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
import md5
import time
import io
import hpfeeds
import pymongo
import ast

# args -g for spam files saved directory
#--host 166.111.132.135 -p 10000 -i 18z4q@hp1 -s a1gl7q7esdp210wz -c spampot_events -g d:\opt\spamfiles

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

def log(msg):
	print '[feedcli] {0}'.format(msg)
	
def get_db(host, port, name, user = '', passwd = ''):
        dbconn = pymongo.Connection(host, port)
        db = pymongo.database.Database(dbconn, name)
	if user != '' or passwd != '':
        	db.authenticate(user, passwd)
        return db

#insertCon=pymongo.Connection(host="localhost",port=27017)
#database=insertCon['spampot']
#collection=database['connections']
#collection.insert(data)

class SpampotBackEndHandler(object):
	
	def __init__(self,db):
		#mongodb
		#self.db = get_db(host, port, name, user , passwd )              
		self.db = db
		self.debug_info = False
		self.attacks=[]
		

		#print 'test'
	#handles
	def handle_spampot_createsession(self,user,ses):
		if self.db is not None:
			if ses['remote_host'] == "127.0.0.1":
				print "remote_host = 127.0.0.1,maybe a test...."
				return
			ses['sendspam_counts'] =0
			ses['end_timestamp'] = datetime.datetime.now()
			self.db['spampot.connections'].insert(ses)	
			#attackid = 122 #ses['_id']
			self.attacks.append(ses['session'])
			
		if self.debug_info ==True:
			print("[%s] %s ->%s" % (ses['session'],ses['remote_host'],ses['local_host']))
			
	def handle_spampot_connectionlost(self,user,ses):
		#session is online
		if ses['session'] in self.attacks:
			#attackid = user.attacks[ses['session']]
			self.attacks.remove(ses['session'])
			if self.db is not None:	
				self.db['spampot.connections'].update({"session" : ses['session']},{'$set':{'sendspam_counts':ses['msg_count'],'end_timestamp':ses['timestamp']} } )
				
		if self.debug_info==True:
			print("[%s] connectionlost,message count is: %s" % (ses['session'],ses['msg_count']))
			
	def handle_spampot_command(self,user,ses):
		if ses['session'] in self.attacks:
			if self.db is not None:
				#attackid = user.attacks[ses['session']]
				self.db['spampot.inputs'].insert(ses)

				if ses['command'] in ["HELO", "EHLO"]:#update connections' remote_hostname
					remote_hostname = ses['data'][4:]
					self.db['spampot.connections'].update({'session':ses['session']}, {'$set':{'remote_hostname':remote_hostname} })

		if self.debug_info==True:
			print("[%s] command:%s" % (ses['session'],ses['command'], ))
			
 	def handle_spampot_relaymail(self,user,ses):
		if ses['session'] in self.attacks:
			#connection = user.attacks[ses['session']][0]
			filename = ses['md5_hash']
			f = base64.b64decode(ses['file'])
			md5_hash = md5.new(f).hexdigest()
			if md5_hash != filename:
				print("[%s] file error %s <-> %s" % ( ses['session'],filename, md5_hash))
			else:
				spamfiles = './spamfiles'
				if spamfiles is not None:
					realdir = writemail(spamfiles,filename, f)                
                
                if self.db is not None:
                    is_probe = False 
                    if ('is_probe' in ses) and (ses['is_probe'] == 'True'):
                       is_probe = True
                    else:
                       is_probe = False
                    
                    ses['to'] = string.replace(ses['to'],"'","\\'")                    
                    ses['to'] = string.replace(ses['to'],'"','\\"')                    
                    tolist =  ses['to'].split(",")
		    dbdata = {}
		    dbdata['connection'] = ses['session']
		    dbdata['spam_md5'] = ses['md5_hash']
		    dbdata['spam_size'] = len(f)
		    dbdata['spam_timestamp'] = ses['timestamp']
		    dbdata['spam_dst'] = realdir
		    dbdata['is_probe'] = is_probe
		    dbdata['spam_count'] = ses['msg_count']
		    dbdata['mail_from'] = ses['from']
		    dbdata['mail_to'] = ses['to']
		    dbdata['mailto_counts'] = len(tolist)
                  
                    self.db['spampot.spams'].insert(dbdata)
		    
   
		    self.db['spampot.connections'].update({'session':ses['session']}, \
				{'$set':{'end_timestamp':dbdata['spam_timestamp'],'sendspam_counts':ses['msg_count']} })
                    #print '77777777777777777777777'
		    del dbdata
		    del ses 
	
	def handle_spampot_proxysurl(self,user,ses):
		if self.debug_info:
			print "proxysurl:",ses
		if self.db is not None:
			oldtarget = ses['old_target']
			i = oldtarget.find(':')   
			oldtarget_port = 80
			if i!=-1 and i > 5:
				oldtarget_port = oldtarget[i+1:]
				
			ses['url'] = oldtarget
			ses['url_port'] = oldtarget_port
			ses['url_counts'] = ses['counts']
			
			del ses['old_target']
			del ses['counts']
			
			self.db['spampot.proxys'].insert(ses)
			
			
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
					
				
def main(opts,action='subscribe'):
	outfd = sys.stdout

	try: hpc = hpfeeds.new(opts.host, opts.port, opts.ident, opts.secret)
	except hpfeeds.FeedException, e:
		log('Error: {0}'.format(e))
		return 1
	
	log('connected to {0}'.format(hpc.brokername))

	if action == 'subscribe':
		
		hander = SpampotBackEndHandler(host='127.0.0.1',port=27017,name='spampot')
	
		def on_message(ident, chan, payload):
			if [i for i in payload[:20] if i not in string.printable]:
				log('publish to {0} by {1}: {2}'.format(chan, ident, payload[:20].encode('hex') + '...'))
			else:
				log('publish to {0} by {1}: {2}----'.format(chan, ident, payload))
				payload_python = str(payload)
				try:
					msg = ast.literal_eval(payload_python.replace("null", "None"))
					hander.process_spampot_message( msg )
				except:
					print "except ast..."
	
		def on_error(payload):
			log('Error message from broker: {0}'.format(payload))
			hpc.stop()
	
		hpc.subscribe(opts.channels)
		try: hpc.run(on_message, on_error)
		except hpfeeds.FeedException, e:
			log('Error: {0}'.format(e))
			return 1

	elif action == 'publish':
		hpc.publish(opts.channels, pubdata)

	elif action == 'sendfile':
		pubfile = open(pubdata, 'rb').read()
		hpc.publish(opts.channels, pubfile)

	log('closing connection.')
	hpc.close()

	return 0
def test2mongodb():
	hander = SpampotBackEndHandler(host='127.0.0.1',port=27017,name='spampot')
	
	paload_list = [
'{"local_host": "202.112.112.249", "protocol": "smtp", "honeypot_name": "spampot", "local_port": "25", "type": "createsession", "remote_port": "49350", "remote_hostname": "", "old_target": "202.112.112.249:25", "session": "2fe46ed012b44105966de64097ca1cc6", "remote_host": "37.59.8.55"}',
'{"type": "command", "honeypot_name": "spampot", "session": "2fe46ed012b44105966de64097ca1cc6", "command": "GET ", "result": "false", "data": "GET http://www.aksarat.pl/cgi-bin/check.rsp?id=1911422&ip=202.112.112.249&port=25 HTTP/1.1"}',
'{"type": "command", "honeypot_name": "spampot", "session": "2fe46ed012b44105966de64097ca1cc6", "command": "HOST", "result": "false", "data": "Host: www.aksarat.pl"}',
'{"type": "command", "honeypot_name": "spampot", "session": "2fe46ed012b44105966de64097ca1cc6", "command": "CONN", "result": "false", "data": "connection: close"}',
'{"msg_count": "0", "session": "2fe46ed012b44105966de64097ca1cc6", "type": "connectionlost", "peername": "37.59.8.55", "honeypot_name": "spampot"}'
]
	for payload_python in paload_list:
		#payload_python='{"local_host": "202.112.112.249", "protocol": "smtp", "honeypot_name": "spampot", "local_port": "25", "type": "createsession", "remote_port": "49350", "remote_hostname": "", "old_target": "202.112.112.249:25", "session": "2fe46ed012b44105966de64097ca1cc6", "remote_host": "37.59.8.55"}'
		msg = ast.literal_eval(payload_python.replace("null", "None"))
		hander.process_spampot_message( msg )
	
def opts():
	usage = "usage: %prog -i ident -s secret --host host -p port -c channel1 [-c channel2, ...] <action> [<data>]"
	parser = optparse.OptionParser(usage=usage)
	parser.add_option("-c", "--chan",
		action="append", dest='channels', nargs=1, type='string',
		help="channel (can be used multiple times)")
	parser.add_option("-i", "--ident",
		action="store", dest='ident', nargs=1, type='string',
		help="authkey identifier")
	parser.add_option("-s", "--secret",
		action="store", dest='secret', nargs=1, type='string',
		help="authkey secret")
	parser.add_option("--host",
		action="store", dest='host', nargs=1, type='string',
		help="broker host")
	parser.add_option("-p", "--port",
		action="store", dest='port', nargs=1, type='int',
		help="broker port")
	parser.add_option("-o", "--output",
		action="store", dest='output', nargs=1, type='string',
		help="publish log filename")
	parser.add_option('-g', '--spamfiles-destination', 
	        dest='spamfiles', help='where to store spam files', 
	        type="string", action="store")

	options, args = parser.parse_args()



	return options,args

if __name__ == '__main__':
	
	#test2mongodb()
	
	options, args = opts()
	try:
		sys.exit(main(options))
	except KeyboardInterrupt:
		sys.exit(0)

