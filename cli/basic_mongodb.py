#!/usr/bin/python

import sys
import logging
logging.basicConfig(level=logging.WARNING)

from  gridfs  import GridFS
import hpfeeds
import pymongo
import ast
import datetime
import md5
from ConfigParser import ConfigParser

config=ConfigParser()
CONFIGFILE = "config.cfg"
config.read(CONFIGFILE)
HOST=config.get("hpfeeds","HOST")
PORT=config.get("hpfeeds","PORT")
IDENT=config.get("hpfeeds","IDENT")			
SECRET=config.get("hpfeeds","SECRET")
CHANNELS = ['dionaea.connections', 'geoloc.events','dionaea.dcerpcrequests','dionaea.shellcodeprofiles','mwbinary.dionaea.sensorunique','dionaea.capture']
	
MONGOHOST=config.get("database","MONGOHOST")	
MONGOPORT=config.get("database","MONGOPORT")
MONGODBNAME=config.get("database","MONGODBNAME")	
MONGOUSER=config.get("database","MONGOUSER")	
MONGOPWD=config.get("database","MONGOPWD")
	
def get_db(host, port, name, user = '', passwd = ''):
        dbconn = pymongo.Connection(host, port)
        db = pymongo.database.Database(dbconn, name)
	if user != '' or passwd != '':
        	db.authenticate(user, passwd)
        return db

def main():
	
	hpc = hpfeeds.new(str(HOST), int(PORT), str(IDENT), str(SECRET))
	print >>sys.stderr, 'connected to', hpc.brokername

	db = get_db(str(MONGOHOST), int(MONGOPORT), str(MONGODBNAME), str(MONGOUSER), str(MONGOPWD))
	collection = None

	def on_message(identifier, channel, payload):
		if channel == 'dionaea.connections':
			try:
				msg = ast.literal_eval(str(payload))
			except:
				print 'exception processing dionaea.connections event', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print msg
				msg['remote_port'] = int(msg['remote_port'])
				msg['local_port'] = int(msg['local_port'])
				print 'inserting...', msg
				collection = db['dionaea.connections']
				collection.insert(msg)
		elif channel == 'geoloc.events':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing geoloc.events', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection =  db['geoloc.events']
				collection.insert(msg)
		elif channel == 'dionaea.dcerpcrequests':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.dcerpcrequests', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.dcerpcrequests']
				collection.insert(msg)
		elif channel == 'dionaea.shellcodeprofiles':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.shellcodeprofiles', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.shellcodeprofiles']
				collection.insert(msg)
		elif channel == 'mwbinary.dionaea.sensorunique' :
			try:
				payload_python = str(payload)
			except:
				print 'exception processing mwbinary.dionaea.sensorunique', repr(payload)
			else:
				hash = md5.new()
				hash.update(payload_python)
				msg = hash.hexdigest()
				print 'inserting mwbinary...', msg
				gfsDate=GridFS(db,'dionaea.sensorunique')
				gfsDate.put(payload_python,filename=msg)
		elif channel == 'dionaea.capture':
			try:
				payload_python = str(payload)
				msg = ast.literal_eval(payload_python.replace("null", "None"))
			except:
				print 'exception processing dionaea.capture', repr(payload)
			else:
				msg["time"] = datetime.datetime.now()
				print 'inserting...', msg
				collection = db['dionaea.capture']
				collection.insert(msg)
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

