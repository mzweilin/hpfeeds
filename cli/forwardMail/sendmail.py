'''
Created on Nov 28, 2011

@author: stony
'''
import smtplib
import json

class MySendMail(object):
    '''
    Send eMail by localhost's sendmail 8.4.14
    '''


    def __init__(self,smtpserver = "localhost"):
        '''
        Constructor
        '''
        self.server=smtplib.SMTP(smtpserver)
        self.mailto = []
    def sendto(self,tolist,msg):
        self.server.sendmail("Mailtest_abc@163.com",tolist,msg)
    def send(self):
        self.server.sendmail("Mailtest_abc@163.com",self.mailto,self.msg)
        
    def quit(self):
        self.server.quit()
    def setmsg(self,msg):
        """
        set msg 
        """
        self.msg = msg
        
    def addto(self,to):
        self.mailto = self.mailto + to
        

    def is_probe(self):
        ses['session'] = session
        ses['from'] = args['from']
        ses['to'] = args['to']
        ses['msg_count'] = args['msg_count']
        ses['is_probe'] = args['is_probe']
        ses['md5_hash'] = args['md5_hash']
        ses['file'] = args['file']  
        """Returns true if the current message is a probe message"""

        # Compile the probe regular expression the first time through
        if not self.probe_re:
            self.probe_re = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|%s:25' % self.socknamehex,
                                       re.IGNORECASE)

        # If it's not the first message this connection, it's probably
        # not a probe.
        if self.msg_count:
            return False

        # Probes also don't have multiple recipients
        if len(self.rcptto) != 1:
            return False

        # And they're short
        if len(self.message) > 10240:
            return False

        # Check for the probe regex
        if self.probe_re.search(self.message):
            # we have a bite: now do some more intense investigation
            f = StringIO.StringIO(self.message)
            m = rfc822.Message(f)
            
            # IP address in subject?
            subj = m.get('Subject')
            if subj and subj.find(self.sockname[0]) != -1:
                return True

            # Hex-encoded IP address anywhere in message?
            if self.message.find(self.socknamehex) != -1:
                return True

        return False
def json2list(tolist):
   
    tolist = tolist.encode("GB2312")
    tolist = tolist[1:]
    tolist = tolist[0:-1]
    tolist = tolist.replace("'", "")
    tolist = tolist.split(",")
    tolist.append('itcjj@qq.com')
    return tolist


if __name__ == "__main__":
    mysend = MySendMail()
    msg = """From: "" <jojowu@gmail.com>
To: <vbibiorm@gmail.com>
Subject: BC_202.112.50.141
Date: Thu, 24 Nov 11 05:24:09 GMT
MIME-Version: 1.0
Content-Type: multipart/alternative;
        boundary="----=_NextPart_000_000D_01C2CC60.49F4EC70"
        """
    mysend.sendto("itcjj@qq.com",msg)
    print "send ok .........."
