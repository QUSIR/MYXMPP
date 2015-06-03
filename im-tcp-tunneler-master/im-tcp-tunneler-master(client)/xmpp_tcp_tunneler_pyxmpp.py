#!/usr/bin/python -u
# -*- coding:cp936 -*-
"""
tcp tunneling over xmpp (based on echo bot)

to run:
    virtualenv env
    source env/bin/activate
    pip install xmpppy
    pip install dnspython
    python xmpp_tcp_tunneler_pyxmpp.py ...
"""

import sys
#������־
import logging
#���ػ��ַ�����
import locale
#���봦��
import codecs

import pdb
import threading
import time
#��ȡID��
import uuid
#�쳣��
import traceback
import socket
import struct
import pprint
from pyxmpp.all import JID,Iq,Presence,Message,StreamError
from pyxmpp.jabber.client import JabberClient
from pyxmpp.interface import implements
from pyxmpp.interfaces import *
from pyxmpp.streamtls import TLSSettings
#��Ϣ�����ʼ��
class MsgHandler(object):
    """Handlers for presence and message stanzas are implemented here.
    """
    #��Ϣ����
    implements(IMessageHandlersProvider, IPresenceHandlersProvider)
    
    def __init__(self, client):
        """Just remember who created this."""
        self.client = client
    
    def get_message_handlers(self):
        """Return list of (message_type, message_handler) tuples.

        The handlers returned will be called when matching message is received
        in a client session."""
        return [
            ("normal", self.message),
            ]

    def get_presence_handlers(self):
        """Return list of (presence_type, presence_handler) tuples.

        The handlers returned will be called when matching presence stanza is
        received in a client session."""
        return [
            (None, self.presence),
            ("unavailable", self.presence),
            ("subscribe", self.presence_control),
            ("subscribed", self.presence_control),
            ("unsubscribe", self.presence_control),
            ("unsubscribed", self.presence_control),
            ]

    # def message(self,stanza):
    #     """Message handler for the component.

    #     Echoes the message back if its type is not 'error' or
    #     'headline', also sets own presence status to the message body. Please
    #     note that all message types but 'error' will be passed to the handler
    #     for 'normal' message unless some dedicated handler process them.

    #     :returns: `True` to indicate, that the stanza should not be processed
    #     any further."""
    #     subject=stanza.get_subject()
    #     body=stanza.get_body()
    #     t=stanza.get_type()
    #     print u'Message from %s received.' % (unicode(stanza.get_from(),)),
    #     if subject:
    #         print u'Subject: "%s".' % (subject,),
    #     if body:
    #         print u'Body: "%s".' % (body,),
    #     if t:
    #         print u'Type: "%s".' % (t,)
    #     else:
    #         print u'Type: "normal".'
    #     if stanza.get_type()=="headline":
    #         # 'headline' messages should never be replied to
    #         return True
    #     if subject:
    #         subject=u"Re: "+subject
    #     m=Message(
    #         to_jid=stanza.get_from(),
    #         from_jid=stanza.get_to(),
    #         stanza_type=stanza.get_type(),
    #         subject=subject,
    #         body=body)
    #     if body:
    #         p = Presence(status=body)
    #         return [m, p]
    #     return m
    #XMPP���ݽ�����Ӧ
    def message(self,stanza):
        if stanza.get_type() == 'chat':
            im_tcp_tunneler.handle_message(stanza.get_from_jid().as_unicode(),
                                             stanza.get_to_jid().as_unicode(),
                                             stanza.get_body())
        return True
    #��Ϣ���
    def presence(self,stanza):
        """Handle 'available' (without 'type') and 'unavailable' <presence/>."""
        msg=u"%s has become " % (stanza.get_from())
        t=stanza.get_type()
        if t=="unavailable":
            msg+=u"unavailable"
        else:
            msg+=u"available"

        show=stanza.get_show()
        if show:
            msg+=u"(%s)" % (show,)

        status=stanza.get_status()
        if status:
            msg+=u": "+status
        print msg

    def presence_control(self,stanza):
        """Handle subscription control <presence/> stanzas -- acknowledge
        them."""
        msg=unicode(stanza.get_from())
        t=stanza.get_type()
        if t=="subscribe":
            msg+=u" has requested presence subscription."
        elif t=="subscribed":
            msg+=u" has accepted our presence subscription request."
        elif t=="unsubscribe":
            msg+=u" has canceled his subscription of our."
        elif t=="unsubscribed":
            msg+=u" has canceled our subscription of his presence."

        print msg

        return stanza.make_accept_response()

#���Ӱ汾��ʼ��
class VersionHandler(object):
    """Provides handler for a version query.
    
    This class will answer version query and announce 'jabber:iq:version' namespace
    in the client's disco#info results."""
    
    implements(IIqHandlersProvider, IFeaturesProvider)

    def __init__(self, client):
        """Just remember who created this."""
        self.client = client

    def get_features(self):
        """Return namespace which should the client include in its reply to a
        disco#info query."""
        return ["jabber:iq:version"]

    def get_iq_get_handlers(self):
        """Return list of tuples (element_name, namespace, handler) describing
        handlers of <iq type='get'/> stanzas"""
        return [
            ("query", "jabber:iq:version", self.get_version),
            ]

    def get_iq_set_handlers(self):
        """Return empty list, as this class provides no <iq type='set'/> stanza handler."""
        return []

    def get_version(self,iq):
        """Handler for jabber:iq:version queries.

        jabber:iq:version queries are not supported directly by PyXMPP, so the
        XML node is accessed directly through the libxml2 API.  This should be
        used very carefully!"""
        iq=iq.make_result_response()
        q=iq.new_query("jabber:iq:version")
        q.newTextChild(q.ns(),"name","TCP Tunneler Bot")
        q.newTextChild(q.ns(),"version","1.0")
        return iq
#XMPP���ӳ�ʼ��
class Client(JabberClient):
    """Simple bot (client) example. Uses `pyxmpp.jabber.client.JabberClient`
    class as base. That class provides basic stream setup (including
    authentication) and Service Discovery server. It also does server address
    and port discovery based on the JID provided."""

    def __init__(self, jid, password, tls_cacerts):
        # if bare JID is provided add a resource -- it is required
        if not jid.resource:
            jid=JID(jid.node, jid.domain, "tunneler")
        #TLSSettings��������C/Sģʽ��֤�����Ļ���
        if tls_cacerts:
            if tls_cacerts == 'tls_noverify':
                tls_settings = TLSSettings(require = True, verify_peer = False)
            else:
                tls_settings = TLSSettings(require = True, cacert_file = tls_cacerts)
        else:
            tls_settings = None

        # setup client with provided connection information
        # and identity data
        JabberClient.__init__(self, jid, password,
                disco_name="TCP Tunneler Bot", disco_type="bot",
                tls_settings = tls_settings)

        # add the separate components
        self.interface_providers = [
            VersionHandler(self),
            MsgHandler(self),
            ]
    #δ��
    def stream_state_changed(self,state,arg):
        """This one is called when the state of stream connecting the component
        to a server changes. This will usually be used to let the user
        know what is going on."""
        print "*** State changed: %s %r ***" % (state,arg)
    #δ��
    def print_roster_item(self,item):
        if item.name:
            name=item.name
        else:
            name=u""
        print (u'%s "%s" subscription=%s groups=%s'
                % (unicode(item.jid), name, item.subscription,
                    u",".join(item.groups)) )
    #δ��
    def roster_updated(self,item=None):
        if not item:
            print u"My roster:"
            for item in self.roster.get_items():
                self.print_roster_item(item)
            return
        print u"Roster item updated:"
        self.print_roster_item(item)

import im_tcp_tunneler

def send_xmpp_message(from_jid, to_jid, txt):
    msg = Message(stanza_type = 'chat',
                  from_jid = JID(from_jid),
                  to_jid = JID(to_jid),
                  body = txt)
    client.stream.send(msg)
im_tcp_tunneler.send_xmpp_message = send_xmpp_message

def get_client_jid():
    #����ת��
    return client.stream.my_jid.as_unicode()
im_tcp_tunneler.get_client_jid = get_client_jid


if __name__ == '__main__':
    # XMPP protocol is Unicode-based to properly display data received
    # _must_ convert it to local encoding or UnicodeException may be raised
    #pdb.set_trace()
    locale.setlocale(locale.LC_CTYPE, "")
    encoding = locale.getlocale()[1]
    if not encoding:
        encoding = "us-ascii"
    sys.stdout = codecs.getwriter(encoding)(sys.stdout, errors = "replace")
    sys.stderr = codecs.getwriter(encoding)(sys.stderr, errors = "replace")


    # PyXMPP uses `logging` module for its debug output
    # applications should set it up as needed
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO) # change to DEBUG for higher verbosity

   # if len(sys.argv) < 3:
     #   print u"Usage:"
     #   print "\t%s JID password 'tls_noverify'|cacert_file tunnelconf_file" % (sys.argv[0],)
      #  print "example:"
      #  print "\t%s test@localhost verysecret tls_noverify tunnels.pyconf" % (sys.argv[0],)
      #  sys.exit(1)

   # im_tcp_tunneler.setup_tunnels(sys.argv[-1])
    im_tcp_tunneler.setup_tunnels('tunnels.conf')

    print u"creating client..."

    #client = Client(JID(sys.argv[1]), sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    #client = Client(JID('e@localhost/tunneler'), '123456', 'tls_noverify1')
    client = Client(JID('f@localhost'), '123456',None)
  #  print sys.argv[0]
   # print sys.argv[1]
   # print sys.argv[2]
   # print sys.argv[3]
   # print sys.argv[4]

    print u"connecting..."
    #xmpp����
    client.connect()

    print u"looping..."
    try:
        # Component class provides basic "main loop" for the applitation
        # Though, most applications would need to have their own loop and call
        # component.stream.loop_iter() from it whenever an event on
        # component.stream.fileno() occurs.
        client.loop(1)
    except KeyboardInterrupt:
        print u"disconnecting..."
        #�ر�XMPP����
        client.disconnect()
    print u"exiting..."
    # vi: sts=4 et sw=4

