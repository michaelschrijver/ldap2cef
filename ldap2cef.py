#!/usr/bin/env python -u
# vim: ts=8 sts=4 sw=4
import re
import repoze.lru
import collections
import time
import syslog
import sys

class LDAPConnection(object):
    __slots__ = ('address', 'bind_dn', 'new_bind_dn', 'last_op', 'op_subject')
    def __init__(self, address):
        self.address = address 
        self.bind_dn = None
        self.new_bind_dn = None
        self.last_op = None
        self.op_subject = None

class LDAPProcessor(object):
    LRU_CONN_CACHE_SIZE = 65536
    LRU_CONN_CACHE_TIMEOUT = 24*60*60

    ldap_message_re = re.compile('conn=(?P<conn>\d+) (?:op|fd)=\d+ (?P<command>\S+)(?P<attributes> .*)')
    ldap_attributes_re = re.compile(' (?P<key>[^ =]+)(?:=(?P<value>\S+|"[^"]*"))?')

    def __init__(self):
        self._connections = repoze.lru.ExpiringLRUCache(self.LRU_CONN_CACHE_SIZE, self.LRU_CONN_CACHE_TIMEOUT)
        self._operations = repoze.lru.ExpiringLRUCache(self.LRU_CONN_CACHE_SIZE * 5, 3600)

    EVENT_BIND = 1
    EVENT_MODIFY = 2
    EVENT_ADD = 3
    EVENT_DELETE = 4
    EVENT_NAMES = {EVENT_BIND: 'BIND', EVENT_MODIFY: 'MODIFY', EVENT_ADD: 'ADD', EVENT_DELETE: 'DELETE'}

    OUTCOME_FAILURE = 'failure'
    OUTCOME_SUCCESS = 'success'

    def cef_log(self, connection_id, event_id, connection, attributes):
        err = attributes.get('err', '')
        outcome = self.OUTCOME_SUCCESS if err == '0' else self.OUTCOME_FAILURE
        try: src, spt = connection.address.split(':')
        except ValueError: src = spt = ''

        # XXX
        print """CEF:0|mozilla|openldap|1.0|{event_id}|{event_name}|6|src={src} spt={spt} cs1=\"{bind_name}\" suser={user} outcome={outcome} cs1Label=BindDN cn1={conn_id} cs2Label=SubjectDN cs2=\"{subject_dn}\" cn1Label=ConnId cn2={err} cn2Label=LdapCode end={end}""".format(
                conn_id = connection_id,
                event_id = event_id,
                event_name = self.EVENT_NAMES.get(event_id, ''),
                err = err,
                outcome = outcome,
                src = src,
                spt = spt,
                bind_name = connection.bind_dn,
                subject_dn = connection.op_subject,
                user = connection.bind_dn,
                end = str(time.time())
                )

    def process_message(self, message):
        message_match = self.ldap_message_re.match(message)
        if message_match:
            def dequote(s):
                if s:
                        # XXX
                        if s[0] == '"' and s[-1] == '"':
                            return s[1:-1]
                        else:
                            return s
            attributes = dict([(m.group('key'), dequote(m.group('value'))) for m in self.ldap_attributes_re.finditer(message_match.group('attributes'))])
            command = message_match.group('command')
            connection_id = int(message_match.group('conn'))
            if command == 'ACCEPT':
                self._connections.put(connection_id, LDAPConnection(attributes['IP']))
            elif command == 'closed':
                self._connections.invalidate(connection_id)
            else:
                connection = self._connections.get(connection_id)
                if not connection:
                    pass # XXX log error
                else:
                    if command == 'BIND':
                        if attributes.has_key('anonymous'):
                            connection.new_bind_dn = 'ANONYMOUS'
                        else:
                            connection.new_bind_dn = attributes['dn']
                    elif command in ('MOD', 'DEL', 'ADD'):
                        if attributes.has_key('dn'):
                            connection.op_subject = attributes['dn']
                    elif command in ('RESULT', 'SEARCH'): # SEARCH really is 'SEARCH RESULT'
                        if connection.last_op == 'BIND':
                            if attributes['err'] == '0':
                                # bind succeeded, assume new identity
                                connection.bind_dn = connection.new_bind_dn
                            self.cef_log(connection_id, self.EVENT_BIND, connection, attributes)
                        elif connection.last_op == 'DEL':
                            self.cef_log(connection_id, self.EVENT_DELETE, connection, attributes)
                        elif connection.last_op == 'ADD':
                            self.cef_log(connection_id, self.EVENT_ADD, connection, attributes)
                        elif connection.last_op == 'MOD':
                            self.cef_log(connection_id, self.EVENT_MODIFY, connection, attributes)
                    elif command == 'UNBIND':
                        connection.bind_dn = None

                    connection.last_op = command

if __name__ == '__main__':
    """Strip date and get message, forward to process_message when there is still stdin"""
    ldap_syslog_re = re.compile('[a-z]{3} +\d+ \d{2}:\d{2}:\d{2} [\w-]+ slapd\[\d+\]: (?P<message>.*)', re.I)
    processor = LDAPProcessor()
    while True:
        line = sys.stdin.readline().rstrip()
        if line == '': break
        m = ldap_syslog_re.match(line)
        if m:
            processor.process_message(m.group('message'))
