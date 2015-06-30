#!/usr/bin/env python -u
# vim: ts=8 sts=4 sw=4
import re
import repoze.lru
import collections
import time
import syslog
import sys

DEBUG=False
OUTFILE='/var/log/arcsight/ldapout.log'
DEBUGFILE='/tmp/ldap-debug'

def debug(message):
    if DEBUG:
        with open(DEBUGFILE, "a") as debugfile:
            debugfile.write("{}\n".format(message))


class LDAPConnection(object):
    """This will hold the connection info found by LDAPProcessor"""
    __slots__ = ('address', 'bind_dn', 'new_bind_dn', 'last_op', 'op_subject')
    def __init__(self, address):
        self.address = address
        self.bind_dn = None
        self.new_bind_dn = None
        self.last_op = None
        self.op_subject = None

class LDAPLogger(object):
    EVENT_BIND = 1
    EVENT_MODIFY = 2
    EVENT_ADD = 3
    EVENT_DELETE = 4
    EVENT_NAMES = {EVENT_BIND: 'BIND', EVENT_MODIFY: 'MODIFY', EVENT_ADD: 'ADD', EVENT_DELETE: 'DELETE'}

    def format_message(self, connection_id, event_id, connection, attributes):
        return """CEF:0|mozilla|openldap|1.0|{event_id}|{event_name}|6|src={src} spt={spt} suser={user} cs1=\"{bind_name}\" cs1Label=BindDN  outcome={outcome} cs2=\"{subject_dn}\" cs2Label=SubjectDN cn1={conn_id} cn1Label=ConnId cn2={err} cn2Label=LdapCode end={end}\n""".format(
                conn_id = connection_id,
                event_id = event_id,
                event_name = self.EVENT_NAMES.get(event_id, ''),
                err = attributes['err'],
                outcome = attributes['outcome'],
                src = attributes['src'],
                spt = attributes['spt'],
                bind_name = connection.bind_dn,
                subject_dn = connection.op_subject,
                user = connection.bind_dn,
                end = str(time.time())
                )

class FileLogger(LDAPLogger):
    def __init__(self, filename):
        self._filename = filename
    def __call__(self, connection_id, event_id, connection, attributes):
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|[Extension]
        with open(self._filename, "a") as outputfile:
            outputfile.write(self.format_message(connection_id, event_id, connection, attributes))

class SyslogLogger(LDAPLogger):
    def __init__(self, ident):
        syslog.openlog(ident)
    def __call__(self, connection_id, event_id, connection, attributes):
        syslog.syslog(self.format_message(connection_id, event_id, connection, attributes))

class LDAPProcessor(object):
    """Main processor, process_message will get called for each line of stdin
    
    Stuff will be kept in a lru cache
    """
    LRU_CONN_CACHE_SIZE = 65536
    LRU_CONN_CACHE_TIMEOUT = 24*60*60

    ldap_message_re = re.compile('conn=(?P<conn>\d+) (?:op|fd)=\d+ (?P<command>\S+)(?P<attributes> ?.*)')
    ldap_attributes_re = re.compile(' (?P<key>[^ =]+)(?:=(?P<value>"([^"\\\\]|\\\\.)*"|\S+))?')
    quoted_re = re.compile('\\\\(.)')

    OUTCOME_FAILURE = 'failure'
    OUTCOME_SUCCESS = 'success'

    def __init__(self, logger):
        self._connections = repoze.lru.ExpiringLRUCache(self.LRU_CONN_CACHE_SIZE, self.LRU_CONN_CACHE_TIMEOUT)
        self._logger = logger

    def cef_log(self, connection_id, event_id, connection, attributes):
        """Will get called if we have a matching log"""
        err = attributes.get('err', '')
        attributes['outcome'] = self.OUTCOME_SUCCESS if err == '0' else self.OUTCOME_FAILURE
        try:
            attributes['src'], attributes['spt'] = connection.address.split(':')
        except ValueError:
            attributes['src'] = attributes['spt'] = ''
        self._logger(connection_id, event_id, connection, attributes)

    def process_message(self, server, message):
        """Line by line call"""
        message_match = self.ldap_message_re.match(message)
        if message_match:
            def dequote(s):
                if s:
                    if s[0] == '"' and s[-1] == '"':
                        return self.quoted_re.sub('\\1', s[1:-1])
                    else:
                        return s
            attributes = dict([(m.group('key'), dequote(m.group('value'))) for m in self.ldap_attributes_re.finditer(message_match.group('attributes'))])
            command = message_match.group('command')
            connection_id = int(message_match.group('conn'))
            cache_key = "{}:{}".format(server,connection_id)
            if command == 'ACCEPT':
                self._connections.put(cache_key, LDAPConnection(attributes['IP']))
            elif command == 'closed':
                self._connections.invalidate(cache_key)
            else:
                connection = self._connections.get(cache_key)
                if not connection:
                    if DEBUG:
                        debug("No connection id for {}".format(message))
                else:
                    if command == 'BIND':
                        if 'anonymous' in attributes:
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
                            self.cef_log(connection_id, LDAPLogger.EVENT_BIND, connection, attributes)
                        elif connection.last_op == 'DEL':
                            self.cef_log(connection_id, LDAPLogger.EVENT_DELETE, connection, attributes)
                        elif connection.last_op == 'ADD':
                            self.cef_log(connection_id, LDAPLogger.EVENT_ADD, connection, attributes)
                        elif connection.last_op == 'MOD':
                            self.cef_log(connection_id, LDAPLogger.EVENT_MODIFY, connection, attributes)
                    elif command == 'UNBIND':
                        connection.bind_dn = None

                    connection.last_op = command
        else:
            # No message match
            if DEBUG:
                debug("NOMSGMATCH {}".format(message))

if __name__ == '__main__':
    """Strip date and get message, forward to process_message when there is still stdin"""
    # Jun 23 08:34:59 aa-ldap-aaaa2 slapd[2197]: conn=1022
    ldap_syslog_re = re.compile('[a-z]{3} +\d+ \d{2}:\d{2}:\d{2} (?P<server>[\w-]+) slapd\[\d+\]: (?P<message>.*)', re.I)
    processor = LDAPProcessor(FileLogger(OUTFILE))
    while True:
        line = sys.stdin.readline().rstrip()
        if line == '': break
        m = ldap_syslog_re.match(line)
        if m:
            processor.process_message(m.group('server'),m.group('message'))
        else:
            if DEBUG:
                debug("UNPARSED: {}".format(line))
