#!/usr/bin/python
# Written for Python 2.7

import xmlrpclib
import getpass
import sys
import hashlib

SITE='livejournal.com'
URL='https://www.'+SITE+'/interface/xmlrpc'

class LJError(Exception):
    def __init__(self, wrapped):
        self.exception = wrapped
    def __str__(self):
        return 'Error talking to server: %s' % self.exception

def md5_hex(s):
    ''' MD5 hex digest, as used by LJ challenge-response authentication '''
    return hashlib.md5(s).hexdigest()

class LJSession:
    def __init__(self, login=None, password=None, verbose=True, debug=False):
        '''
        Connect and authenticate to LJ.
        Uses challenge-response authentication if possible, falling back to
        cleartext if not.
        Prompts for login and password if not provided as arguments.

        On successful return, this object has a 'server' object you can use
        to talk to the server.
        For each transaction, call auth_headers() to add the authentication
        parameters.
        '''
        if login is None:
            login = raw_input('Username on '+SITE+': ')
        if password is None:
            password = getpass.getpass()
        self._login = login
        self._password = password
        self._do_challenge_response = True

        self.server = xmlrpclib.ServerProxy(URL, verbose=debug)

        try:
            rv = self.server.LJ.XMLRPC.login(self.auth_headers({'clientversion':'shred/0.01'}))
        except xmlrpclib.Fault as f:
            raise LJError(f)
        # Succeeded

    def auth_headers(self, args={}, verbose=False, debug=False):
        challdict = None
        try:
            if self._do_challenge_response:
                challdict = self.server.LJ.XMLRPC.getchallenge()
        except xmlrpclib.Fault as f:
            if verbose:
                print 'Server didn\'t like getchallenge, falling back to cleartext'
            self._do_challenge_response = False

        if challdict and challdict['auth_scheme'] != 'c0':
            if verbose:
                print 'Server responded with unknown auth_scheme %s, falling back to cleartext' % challdict['auth_scheme']
            challdict = None
            self._do_challenge_response = False

        if self._do_challenge_response:
            if verbose:
                print 'Using challenge-response'
            response = md5_hex(challdict['challenge'] + md5_hex(self._password))
            args.update({'auth_method':'challenge', 'auth_challenge':challdict['challenge'], 'auth_response':response})
        else:
            # Fall back to cleartext
            args.update({'auth_method':'clear', 'password':self._password})

        args.update({'username': self._login, 'ver':1})
        # Possible enhancement: Use a session cookie
        return args

def walk_entries(lj):
    response = lj.server.LJ.XMLRPC.getdaycounts(lj.auth_headers({'mode':'getdaycounts'}))
    total = sum([record['count'] for record in response['daycounts']])
    print 'Total %u entries' % total

def realmain():
    lj = LJSession()
    print lj.server.LJ.XMLRPC.getevents(lj.auth_headers({'selecttype':'syncitems','lastsync':'1970-01-01 00:00:00'}))
# CLI options: (sys.argv)
    walk_entries(lj)

# 1. What to do (delete, empty, lipsumise, blockout)
# 2. Whether to leave the last

# TODO safety check user is about to overwrite / delete journal entries...

if __name__ == '__main__':
    try:
        realmain()
    except LJError as e:
        print e

