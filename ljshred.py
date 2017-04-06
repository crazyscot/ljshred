#!/usr/bin/python
# Written for Python 2.7

import xmlrpclib
import getpass
import sys
import hashlib
import argparse
import yaml

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
            rv = self.server.LJ.XMLRPC.login(self.auth_headers({'clientversion':'shred/0.01'}, verbose=verbose))
        except xmlrpclib.Fault as f:
            raise LJError(f)
        # Succeeded

    def auth_headers(self, args={}, verbose=False):
        '''
        Add LJ authentication headers (arguments? parameters?) to a given XMLRPC request dictionary.
        Does a challenge round-trip if it can.
        '''
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


def print_entry(lj,event):
    ''' Callback which prints out basic information about each entry '''
    try:
        subject=event['subject']
    except KeyError:
        subject='<no subject>'
    print '  #%u %s %s' % (event['itemid'], event['eventtime'], subject)


def walk_entries(lj, callback=print_entry):
    '''
    Enumerates all the entries for a journal, day by day, and calls a
    callback to do something to each of them
    '''

    response = lj.server.LJ.XMLRPC.getdaycounts(lj.auth_headers({'mode':'getdaycounts'}))
    total = sum([record['count'] for record in response['daycounts']])
    print 'There are %u entries' % total
    # Now enumerate entries per day
    for record in response['daycounts']:
        date = record['date']
        print '%s has %d entries:' %(date, record['count'])
        (year, month, day) = date.split('-')
        evts = lj.server.LJ.XMLRPC.getevents(lj.auth_headers({'selecttype':'day', 'year':year,'month':month,'day':day}))
        for event in evts['events']:
            callback(lj,event)

def ljshred_main(testfile=None):
    ''' The main part of the program, after the argument parsing '''
    loginargs = {}
    if testfile is not None:
        # Attempt to read login data from file.. This is only really intended for testing.
        try:
            with open(testfile, 'r') as f:
                try:
                    loginargs.update(yaml.load(f))
                    print 'Logging in as %s with credentials from file'%loginargs['login']
                except yaml.YAMLError as e:
                    print e
                    return 5
        except IOError as e:
            print e
            return 5

    lj = LJSession(**loginargs)
    walk_entries(lj)

# 1. What to do (delete, empty, lipsumise, blockout)
# 2. Whether to leave the last

# TODO safety check user is about to overwrite / delete journal entries...

def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--testfile', action='store', dest='testfile')
    return vars(parser.parse_args(args))

if __name__ == '__main__':
    try:
        ljshred_main(**parse_args())
    except LJError as e:
        print e

