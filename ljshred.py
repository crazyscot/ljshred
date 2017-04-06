#!/usr/bin/python
# Written for Python 2.7

import xmlrpclib
import getpass
import sys
import hashlib
import argparse
import yaml
import re
import string
import random

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
    def __init__(self, login=None, password=None, verbose=True, debug=False, cleartext_password=False):
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
        self._hpassword = md5_hex(password)
        self._do_challenge_response = not cleartext_password

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
            response = md5_hex(challdict['challenge'] + self._hpassword)
            args.update({'auth_method':'challenge', 'auth_challenge':challdict['challenge'], 'auth_response':response})
        else:
            # Fall back to cleartext
            args.update({'auth_method':'clear', 'hpassword':self._hpassword})

        args.update({'username': self._login, 'ver':1})
        # TODO: enhancement: Use a session cookie
        return args


def print_entry(lj,event):
    ''' Callback which prints out basic information about each entry '''
    try:
        subject=event['subject']
    except KeyError:
        subject='<no subject>'
    print '  #%u %s %s' % (event['itemid'], event['eventtime'], subject)

def xmlrpc_to_unicode(xm):
    '''
        Converts a str or xmlrpc.Binary into a unicode string.
        (xmlrpc might pass us either.)
    '''
    if xm.__class__ is 's'.__class__:
        xm = unicode(xm)
    elif xm.__class__ is xmlrpclib.Binary: # unicode, utf-8 encoded
        xm = xm.data.decode('utf-8')
    else:
        raise TypeError('Data is unknown type %s'%xm.__class__)
    return xm

def entry_to_blocks(lj,event):
    '''
    Callback which replaces all the text in an item with solid-block glyphs
    (U+2588)
    '''
    text = xmlrpc_to_unicode(event['event'])
    text = re.sub(r"\S", unichr(0x2588), text, flags=re.UNICODE)
    args = {
        'itemid': event['itemid'],
        'event': text,
        'lineendings':'\n',
        }

    try:
        subject = xmlrpc_to_unicode(event['subject'])
        subject = re.sub(r"\S", unichr(0x2588), subject, flags=re.UNICODE)
        args['subject'] = subject
    except KeyError: # subject not in entry
        pass

    for kw in ['allowmask', 'props', 'security']:
        if kw in event:
            args[kw] = event[kw]
    lj.server.LJ.XMLRPC.editevent(lj.auth_headers(args))
    # response data ignored

GARBAGE = string.letters + string.digits

def garbagify(s):
    ''' Replaces all the non-whitespace in a string with garbage '''
    s = re.sub(r"\S", '?', s, flags=re.UNICODE)
    rv = ''.join([ (random.choice(GARBAGE) if c=='?' else c) for c in s ])
    return str(rv)


def entry_to_garbage(lj,event):
    '''
    Callback which replaces all the text in an item with random garbage
    (U+2588)
    '''
    args = {
        'itemid': event['itemid'],
        'event': garbagify(xmlrpc_to_unicode(event['event'])),
        'lineendings':'\n',
        }

    try:
        args['subject'] = garbagify(xmlrpc_to_unicode(event['subject']))
    except KeyError: # subject not in entry
        pass

    for kw in ['allowmask', 'props', 'security']:
        if kw in event:
            args[kw] = event[kw]
    lj.server.LJ.XMLRPC.editevent(lj.auth_headers(args))
    # response data ignored

def walk_entries(lj, callback=print_entry, include_the_last_one=True):
    '''
    Enumerates all the entries for a journal, day by day, and calls a
    callback to do something to each of them
    '''

    response = lj.server.LJ.XMLRPC.getdaycounts(lj.auth_headers({'mode':'getdaycounts'}))
    total = sum([record['count'] for record in response['daycounts']])
    print 'There are %u entries' % total
    # Now enumerate entries per day
    prev = None
    for record in response['daycounts']:
        date = record['date']
        print '%s has %d entries' %(date, record['count'])
        (year, month, day) = date.split('-')
        evts = lj.server.LJ.XMLRPC.getevents(lj.auth_headers({'selecttype':'day', 'year':year,'month':month,'day':day}))
        for event in evts['events']:
            if prev is not None:
                callback(lj, prev)
            prev = event
    if include_the_last_one:
        callback(lj,event)

def ljshred_main(testfile=None, action_callback=print_entry, cleartext_password=False, except_latest=True):
    ''' The main part of the program, after the argument parsing '''
    # Default, if no mode specified, is just to print:
    if action_callback is None:
        action_callback=print_entry
    loginargs = {'cleartext_password':cleartext_password}
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
    walk_entries(lj, action_callback, not except_latest)

# TODO safety check user is about to overwrite / delete journal entries...

def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(
            description='Shreds all the entries in a LiveJournal.',
            epilog='This program is DANGEROUS and IRREVERSIBLE. Use at your own risk.')
    parser.add_argument('-t','--testfile', action='store', dest='testfile', help=argparse.SUPPRESS)
    parser.add_argument('--cleartext_password', action='store_true', help='Sends the password in (nearly) clear text, which is faster but less secure')
    parser.add_argument('--except-latest', action='store_true', help='Doesn\'t affect the latest entry')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--printout', dest='action_callback', action='store_const', const=print_entry, help='Only prints out all the entries it would touch, doesn\'t actually change anything.')
    group.add_argument('--block-out', dest='action_callback', action='store_const', const=entry_to_blocks, help='Replaces all non-whitespace text in all entries with a solid block character')
    group.add_argument('--random-garbage', dest='action_callback', action='store_const', const=entry_to_garbage, help='Replaces entries with random garbage text')

    return vars(parser.parse_args(args))

if __name__ == '__main__':
    try:
        ljshred_main(**parse_args())
    except LJError as e:
        print e

