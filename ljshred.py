#!/usr/bin/python
# ljshred: Tool to actively shred the content of a LiveJournal.
# Run with `--help' for detailed options.
# Written for Python 2.7

# This program is DANGEROUS and IRREVERSIBLE. Use at your own risk.


# BSD 3-Clause License
#
# Copyright (c) 2017, Ross Younger.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import xmlrpclib
import getpass
import sys
import hashlib
import argparse
import yaml
import re
import string
import random
import time

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
    VALID_ARGS=['login', 'password', 'verbose', 'debug', 'cleartext_password']
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
        Converts data received from xmlrpc into a unicode string.
        (xmlrpc might pass us a str, a Binary or even an int...)
    '''
    if xm.__class__ is xmlrpclib.Binary: # unicode, utf-8 encoded
        xm = xm.data.decode('utf-8')
    else:
        xm = unicode(xm)
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
    return rv.encode('utf-8')


def entry_to_garbage(lj,event):
    '''
    Callback which replaces all the text in an item with random garbage
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

MIXED_MODE_MODELIST=[entry_to_garbage, entry_to_blocks]

def mixed_mode(lj,event):
    ''' Randomly calls on to another mode '''
    return random.choice(MIXED_MODE_MODELIST)(lj,event)

def delete_entry(lj,event):
    '''
    Callback which deletes entry
    '''
    args = {
        'itemid': event['itemid'],
        'event': '',
        'lineendings':'\n',
        }

    # For good practise we will propagate security settings, even though the entry should be deleted.
    for kw in ['allowmask', 'props', 'security']:
        if kw in event:
            args[kw] = event[kw]
    lj.server.LJ.XMLRPC.editevent(lj.auth_headers(args))
    # response data ignored


def walk_entries(lj, callback=print_entry, include_the_last_one=True, start_date=None, end_date=None, throttle_time=3):
    '''
    Enumerates all the entries for a journal, day by day, and calls a
    callback to do something to each of them
    '''

    try:
        throttle_time=float(throttle_time)
    except TypeError:
        throttle_time=3.0

    response = lj.server.LJ.XMLRPC.getdaycounts(lj.auth_headers({'mode':'getdaycounts'}))
    total = sum([record['count'] for record in response['daycounts']])
    if total is 1:
        print 'There is 1 entry'
    else:
        print 'There are %u entries' % total
    # Now enumerate entries per day
    prev = None
    for record in response['daycounts']:
        date = record['date']
        if start_date is not None and start_date > date:
            continue
        if end_date is not None and date > end_date:
            continue
        print '%s has %d entr%s' %(date, record['count'], 'y' if record['count']==1 else 'ies')
        (year, month, day) = date.split('-')
        evts = lj.server.LJ.XMLRPC.getevents(lj.auth_headers({'selecttype':'day', 'year':year,'month':month,'day':day}))
        for event in evts['events']:
            if prev is not None:
                callback(lj, prev)
            prev = event
            time.sleep(throttle_time)
    if include_the_last_one and prev is not None:
        callback(lj,prev)

def dire_warning():
    print '''
====== DANGER, LASER GUIDED DRAGONS =================================

This program makes irreversible changes to the contents of your LiveJournal
account.

THERE IS NO UNDO FUNCTION.

Do not run this program "just to see what it does".
It does what it says on the tin. It DESTROYS YOUR DATA.

If you are sure you want to do this, type the phrase:
    I want to destroy my data
and press Enter.
        '''
    shibboleth = raw_input('Are you sure? ')
    if shibboleth.strip() != u'I want to destroy my data':
        sys.exit(1)
    print 'OK, proceeding. Don\'t say you weren\'t warned.'

def ljshred_main(testfile=None, action_callback=print_entry, cleartext_password=False, except_latest=True, start_date=None, end_date=None, throttle_time=None):
    ''' The main part of the program, after the argument parsing '''
    testargs = {}
    loginargs = {}
    if testfile is not None:
        # Attempt to read login data from file.. This is only really intended for testing.
        try:
            with open(testfile, 'r') as f:
                try:
                    testargs.update(yaml.load(f))
                    print 'Logging in as %s with credentials from file'%testargs['login']
                except yaml.YAMLError as e:
                    print e
                    return 5
        except IOError as e:
            print e
            return 5
        loginargs = { k: testargs[k]
                for k in testargs
                if k in LJSession.VALID_ARGS }

    # Default, if no mode specified, is just to print:
    if action_callback is None:
        action_callback=print_entry
    if action_callback is not print_entry and 'i_want_to_destroy_my_data' not in testargs:
        dire_warning()

    loginargs['cleartext_password']=cleartext_password

    lj = LJSession(**loginargs)
    walk_entries(lj, action_callback, not except_latest, start_date, end_date, throttle_time)

def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(
            description='Shreds all the entries in a LiveJournal.',
            epilog='This program is DANGEROUS and IRREVERSIBLE. Use at your own risk.')
    parser.add_argument('-t','--testfile', action='store', dest='testfile', help=argparse.SUPPRESS)
    parser.add_argument('--cleartext_password', action='store_true', help='Sends the password in (nearly) clear text, which is faster but less secure')
    parser.add_argument('--except-latest', action='store_true', help='Doesn\'t affect the latest entry')
    parser.add_argument('--start-date', action='store', dest='start_date', help='If given, starts shredding at the given date (e.g. 2017-12-31)', metavar='YYYY-MM-DD')
    parser.add_argument('--end-date', action='store', dest='end_date', help='If given, stops shredding at the given date', metavar='YYYY-MM-DD')
    parser.add_argument('--throttle-time', action='store', dest='throttle_time', help='Attempts to defeat the LJ API posting limit by waiting this many seconds (default 3) between successive entry updates.')

    group1 = parser.add_argument_group('Action modes (specify one)')
    group = group1.add_mutually_exclusive_group()
    group.add_argument('--printout', dest='action_callback', action='store_const', const=print_entry, help='Only prints out all the entries it would touch, doesn\'t actually change anything.')
    group.add_argument('--block-out', dest='action_callback', action='store_const', const=entry_to_blocks, help='Replaces all non-whitespace text in all entries with a solid block character')
    group.add_argument('--random-garbage', dest='action_callback', action='store_const', const=entry_to_garbage, help='Replaces entries with random garbage text')
    group.add_argument('--mixed-mode', dest='action_callback', action='store_const', const=mixed_mode, help='A mixture of --random-garbage and --block-out modes')
    group.add_argument('--delete', dest='action_callback', action='store_const', const=delete_entry, help='Deletes entries')

    return vars(parser.parse_args(args))

if __name__ == '__main__':
    try:
        ljshred_main(**parse_args())
    except LJError as e:
        print e

