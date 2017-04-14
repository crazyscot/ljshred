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

def standard_args_for(event, subject, text):
    '''
    Returns a list of args for an event.
    _text_ is the entry text, _subject_ is the subject (may be None)
    '''
    args = {
        'itemid': event['itemid'],
        'event': text,
        'lineendings':'\n',
        }
    # For good practise we will propagate security settings
    for kw in ['allowmask', 'props', 'security']:
        if kw in event:
            args[kw] = event[kw]
    if subject is not None:
        args['subject'] = subject
    return args

# List of zalgo characters taken from https://gist.github.com/MetroWind/1401473
ZALGO_UP = [u'\u030D', u'\u030E', u'\u0304', u'\u0305', u'\u033F',
        u'\u0311', u'\u0306', u'\u0310', u'\u0352', u'\u0357',
        u'\u0351', u'\u0307', u'\u0308', u'\u030A', u'\u0342',
        u'\u0343', u'\u0344', u'\u034A', u'\u034B', u'\u034C',
        u'\u0303', u'\u0302', u'\u030C', u'\u0350', u'\u0300',
        u'\u0301', u'\u030B', u'\u030F', u'\u0312', u'\u0313',
        u'\u0314', u'\u033D', u'\u0309', u'\u0363', u'\u0364',
        u'\u0365', u'\u0366', u'\u0367', u'\u0368', u'\u0369',
        u'\u036A', u'\u036B', u'\u036C', u'\u036D', u'\u036E',
        u'\u036F', u'\u033E', u'\u035B', u'\u0346', u'\u031A']

ZALGO_MID = [u'\u0315', u'\u031B', u'\u0340', u'\u0341', u'\u0358',
        u'\u0321', u'\u0322', u'\u0327', u'\u0328', u'\u0334',
        u'\u0335', u'\u0336', u'\u034F', u'\u035C', u'\u035D',
        u'\u035E', u'\u035F', u'\u0360', u'\u0362', u'\u0338',
        u'\u0337', u'\u0361', u'\u0489']

ZALGO_DOWN = [u'\u0316', u'\u0317', u'\u0318', u'\u0319', u'\u031C',
        u'\u031D', u'\u031E', u'\u031F', u'\u0320', u'\u0324',
        u'\u0325', u'\u0326', u'\u0329', u'\u032A', u'\u032B',
        u'\u032C', u'\u032D', u'\u032E', u'\u032F', u'\u0330',
        u'\u0331', u'\u0332', u'\u0333', u'\u0339', u'\u033A',
        u'\u033B', u'\u033C', u'\u0345', u'\u0347', u'\u0348',
        u'\u0349', u'\u034D', u'\u034E', u'\u0353', u'\u0354',
        u'\u0355', u'\u0356', u'\u0359', u'\u035A', u'\u0323']

def zalgochar(c):
    ''' Zalgoises a single character. Returns a unicode string. '''
    # Don't zalgoise a zalgo character, that way lies madness
    if c in ZALGO_UP or c in ZALGO_MID or c in ZALGO_DOWN:
        return c
    rv = [c]
    rv += [ random.choice(ZALGO_UP) for _ in range(random.randint(1,8)) ]
    rv += [ random.choice(ZALGO_MID) for _ in range(random.randint(0,2)) ]
    rv += [ random.choice(ZALGO_DOWN) for _ in range(random.randint(1,8)) ]
    return ''.join(rv)

def zalgoise_string(s, maxlen):
    '''
    Function to zalgoise a Unicode string, with a really naive way of making sure we fall inside the given length limit
    '''
    s = ''.join([zalgochar(c) for c in unicode(s)])
    while len(s.encode('utf-8')) > maxlen:
        s=s[0:len(s)/2]
    return s

def zalgoise_entry(lj, event):
    '''
    Callback which zalgoises the entry text. This one is reversible by
    filtering out the zalgo characters, at least on short entries.
    For a heavier zalgoisation, run the tool a second time.

    Zalgoisation is all about Unicode combining characters.
    See http://stackoverflow.com/questions/6579844/how-does-zalgo-text-work

    Unfortunately LJ has fixed size limits on entry text and subjects.
    Adding UTF-8 combining characters very quickly hits the limit for a
    subject line, so it's not worth doing those.
    '''
    text = zalgoise_string(xmlrpc_to_unicode(event['event']), 65535)
    try:
        subject = xmlrpc_to_unicode(event['subject'])
    except KeyError: # subject not in entry
        subject = None
    lj.server.LJ.XMLRPC.editevent(lj.auth_headers(standard_args_for(event, subject, text)))
    # response data ignored

def chickenise(lj,event):
    '''
    Callback which replaces words with "chicken", leaving punctuation (non-word characters) untouched.
    The naive implementation corrupts any HTML tags found within, so they are removed.
    '''
    text = xmlrpc_to_unicode(event['event'])
    text = re.sub(r"\w+", 'chicken', text, flags=re.UNICODE)
    text = re.sub(r"<[^<]*>", '', text, flags=re.UNICODE)
    try:
        subject = xmlrpc_to_unicode(event['subject'])
        subject = re.sub(r"\w+", 'chicken', subject, flags=re.UNICODE)
    except KeyError: # subject not in entry
        subject = None
    lj.server.LJ.XMLRPC.editevent(lj.auth_headers(standard_args_for(event, subject, text)))
    # response data ignored

def entry_to_blocks(lj,event):
    '''
    Callback which replaces all the text in an item with solid-block glyphs
    (U+2588)
    '''
    text = xmlrpc_to_unicode(event['event'])
    text = re.sub(r"\S", unichr(0x2588), text, flags=re.UNICODE)
    try:
        subject = xmlrpc_to_unicode(event['subject'])
        subject = re.sub(r"\S", unichr(0x2588), subject, flags=re.UNICODE)
    except KeyError: # subject not in entry
        subject = None
    lj.server.LJ.XMLRPC.editevent(lj.auth_headers(standard_args_for(event, subject, text)))
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
    try:
        subject = garbagify(xmlrpc_to_unicode(event['subject']))
    except KeyError: # subject not in entry
        subject = None
    lj.server.LJ.XMLRPC.editevent(lj.auth_headers(standard_args_for(event, subject, garbagify(xmlrpc_to_unicode(event['event'])))))
    # response data ignored

MIXED_MODE_MODELIST=[entry_to_garbage, entry_to_blocks, chickenise]

def mixed_mode(lj,event):
    ''' Randomly calls on to another mode '''
    return random.choice(MIXED_MODE_MODELIST)(lj,event)

def delete_entry(lj,event):
    '''
    Callback which deletes entry
    '''
    lj.server.LJ.XMLRPC.editevent(lj.auth_headers(standard_args_for(event, None, '')))
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
    group.add_argument('--chicken', dest='action_callback', action='store_const', const=chickenise, help='Replaces all words with the word "chicken"')
    group.add_argument('--mixed-mode', dest='action_callback', action='store_const', const=mixed_mode, help='Applies one of --random-garbage, --block-out or --chicken to each entry in turn')
    group.add_argument('--delete', dest='action_callback', action='store_const', const=delete_entry, help='Deletes entries')
    group.add_argument('--zalgo', dest='action_callback', action='store_const', const=zalgoise_entry, help='Zalgoises the text (adds a bunch of Unicode combining characters which smear a mess over them). This conversion is largely reversible, and it doesn\'t look very good in all browsers.')

    return vars(parser.parse_args(args))

if __name__ == '__main__':
    try:
        ljshred_main(**parse_args())
    except LJError as e:
        print e

