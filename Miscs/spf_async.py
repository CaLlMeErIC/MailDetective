#!/usr/bin/python
import re
import aiodns
import socket
import time
import ipaddr as ipaddress
from ipaddr import Bytes
import urllib.parse as urllibparse
import sys
from functools import reduce

__version__ = "2.0.14"
MODULE = 'spf'


async def DNSLookup_pydns(name, qtype):   # noqa
    resolver = aiodns.DNSResolver()
    try:
        result = await resolver.query(name, qtype)   # noqa
    except aiodns.error.DNSError:
        result = None
    r = []
    if result:
        for a in result:
            if hasattr(a, 'text'):
                r.append(((name, qtype), [a.text]))
            elif hasattr(a, 'host'):
                r.append(((name, "A"), a.host))
    return r


DNSLookup = DNSLookup_pydns

RE_SPF = re.compile(br'^v=spf1$|^v=spf1 ', re.IGNORECASE)

# Regular expression to look for modifiers
RE_MODIFIER = re.compile(r'^([a-z][a-z0-9_\-\.]*)=', re.IGNORECASE)

# Regular expression to find macro expansions
PAT_CHAR = r'%(%|_|-|(\{[^\}]*\}))'
RE_CHAR = re.compile(PAT_CHAR)
RE_INVALID_MACRO = re.compile(r'(?<!%)%[^{%_-]|%$')

# Regular expression to break up a macro expansion
RE_ARGS = re.compile(r'([0-9]*)(r?)([^0-9a-zA-Z]*)')

RE_DUAL_CIDR = re.compile(r'//(0|[1-9]\d*)$')
RE_CIDR = re.compile(r'/(0|[1-9]\d*)$')

PAT_IP4 = r'\.'.join([r'(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])'] * 4)
RE_IP4 = re.compile(PAT_IP4 + '$')

RE_TOPLAB = re.compile(
    r'\.(?:[0-9a-z]*[a-z][0-9a-z]*|[0-9a-z]+-[0-9a-z-]*[0-9a-z])\.?$|%s'
    % PAT_CHAR, re.IGNORECASE)

RE_DOT_ATOM = re.compile(r'%(atext)s+([.]%(atext)s+)*$' % {
    'atext': r"[0-9a-z!#$%&'*+/=?^_`{}|~-]"}, re.IGNORECASE)

# Derived from RFC 3986 appendix A
RE_IP6 = re.compile('(?:%(hex4)s:){6}%(ls32)s$'
                    '|::(?:%(hex4)s:){5}%(ls32)s$'
                    '|(?:%(hex4)s)?::(?:%(hex4)s:){4}%(ls32)s$'
                    '|(?:(?:%(hex4)s:){0,1}%(hex4)s)?::(?:%(hex4)s:){3}%(ls32)s$'
                    '|(?:(?:%(hex4)s:){0,2}%(hex4)s)?::(?:%(hex4)s:){2}%(ls32)s$'
                    '|(?:(?:%(hex4)s:){0,3}%(hex4)s)?::%(hex4)s:%(ls32)s$'
                    '|(?:(?:%(hex4)s:){0,4}%(hex4)s)?::%(ls32)s$'
                    '|(?:(?:%(hex4)s:){0,5}%(hex4)s)?::%(hex4)s$'
                    '|(?:(?:%(hex4)s:){0,6}%(hex4)s)?::$'
                    % {
                        'ls32': r'(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|%s)' % PAT_IP4,
                        'hex4': r'[0-9a-f]{1,4}'
                    }, re.IGNORECASE)

# Local parts and senders have their delimiters replaced with '.' during
# macro expansion
#
JOINERS = {'l': '.', 's': '.'}

RESULTS = {'+': 'pass', '-': 'fail', '?': 'neutral', '~': 'softfail',
           'pass': 'pass', 'fail': 'fail', 'permerror': 'permerror',
           'error': 'temperror', 'neutral': 'neutral', 'softfail': 'softfail',
           'none': 'none', 'local': 'local', 'trusted': 'trusted',
           'ambiguous': 'ambiguous', 'unknown': 'permerror'}

EXPLANATIONS = {'pass': 'sender SPF authorized',
                'fail': 'SPF fail - not authorized',
                'permerror': 'permanent error in processing',
                'temperror': 'temporary DNS error in processing',
                'softfail': 'domain owner discourages use of this host',
                'neutral': 'access neither permitted nor denied',
                'none': '',
                # Note: The following are not formally SPF results
                'local': 'No SPF result due to local policy',
                'trusted': 'No SPF check - trusted-forwarder.org',
                # Ambiguous only used in harsh mode for SPF validation
                'ambiguous': 'No error, but results may vary'
                }

DELEGATE = None

# standard default SPF record for best_guess
DEFAULT_SPF = 'v=spf1 a/24 mx/24 ptr'

# Whitelisted forwarders here.  Additional locally trusted forwarders can be
# added to this record.
TRUSTED_FORWARDERS = 'v=spf1 ?include:spf.trusted-forwarder.org -all'

# maximum DNS lookups allowed
MAX_LOOKUP = 10  # RFC 4408 Para 10.1/RFC 7208 4.6.4
MAX_MX = 10  # RFC 4408 Para 10.1/RFC 7208 4.6.4
MAX_PTR = 10  # RFC 4408 Para 10.1/RFC 7208 4.6.4
MAX_CNAME = 10  # analogous interpretation to MAX_PTR
MAX_RECURSION = 20
MAX_PER_LOOKUP_TIME = 20  # Per RFC 7208 4.6.4
MAX_VOID_LOOKUPS = 2  # RFC 7208 4.6.4

ALL_MECHANISMS = ('a', 'mx', 'ptr', 'exists', 'include', 'ip4', 'ip6', 'all')
COMMON_MISTAKES = {
    'prt': 'ptr', 'ip': 'ip4', 'ipv4': 'ip4', 'ipv6': 'ip6', 'all.': 'all'
}


# If harsh processing, for the validator, is invoked, warn if results
# likely deviate from the publishers intention.
class AmbiguityWarning(Exception):
    "SPF Warning - ambiguous results"

    def __init__(self, msg, mech=None, ext=None):
        Exception.__init__(self, msg, mech)
        self.msg = msg
        self.mech = mech
        self.ext = ext

    def __str__(self):
        if self.mech:
            return '%s: %s' % (self.msg, self.mech)
        return self.msg


class TempError(Exception):
    "Temporary SPF error"

    def __init__(self, msg, mech=None, ext=None):
        Exception.__init__(self, msg, mech)
        self.msg = str(msg)
        self.mech = mech
        self.ext = ext

    def __str__(self):
        if self.mech:
            return '%s: %s' % (self.msg, self.mech)
        return self.msg


class PermError(Exception):
    "Permanent SPF error"

    def __init__(self, msg, mech=None, ext=None):
        Exception.__init__(self, msg, mech)
        self.msg = msg
        self.mech = mech
        self.ext = ext

    def __str__(self):
        if self.mech:
            return '%s: %s' % (self.msg, self.mech)
        return self.msg


async def check2(i, s, h, local=None, receiver=None, timeout=MAX_PER_LOOKUP_TIME, verbose=False, querytime=20):   # noqa
    """Test an incoming MAIL FROM:<s>, from a client with ip address i.
    h is the HELO/EHLO domain name.  This is the RFC4408/7208 compliant
    pySPF2.0 interface.  The interface returns an SPF result and explanation
    only.  SMTP response codes are not returned since neither RFC 4408 nor RFC
    7208 does specify receiver policy.  Applications updated for RFC 4408 and
    RFC 7208 should use this interface.  The maximum time, in seconds, this
    function is allowed to run before a TempError is returned is controlled by
    querytime.  When set to 0 the timeout parameter (default 20 seconds)
    controls the time allowed for each DNS lookup.  When set to a non-zero
    value, it total time for all processing related to the SPF check is
    limited to querytime (default 20 seconds as recommended in RFC 7208,
    paragraph 4.6.4).

    Returns (result, explanation) where result in
    ['pass', 'permerror', 'fail', 'temperror', 'softfail', 'none', 'neutral' ].

    Example:
    #>>> check2(i='61.51.192.42', s='liukebing@bcc.com', h='bmsi.com')

    """
    res, _, exp = await query(i=i, s=s, h=h, local=local,   # noqa
                              receiver=receiver, timeout=timeout, verbose=verbose, querytime=querytime).check()    # noqa
    return res, exp


async def check(i, s, h, local=None, receiver=None, verbose=False):   # noqa
    """Test an incoming MAIL FROM:<s>, from a client with ip address i.
    h is the HELO/EHLO domain name.  This is the pre-RFC SPF Classic interface.
    Applications written for pySPF 1.6/1.7 can use this interface to allow
    pySPF2 to be a drop in replacement for older versions.  With the exception
    of result codes, performance in RFC 4408 compliant.

    Returns (result, code, explanation) where result in
    ['pass', 'unknown', 'fail', 'error', 'softfail', 'none', 'neutral' ].

    Example:
    #>>> check(i='61.51.192.42', s='liukebing@bcc.com', h='bmsi.com')

    """
    res, code, exp = await query(i=i, s=s, h=h, local=local, receiver=receiver, verbose=verbose).check()   # noqa
    if res == 'permerror':
        res = 'unknown'
    elif res == 'tempfail':
        res == 'error'
    return res, code, exp


class query(object):
    """A query object keeps the relevant information about a single SPF
    query:

    i: ip address of SMTP client in dotted notation
    s: sender declared in MAIL FROM:<>
    l: local part of sender s
    d: current domain, initially domain part of sender s
    h: EHLO/HELO domain
    v: 'in-addr' for IPv4 clients and 'ip6' for IPv6 clients
    t: current timestamp
    p: SMTP client domain name
    o: domain part of sender s
    r: receiver
    c: pretty ip address (different from i for IPv6)

    This is also, by design, the same variables used in SPF macro
    expansion.

    Also keeps cache: DNS cache.
    """

    def __init__(self, i, s, h, local=None, receiver=None, strict=True,
                 timeout=MAX_PER_LOOKUP_TIME, verbose=False, querytime=0):
        self.s, self.h = s, h
        if not s and h:
            self.s = 'postmaster@' + h
            self.ident = 'helo'
        else:
            self.ident = 'mailfrom'
        self.l, self.o = split_email(s, h)
        self.t = str(int(time.time()))
        self.d = self.o
        self.p = None  # lazy evaluation
        if receiver:
            self.r = receiver
        else:
            self.r = 'unknown'
        # Since the cache does not track Time To Live, it is created
        # fresh for each query.  It is important for efficiently using
        # multiple results provided in DNS answers.
        self.cache = {}
        self.defexps = dict(EXPLANATIONS)
        self.exps = dict(EXPLANATIONS)
        self.libspf_local = local  # local policy
        self.lookups = 0
        # New processing limit in RFC 7208, section 4.6.4
        self.void_lookups = 0
        # strict can be False, True, or 2 (numeric) for harsh
        self.strict = strict
        self.timeout = timeout
        self.querytime = querytime  # Default to not using a global check
        # timelimit since this is an RFC 4408 MAY
        if querytime > 0:
            self.timeout = querytime
        self.timer = 0
        self.ipaddr = None
        if i:
            self.set_ip(i)
        # Document bits of the object model not set up here:
        # self.i = string, expanded dot notation, suitable for PTR lookups
        # self.c = string, human readable form of the connect IP address
        # single letter lowercase variable names (e.g. self.i) are used for SPF macros
        # For IPv4, self.i = self.c, but not in IPv6
        # self.iplist = list of IPv4/6 addresses that would pass, collected
        #               when list or list6 is passed as 'i'
        # self.addr = ipaddr/ipaddress object representing the connect IP
        self.default_modifier = True
        self.verbose = verbose
        self.authserv = None  # Only used in A-R header generation tests

    def log(self, mech, d, spf):
        print('%s: %s "%s"' % (mech, d, spf))

    def set_ip(self, i):
        "Set connect ip, and ip6 or ip4 mode."
        self.iplist = False
        if i.lower() == 'list':
            self.iplist = []
            ip6 = False
        elif i.lower() == 'list6':
            self.iplist = []
            ip6 = True
        else:
            try:
                try:
                    self.ipaddr = ipaddress.ip_address(i)
                except AttributeError:
                    self.ipaddr = ipaddress.IPAddress(i)
            except ValueError as x:
                raise PermError(str(x))
            if self.ipaddr.version == 6:
                if self.ipaddr.ipv4_mapped:
                    self.ipaddr = ipaddress.IPv4Address(self.ipaddr.ipv4_mapped)
                    ip6 = False
                else:
                    ip6 = True
            else:
                ip6 = False
            self.c = str(self.ipaddr)
        # NOTE: self.A is not lowercase, so isn't a macro.  See query.expand()
        if ip6:
            self.A = 'AAAA'
            self.v = 'ip6'
            if self.ipaddr:
                self.i = '.'.join(list(self.ipaddr.exploded.replace(':', '').upper()))
            self.cidrmax = 128
        else:
            self.A = 'A'
            self.v = 'in-addr'
            if self.ipaddr:
                self.i = self.ipaddr.exploded
            self.cidrmax = 32

    def set_default_explanation(self, exp):
        exps = self.exps
        defexps = self.defexps
        for i in 'softfail', 'fail', 'permerror':
            exps[i] = exp
            defexps[i] = exp

    def set_explanation(self, exp):
        exps = self.exps
        for i in 'softfail', 'fail', 'permerror':
            exps[i] = exp

    # Compute p macro only if needed
    def getp(self):
        if not self.p:
            p = self.validated_ptrs()
            if not p:
                self.p = "unknown"
            elif self.d in p:
                self.p = self.d
            else:
                sfx = '.' + self.d
                for d in p:
                    if d.endswith(sfx):
                        self.p = d
                        break
                else:
                    self.p = p[0]
        return self.p

    async def best_guess(self, spf=DEFAULT_SPF):    # noqa
        """Return a best guess based on a default SPF record.
    >>> q = query('1.2.3.4','','SUPERVISION1',receiver='example.com')
    >>> q.best_guess()[0]
    'none'
        """
        if RE_TOPLAB.split(self.d)[-1]:
            return ('none', 250, '')
        pe = self.perm_error
        r, c, e = await self.check(spf)   # noqa
        if r == 'permerror':  # permerror not useful for bestguess
            if self.perm_error and self.perm_error.ext:
                r, c, e = self.perm_error.ext
            else:
                r, c = 'neutral', 250
            self.perm_error = pe
        return r, c, e

    async def check(self, spf=None):   # noqa
        """
    Returns (result, mta-status-code, explanation) where result
    in ['fail', 'softfail', 'neutral' 'permerror', 'pass', 'temperror', 'none']

    Examples:
    >>> q = query(s='strong-bad@email.example.com',
    ...           h='mx.example.org', i='192.0.2.3')
    >>> q.check(spf='v=spf1 ?all')
    ('neutral', 250, 'access neither permitted nor denied')

    >>> q.check(spf='v=spf1 redirect=controlledmail.com exp=_exp.controlledmail.com')
    ('fail', 550, 'SPF fail - not authorized')

    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 ?all moo')
    ('permerror', 550, 'SPF Permanent Error: Unknown mechanism found: moo')

    >>> q.check(spf='v=spf1 ip4:192.0.0.n ?all')
    ('permerror', 550, 'SPF Permanent Error: Invalid IP4 address: ip4:192.0.0.n')

    >>> q.check(spf='v=spf1 ip4:192.0.2.3 ip4:192.0.0.n ?all')
    ('permerror', 550, 'SPF Permanent Error: Invalid IP4 address: ip4:192.0.0.n')

    >>> q.check(spf='v=spf1 ip6:2001:db8:ZZZZ:: ?all')
    ('permerror', 550, 'SPF Permanent Error: Invalid IP6 address: ip6:2001:db8:ZZZZ::')

    >>> q.check(spf='v=spf1 =a ?all moo')
    ('permerror', 550, 'SPF Permanent Error: Unknown qualifier, RFC 4408 para 4.6.1, found in: =a')

    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 ~all')
    ('pass', 250, 'sender SPF authorized')

    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 -all moo=')
    ('pass', 250, 'sender SPF authorized')

    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 -all match.sub-domains_9=yes')
    ('pass', 250, 'sender SPF authorized')

    >>> q.strict = False
    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 -all moo')
    ('permerror', 550, 'SPF Permanent Error: Unknown mechanism found: moo')
    >>> q.perm_error.ext
    ('pass', 250, 'sender SPF authorized')

    >>> q.strict = True
    >>> q.check(spf='v=spf1 ip4:192.1.0.0/16 moo -all')
    ('permerror', 550, 'SPF Permanent Error: Unknown mechanism found: moo')

    >>> q.check(spf='v=spf1 ip4:192.1.0.0/16 ~all')
    ('softfail', 250, 'domain owner discourages use of this host')

    >>> q.check(spf='v=spf1 -ip4:192.1.0.0/6 ~all')
    ('fail', 550, 'SPF fail - not authorized')

    # Assumes DNS available
    >>> q.check()
    ('none', 250, '')

    >>> q.check(spf='v=spf1 ip4:1.2.3.4 -a:example.net -all')
    ('fail', 550, 'SPF fail - not authorized')
    >>> q.libspf_local='ip4:192.0.2.3 a:example.org'
    >>> q.check(spf='v=spf1 ip4:1.2.3.4 -a:example.net -all')
    ('pass', 250, 'sender SPF authorized')

    >>> q.check(spf='v=spf1 ip4:1.2.3.4 -all exp=_exp.controlledmail.com')
    ('fail', 550, 'Controlledmail.com does not send mail from itself.')

    >>> q.check(spf='v=spf1 ip4:1.2.3.4 ?all exp=_exp.controlledmail.com')
    ('neutral', 250, 'access neither permitted nor denied')
        """
        self.mech = []  # unknown mechanisms
        # If not strict, certain PermErrors (mispelled
        # mechanisms, strict processing limits exceeded)
        # will continue processing.  However, the exception
        # that strict processing would raise is saved here
        self.perm_error = None
        self.mechanism = None
        self.void_lookups = 0
        self.options = {}

        try:
            self.lookups = 0
            if not spf:
                spf = await self.dns_spf(self.d)   # noqa
                if self.verbose:
                    self.log("top", self.d, spf)
            if self.libspf_local and spf:
                spf = insert_libspf_local_policy(
                    spf, self.libspf_local)
            rc = await self.check1(spf, self.d, 0)   # noqa
            if self.perm_error:
                # lax processing encountered a permerror, but continued
                self.perm_error.ext = rc
                raise self.perm_error
            return rc

        except TempError as x:
            self.prob = x.msg
            if x.mech:
                self.mech.append(x.mech)
            return ('temperror', 451, 'SPF Temporary Error: ' + str(x))
        except PermError as x:
            if not self.perm_error:
                self.perm_error = x
            self.prob = x.msg
            if x.mech:
                self.mech.append(x.mech)
            # Pre-Lentczner draft treats this as an unknown result
            # and equivalent to no SPF record.
            return ('permerror', 550, 'SPF Permanent Error: ' + str(x))

    async def check1(self, spf, domain, recursion):   # noqa
        # spf rfc: 3.7 Processing Limits
        #
        if recursion > MAX_RECURSION:
            # This should never happen in strict mode
            # because of the other limits we check,
            # so if it does, there is something wrong with
            # our code.  It is not a PermError because there is not
            # necessarily anything wrong with the SPF record.
            if self.strict:
                raise AssertionError('Too many levels of recursion')
            # As an extended result, however, it should be
            # a PermError.
            raise PermError('Too many levels of recursion')
        try:
            try:
                tmp, self.d = self.d, domain
                return await self.check0(spf, recursion)   # noqa
            finally:
                self.d = tmp
        except AmbiguityWarning as x:
            self.prob = x.msg
            if x.mech:
                self.mech.append(x.mech)
            return ('ambiguous', 000, 'SPF Ambiguity Warning: %s' % x)

    def note_error(self, *msg):
        if self.strict:
            raise PermError(*msg)
        # if lax mode, note error and continue
        if not self.perm_error:
            try:
                raise PermError(*msg)
            except PermError as x:
                # FIXME: keep a list of errors for even friendlier diagnostics.
                self.perm_error = x
        return self.perm_error

    def expand_domain(self, arg):
        "validate and expand domain-spec"
        # any trailing dot was removed by expand()
        if RE_TOPLAB.split(arg)[-1]:
            raise PermError('Invalid domain found (use FQDN)', arg)
        return self.expand(arg)

    def validate_mechanism(self, mech):
        """Parse and validate a mechanism.
    Returns mech,m,arg,cidrlength,result

    Examples:
    >>> q = query(s='strong-bad@email.example.com.',
    ...           h='mx.example.org', i='192.0.2.3')
    >>> q.validate_mechanism('A')
    ('A', 'a', 'email.example.com', 32, 'pass')

    >>> q = query(s='strong-bad@email.example.com',
    ...           h='mx.example.org', i='192.0.2.3')
    >>> q.validate_mechanism('A//64')
    ('A//64', 'a', 'email.example.com', 32, 'pass')

    >>> q.validate_mechanism('A/24//64')
    ('A/24//64', 'a', 'email.example.com', 24, 'pass')

    >>> q.validate_mechanism('?mx:%{d}/27')
    ('?mx:%{d}/27', 'mx', 'email.example.com', 27, 'neutral')

    >>> try: q.validate_mechanism('ip4:1.2.3.4/247')
    ... except PermError as x: print(x)
    Invalid IP4 CIDR length: ip4:1.2.3.4/247

    >>> try: q.validate_mechanism('ip4:1.2.3.4/33')
    ... except PermError as x: print(x)
    Invalid IP4 CIDR length: ip4:1.2.3.4/33

    >>> try: q.validate_mechanism('a:example.com:8080')
    ... except PermError as x: print(x)
    Invalid domain found (use FQDN): example.com:8080

    >>> try: q.validate_mechanism('ip4:1.2.3.444/24')
    ... except PermError as x: print(x)
    Invalid IP4 address: ip4:1.2.3.444/24

    >>> try: q.validate_mechanism('ip4:1.2.03.4/24')
    ... except PermError as x: print(x)
    Invalid IP4 address: ip4:1.2.03.4/24

    >>> try: q.validate_mechanism('-all:3030')
    ... except PermError as x: print(x)
    Invalid all mechanism format - only qualifier allowed with all: -all:3030

    >>> q.validate_mechanism('-mx:%%%_/.Clara.de/27')
    ('-mx:%%%_/.Clara.de/27', 'mx', '% /.Clara.de', 27, 'fail')

    >>> q.validate_mechanism('~exists:%{i}.%{s1}.100/86400.rate.%{d}')
    ('~exists:%{i}.%{s1}.100/86400.rate.%{d}', 'exists',
    '192.0.2.3.com.100/86400.rate.email.example.com', 32, 'softfail')

    >>> q.validate_mechanism('a:mail.example.com.')
    ('a:mail.example.com.', 'a', 'mail.example.com', 32, 'pass')

    >>> try: q.validate_mechanism('a:mail.example.com,')
    ... except PermError as x: print(x)
    Do not separate mechnisms with commas: a:mail.example.com,

    >>> q = query(s='strong-bad@email.example.com',
    ...           h='mx.example.org', i='2001:db8:1234::face:b007')
    >>> q.validate_mechanism('A//64')
    ('A//64', 'a', 'email.example.com', 64, 'pass')

    >>> q.validate_mechanism('A/16')
    ('A/16', 'a', 'email.example.com', 128, 'pass')

    >>> q.validate_mechanism('A/16//48')
    ('A/16//48', 'a', 'email.example.com', 48, 'pass')

    """
        if mech.endswith(","):
            self.note_error('Do not separate mechnisms with commas', mech)
            mech = mech[:-1]
        # a mechanism
        m, arg, cidrlength, cidr6length = parse_mechanism(mech, self.d)
        # map '?' '+' or '-' to 'neutral' 'pass' or 'fail'
        if m:
            result = RESULTS.get(m[0])
            if result:
                # eat '?' '+' or '-'
                m = m[1:]
            else:
                # default pass
                result = 'pass'
        if m in COMMON_MISTAKES:
            self.note_error('Unknown mechanism found', mech)
            m = COMMON_MISTAKES[m]

        if m == 'a' and RE_IP4.match(arg):
            x = self.note_error(
                'Use the ip4 mechanism for ip4 addresses', mech)
            m = 'ip4'

        # validate cidr and dual-cidr
        if m in ('a', 'mx'):
            if cidrlength is None:
                cidrlength = 32
            elif cidrlength > 32:
                raise PermError('Invalid IP4 CIDR length', mech)
            if cidr6length is None:
                cidr6length = 128
            elif cidr6length > 128:
                raise PermError('Invalid IP6 CIDR length', mech)
            if self.v == 'ip6':
                cidrlength = cidr6length
        elif m == 'ip4' or RE_IP4.match(m):
            if m != 'ip4':
                self.note_error('Missing IP4', mech)
                m, arg = 'ip4', m
            if cidr6length is not None:
                raise PermError('Dual CIDR not allowed', mech)
            if cidrlength is None:
                cidrlength = 32
            elif cidrlength > 32:
                raise PermError('Invalid IP4 CIDR length', mech)
            if not RE_IP4.match(arg):
                raise PermError('Invalid IP4 address', mech)
        elif m == 'ip6':
            if cidr6length is not None:
                raise PermError('Dual CIDR not allowed', mech)
            if cidrlength is None:
                cidrlength = 128
            elif cidrlength > 128:
                raise PermError('Invalid IP6 CIDR length', mech)
            if not RE_IP6.match(arg):
                raise PermError('Invalid IP6 address', mech)
        else:
            if cidrlength is not None or cidr6length is not None:
                if m in ALL_MECHANISMS:
                    raise PermError('CIDR not allowed', mech)
            cidrlength = self.cidrmax

        if m in ('a', 'mx', 'ptr', 'exists', 'include'):
            if m == 'exists' and not arg:
                raise PermError('implicit exists not allowed', mech)
            arg = self.expand_domain(arg)
            if not arg:
                raise PermError('empty domain:', mech)
            if m == 'include':
                if arg == self.d:
                    if mech != 'include':
                        raise PermError('include has trivial recursion', mech)
                    raise PermError('include mechanism missing domain', mech)
            return mech, m, arg, cidrlength, result

        # validate 'all' mechanism per RFC 4408 ABNF
        if m == 'all' and mech.count(':'):
            # print '|'+ arg + '|', mech, self.d,
            self.note_error(
                'Invalid all mechanism format - only qualifier allowed with all', mech)
        if m in ALL_MECHANISMS:
            return mech, m, arg, cidrlength, result
        if m[1:] in ALL_MECHANISMS:
            x = self.note_error(
                'Unknown qualifier, RFC 4408 para 4.6.1, found in', mech)
        else:
            x = self.note_error('Unknown mechanism found', mech)
        return mech, m, arg, cidrlength, x

    async def check0(self, spf, recursion):   # noqa
        """Test this query information against SPF text.

        Returns (result, mta-status-code, explanation) where
        result in ['fail', 'unknown', 'pass', 'none']
        """

        if not spf:
            return ('none', 250, EXPLANATIONS['none'])

        # Split string by space, drop the 'v=spf1'.  Split by all whitespace
        # casuses things like carriage returns being treated as valid space
        # separators, so split() is not sufficient.
        spf = spf.split(' ')
        # Catch case where SPF record has no spaces.
        # Can never happen with conforming dns_spf(), however
        # in the future we might want to give warnings
        # for common mistakes like IN TXT "v=spf1" "mx" "-all"
        # in relaxed mode.
        if spf[0].lower() != 'v=spf1':
            if self.strict > 1:
                raise AmbiguityWarning('Invalid SPF record in', self.d)
            return ('none', 250, EXPLANATIONS['none'])
        # Just to make it even more fun, the relevant piece of the ABNF for
        # term separations is *( 1*SP ( directive / modifier ) ), so it's one
        # or more spaces, not just one.  So strip empty mechanisms.
        spf = [mech for mech in spf[1:] if mech]

        # copy of explanations to be modified by exp=
        exps = self.exps
        redirect = None

        # no mechanisms at all cause unknown result, unless
        # overridden with 'default=' modifier
        #
        default = 'neutral'
        mechs = []

        modifiers = []
        # Look for modifiers
        #
        for mech in spf:
            m = RE_MODIFIER.split(mech)[1:]
            if len(m) != 2:
                mechs.append(self.validate_mechanism(mech))
                continue

            mod, arg = m
            if mod in modifiers:
                if mod == 'redirect':
                    raise PermError('redirect= MUST appear at most once', mech)
                self.note_error('%s= MUST appear at most once' % mod, mech)
                # just use last one in lax mode
            modifiers.append(mod)
            if mod == 'exp':
                # always fetch explanation to check permerrors
                if not arg:
                    raise PermError('exp has empty domain-spec:', arg)
                arg = self.expand_domain(arg)
                if arg:
                    try:
                        exp = self.get_explanation(arg)
                        if exp and not recursion:
                            # only set explanation in base recursion level
                            self.set_explanation(exp)
                    except:
                        pass
            elif mod == 'redirect':
                self.check_lookups()
                redirect = self.expand_domain(arg)
                if not redirect:
                    raise PermError('redirect has empty domain:', arg)
            elif mod == 'default':
                # default modifier is obsolete
                if self.strict > 1:
                    raise AmbiguityWarning('The default= modifier is obsolete.')
                if not self.strict and self.default_modifier:
                    # might be an old policy, so do it anyway
                    arg = self.expand(arg)
                    # default=- is the same as default=fail
                    default = RESULTS.get(arg, default)
            elif mod == 'op':
                if not recursion:
                    for v in arg.split('.'):
                        if v:
                            self.options[v] = True
            else:
                # spf rfc: 3.6 Unrecognized Mechanisms and Modifiers
                self.expand(m[1])  # syntax error on invalid macro

        # Evaluate mechanisms
        #
        for mech, m, arg, cidrlength, result in mechs:

            if m == 'include':
                self.check_lookups()
                d = await self.dns_spf(arg)   # noqa
                if self.verbose:
                    self.log("include", arg, d)
                res, code, txt = await self.check1(d, arg, recursion + 1)   # noqa
                if res == 'pass':
                    break
                if res == 'none':
                    self.note_error(
                        'No valid SPF record for included domain: %s' % arg,
                        mech)
                res = 'neutral'
                continue
            elif m == 'all':
                break

            elif m == 'exists':
                self.check_lookups()
                try:
                    if len(await self.dns_a(arg, 'A')) > 0:   # noqa
                        break
                except AmbiguityWarning:
                    # Exists wants no response sometimes so don't raise
                    # the warning.
                    pass

            elif m == 'a':
                self.check_lookups()
                if self.cidrmatch(await self.dns_a(arg, self.A), cidrlength):   # noqa
                    break

            elif m == 'mx':
                self.check_lookups()
                if self.cidrmatch(await self.dns_mx(arg), cidrlength):   # noqa
                    break

            elif m == 'ip4':
                if self.v == 'in-addr':  # match own connection type only
                    try:
                        if self.cidrmatch([arg], cidrlength):
                            break
                    except socket.error:
                        raise PermError('syntax error', mech)

            elif m == 'ip6':
                if self.v == 'ip6':  # match own connection type only
                    try:
                        if self.cidrmatch([arg], cidrlength):
                            break
                    except socket.error:
                        raise PermError('syntax error', mech)

            elif m == 'ptr':
                self.check_lookups()
                if domainmatch(self.validated_ptrs(), arg):
                    break

        else:
            # no matches
            if redirect:
                # Catch redirect to a non-existant SPF record.
                redirect_record = await self.dns_spf(redirect)   # noqa
                if not redirect_record:
                    raise PermError('redirect domain has no SPF record',
                                    redirect)
                if self.verbose:
                    self.log("redirect", redirect, redirect_record)
                # forget modifiers on redirect
                if not recursion:
                    self.exps = dict(self.defexps)
                    self.options = {}
                return await self.check1(redirect_record, redirect, recursion)   # noqa
            result = default
            mech = None

        if not recursion:  # record matching mechanism at base level
            self.mechanism = mech
        if result == 'fail':
            return (result, 550, exps[result])
        else:
            return (result, 250, exps[result])

    def check_lookups(self):
        self.lookups = self.lookups + 1
        if self.lookups > MAX_LOOKUP * 4:
            raise PermError('More than %d DNS lookups' % (MAX_LOOKUP * 4))
        if self.lookups > MAX_LOOKUP:
            self.note_error('Too many DNS lookups')

    async def get_explanation(self, spec):   # noqa
        """Expand an explanation."""
        if spec:
            try:
                a = await self.dns_txt(spec, ignore_void=True)   # noqa
                if len(a) == 1:
                    return str(self.expand(to_ascii(a[0]), stripdot=False))
            except PermError:
                # RFC4408 6.2/4 syntax errors cause exp= to be ignored
                if self.strict > 1:
                    raise  # but report in harsh mode for record checking tools
                pass
        elif self.strict > 1:
            raise PermError('Empty domain-spec on exp=')
        # RFC4408 6.2/4 empty domain spec is ignored
        # (unless you give precedence to the grammar).
        return None

    def expand(self, s, stripdot=True):  # macros='slodipvh'
        """Do SPF RFC macro expansion.

        Examples:
        >>> q = query(s='strong-bad@email.example.com',
        ...           h='mx.example.org', i='192.0.2.3')
        >>> q.p = 'mx.example.org'
        >>> q.r = 'example.net'

        >>> q.expand('%{d}')
        'email.example.com'

        >>> q.expand('%{d4}')
        'email.example.com'

        >>> q.expand('%{d3}')
        'email.example.com'

        >>> q.expand('%{d2}')
        'example.com'

        >>> q.expand('%{d1}')
        'com'

        >>> q.expand('%{p}')
        'mx.example.org'

        >>> q.expand('%{p2}')
        'example.org'

        >>> q.expand('%{dr}')
        'com.example.email'

        >>> q.expand('%{d2r}')
        'example.email'

        >>> q.expand('%{l}')
        'strong-bad'

        >>> q.expand('%{l-}')
        'strong.bad'

        >>> q.expand('%{lr}')
        'strong-bad'

        >>> q.expand('%{lr-}')
        'bad.strong'

        >>> q.expand('%{l1r-}')
        'strong'

        >>> q.expand('%{c}',stripdot=False)
        '192.0.2.3'

        >>> q.expand('%{r}',stripdot=False)
        'example.net'

        >>> q.expand('%{ir}.%{v}._spf.%{d2}')
        '3.2.0.192.in-addr._spf.example.com'

        >>> q.expand('%{lr-}.lp._spf.%{d2}')
        'bad.strong.lp._spf.example.com'

        >>> q.expand('%{lr-}.lp.%{ir}.%{v}._spf.%{d2}')
        'bad.strong.lp.3.2.0.192.in-addr._spf.example.com'

        >>> q.expand('%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}')
        '3.2.0.192.in-addr.strong.lp._spf.example.com'

        >>> try: q.expand('%(ir).%{v}.%{l1r-}.lp._spf.%{d2}')
        ... except PermError as x: print(x)
        invalid-macro-char : %(ir)

        >>> q.expand('%{p2}.trusted-domains.example.net')
        'example.org.trusted-domains.example.net'

        >>> q.expand('%{p2}.trusted-domains.example.net.')
        'example.org.trusted-domains.example.net'

        >>> q = query(s='@email.example.com',
        ...           h='mx.example.org', i='192.0.2.3')
        >>> q.p = 'mx.example.org'
        >>> q.expand('%{l}')
        'postmaster'

        """
        # Check for invalid macro syntax
        if s.find('%') >= 0:
            regex = RE_INVALID_MACRO
            for label in s.split('.'):
                if regex.search(s):
                    raise PermError('invalid-macro-char ', label)
        # expand macros
        end = 0
        result = ''
        for i in RE_CHAR.finditer(s):
            result += s[end:i.start()]
            macro = s[i.start():i.end()]
            if macro == '%%':
                result += '%'
            elif macro == '%_':
                result += ' '
            elif macro == '%-':
                result += '%20'
            else:
                letter = macro[2].lower()
                #                print letter
                if letter == 'p':
                    self.getp()
                elif letter in 'crt' and stripdot:
                    raise PermError(
                        'c,r,t macros allowed in exp= text only', macro)
                expansion = getattr(self, letter, self)
                if expansion:
                    if expansion == self:
                        raise PermError('Unknown Macro Encountered', macro)
                    e = expand_one(expansion, macro[3:-1], JOINERS.get(letter))
                    if letter != macro[2]:
                        e = urllibparse.quote(e, '~')
                    result += e
            end = i.end()
        result += s[end:]
        if stripdot and result.endswith('.'):
            result = result[:-1]
        if result.count('.') != 0:
            if len(result) > 253:
                result = result[(result.index('.') + 1):]
        return result

    async def dns_spf(self, domain):   # noqa
        """Get the SPF record recorded in DNS for a specific domain
        name.  Returns None if not found, or if more than one record
        is found.
        """
        # Per RFC 4.3/1, check for malformed domain.  This produces
        # no results as a special case.
        for label in domain.split('.'):
            if not label or len(label) > 63:
                return None
        # for performance, check for most common case of TXT first
        a = [t for t in await self.dns_txt(domain) if RE_SPF.match(t)]   # noqa
        if len(a) > 1:
            if self.verbose:
                print('cache=', self.cache)
            raise PermError('Two or more type TXT spf records found.')
        if len(a) == 1 and self.strict < 2:
            return to_ascii(a[0])
        # check official SPF type first when it becomes more popular
        if self.strict > 1:
            # Only check for Type SPF in harsh mode until it is more popular.
            try:
                b = [t for t in await self.dns_txt(domain, 'SPF', ignore_void=True) if RE_SPF.match(t)]   # noqa
            except TempError as x:
                # some braindead DNS servers hang on type 99 query
                if self.strict > 1:
                    raise TempError(x)
                b = []
            if len(b) > 1:
                raise PermError('Two or more type SPF spf records found.')
            if len(b) == 1:
                if self.strict > 1 and len(a) == 1 and a[0] != b[0]:
                    # Changed from permerror to warning based on RFC 4408 Auth 48 change
                    raise AmbiguityWarning(
                        'v=spf1 records of both type TXT and SPF (type 99) present, but not identical')
                return to_ascii(b[0])
        if len(a) == 1:
            return to_ascii(a[0])  # return TXT if SPF wasn't found
        if DELEGATE:  # use local record if neither found
            a = [t
                 for t in await self.dns_txt(domain + '._spf.' + DELEGATE, ignore_void=True)   # noqa
                 if RE_SPF.match(t)
                 ]
            if len(a) == 1:
                return to_ascii(a[0])
        return None

    # Get list of TXT records for a domain name.
    # Any DNS library *must* return bytes (same as str in python2) for TXT
    # or SPF since there is no general decoding to unicode.  Py3dns-3.0.2
    # incorrectly attempts to convert to str using idna encoding by default.
    # We work around this by assuming any UnicodeErrors coming from py3dns
    # are from a non-ascii SPF record (incorrect in general).  Packages
    # should require py3dns != 3.0.2.
    #
    # We cannot check for non-ascii here, because we must ignore non-SPF
    # records - even when they are non-ascii.  So we return bytes.
    # The caller does the ascii check for SPF records and explanations.
    #
    async def dns_txt(self, domainname, rr='TXT', ignore_void=False):   # noqa
        "Get a list of TXT records for a domain name."
        if domainname:
            try:
                dns_list = await self.dns(domainname, rr, ignore_void=ignore_void)   # noqa
                if dns_list:
                    # a[0][:0] is '' for py3dns-3.0.2, otherwise b''
                    a = [a[0][:0].join(a) for a in dns_list if a]
                    # FIXME: workaround for error in py3dns-3.0.2
                    if isinstance(a[0], bytes):
                        return a
                    return [s.encode('utf-8') for s in a]
            # FIXME: workaround for error in py3dns-3.0.2
            except UnicodeError:
                raise PermError('Non-ascii characters found in %s record for %s'
                                % (rr, domainname))
        return []

    async def dns_mx(self, domainname):   # noqa
        """Get a list of IP addresses for all MX exchanges for a
        domain name.
        """
        # RFC 4408/7208 section 5.4 "mx"
        # To prevent DoS attacks, more than 10 MX names MUST NOT be looked up
        # Changed to permerror if more than 10 exist in 7208
        mxnames = await self.dns(domainname, 'MX')   # noqa
        if self.strict:
            max = MAX_MX
            if len(mxnames) > MAX_MX:
                raise PermError(
                    'More than %d MX records returned' % MAX_MX)
            if self.strict > 1:
                if len(mxnames) == 0:
                    raise AmbiguityWarning(
                        'No MX records found for mx mechanism', domainname)
        else:
            max = MAX_MX * 4
        mxnames.sort()
        return [a for mx in mxnames[:max] for a in await self.dns_a(mx[1], self.A)]   # noqa

    async def dns_a(self, domainname, A='A'):   # noqa
        """Get a list of IP addresses for a domainname.
        """
        if not domainname:
            return []
        r = await self.dns(domainname, A)   # noqa
        if self.strict > 1 and len(r) == 0:
            raise AmbiguityWarning(
                'No %s records found for' % A, domainname)
        if A == 'AAAA' and bytes is str:
            # work around pydns inconsistency plus python2 bytes/str ambiguity
            return [Bytes(ip) for ip in r]
        return r

    async def validated_ptrs(self):   # noqa
        """Figure out the validated PTR domain names for the connect IP."""
        # To prevent DoS attacks, more than 10 PTR names MUST NOT be looked up
        if self.strict:
            max = MAX_PTR
            if self.strict > 1:
                # Break out the number of PTR records returned for testing
                try:
                    ptrnames = await self.dns_ptr(self.i)   # noqa
                    if len(ptrnames) > max:
                        warning = 'More than %d PTR records returned' % max
                        raise AmbiguityWarning(warning, self.c)
                    else:
                        if len(ptrnames) == 0:
                            raise AmbiguityWarning(
                                'No PTR records found for ptr mechanism', self.c)
                except:
                    raise AmbiguityWarning(
                        'No PTR records found for ptr mechanism', self.c)
        else:
            max = MAX_PTR * 4
        cidrlength = self.cidrmax
        return [p for p in await self.dns_ptr(self.i)[:max]   # noqa
                if self.cidrmatch(self.dns_a(p, self.A), cidrlength)]   # noqa

    async def dns_ptr(self, i):   # noqa
        """Get a list of domain names for an IP address."""
        return await self.dns('%s.%s.arpa' % (reverse_dots(i), self.v), 'PTR')   # noqa

    # We have to be careful which additional DNS RRs we cache.  For
    # instance, PTR records are controlled by the connecting IP, and they
    # could poison our local cache with bogus A and MX records.

    SAFE2CACHE = {
        ('MX', 'A'): None,
        ('MX', 'MX'): None,
        ('CNAME', 'A'): None,
        ('A', 'A'): None,
        ('AAAA', 'AAAA'): None,
        ('PTR', 'PTR'): None,
        ('TXT', 'TXT'): None,
        ('SPF', 'SPF'): None
    }

    # FIXME: move to anydns
    #
    #   All types return a list of values.  TXT/SPF values are
    #   in turn a list of strings (as bytes), as DNS supports long
    #   strings as shorter strings which must be concatenated.
    #
    async def dns(self, name, qtype, cnames=None, ignore_void=False):   # noqa
        """DNS query.

        If the result is in cache, return that.  Otherwise pull the
        result from DNS, and cache ALL answers, so additional info
        is available for further queries later.

        CNAMEs are followed.

        If there is no data, [] is returned.

        pre: qtype in ['A', 'AAAA', 'MX', 'PTR', 'TXT', 'SPF']
        post: isinstance(__return__, types.ListType)

        Examples:
        >>> c = query(s='strong-bad@email.example.com',
        ...           h='parallel.kitterman.org',i='192.0.2.123')
        >>> "".join( chr(x) for x in bytearray(c.dns('parallel.kitterman.org', 'TXT')[0][0]) )
        'v=spf1 include:long.kitterman.org include:cname.kitterman.org -all'
        """
        if not name:
            raise Exception('Invalid query')
        name = str(name)
        if name.endswith('.'):
            name = name[:-1]
        if not reduce(lambda x, y: x and 0 < len(y) < 64, name.split('.'), True):
            return []  # invalid DNS name (too long or empty)
        name = name.lower()
        result = self.cache.get((name, qtype), [])
        if result:
            return result
        cnamek = (name, 'CNAME')
        cname = self.cache.get(cnamek)

        debug = self.verbose and name.startswith('cname.')

        if cname:
            cname = cname[0]
        else:
            safe2cache = query.SAFE2CACHE
            for k, v in await DNSLookup(name, qtype):   # noqa
                if debug:
                    print('result=', k, v)
                # Force case insensitivity in cache, DNS servers often
                # return random case in domain part of answers.
                k = (k[0].lower(), k[1])
                if k == cnamek:
                    cname = v
                    result = self.cache.get((cname, qtype), [])
                    if result:
                        break
                if k[1] == 'CNAME' or (qtype, k[1]) in safe2cache:
                    if debug:
                        print('addcache=', k, v)
                    self.cache.setdefault(k, []).append(v)
                    # if ans and qtype == k[1]:
                    #    self.cache.setdefault((name,qtype), []).append(v)
            result = self.cache.get((name, qtype), [])
        if not result and cname:
            if not cnames:
                cnames = {}
            elif len(cnames) >= MAX_CNAME:
                # return result    # if too many == NX_DOMAIN
                raise PermError('Length of CNAME chain exceeds %d' % MAX_CNAME)
            cnames[name] = cname
            if cname.lower().rstrip('.') in cnames:
                if self.strict > 1:
                    raise AmbiguityWarning('CNAME loop', cname)
            else:
                result = await self.dns(cname, qtype, cnames=cnames)   # noqa
                if result:
                    self.cache[(name, qtype)] = result
        if not result and not ignore_void:
            self.void_lookups += 1
            if self.void_lookups > MAX_VOID_LOOKUPS:
                raise PermError('Void lookup limit of %d exceeded' % MAX_VOID_LOOKUPS)
        return result

    def cidrmatch(self, ipaddrs, n):
        """Match connect IP against a CIDR network of other IP addresses.

        Examples:
        >>> c = query(s='strong-bad@email.example.com',
        ...           h='mx.example.org', i='192.0.2.3')
        >>> c.p = 'mx.example.org'
        >>> c.r = 'example.com'

        >>> c.cidrmatch(['192.0.2.3'],32)
        True
        >>> c.cidrmatch(['192.0.2.2'],32)
        False
        >>> c.cidrmatch(['192.0.2.2'],31)
        True

        >>> six = query(s='strong-bad@email.example.com',
        ...           h='mx.example.org', i='2001:0db8:0:0:0:0:0:0001')
        >>> six.p = 'mx.example.org'
        >>> six.r = 'example.com'

        >>> six.cidrmatch(['2001:0DB8::'],127)
        True
        >>> six.cidrmatch(['2001:0DB8::'],128)
        False
        >>> six.cidrmatch(['2001:0DB8:0:0:0:0:0:0001'],128)
        True
        """
        try:
            try:
                for netwrk in [ipaddress.ip_network(ip) for ip in ipaddrs]:
                    network = netwrk.supernet(new_prefix=n)
                    if isinstance(self.iplist, bool):
                        if network.__contains__(self.ipaddr):
                            return True
                    else:
                        if n < self.cidrmax:
                            self.iplist.append(network)
                        else:
                            self.iplist.append(network.ip)
            except AttributeError:
                for netwrk in [ipaddress.IPNetwork(ip, strict=False) for ip in ipaddrs]:
                    network = netwrk.supernet(new_prefix=n)
                    if isinstance(self.iplist, bool):
                        if network.__contains__(self.ipaddr):
                            return True
                    else:
                        if n < self.cidrmax:
                            self.iplist.append(network)
                        else:
                            self.iplist.append(network.ip)
        except ValueError as x:
            raise PermError(str(x))
        return False


def split_email(s, h):
    """Given a sender email s and a HELO domain h, create a valid tuple
    (l, d) local-part and domain-part.

    Examples:
    >>> split_email('', 'wayforward.net')
    ('postmaster', 'wayforward.net')

    >>> split_email('foo.com', 'wayforward.net')
    ('postmaster', 'foo.com')

    >>> split_email('terry@wayforward.net', 'optsw.com')
    ('terry', 'wayforward.net')
    """
    if not s:
        return 'postmaster', h
    else:
        parts = s.split('@', 1)
        if parts[0] == '':
            parts[0] = 'postmaster'
        if len(parts) == 2:
            return tuple(parts)
        else:
            return 'postmaster', s


def quote_value(s):
    """Quote the value for a key-value pair in Received-SPF header field
    if needed.  No quoting needed for a dot-atom value.

    Examples:
    >>> quote_value('foo@bar.com')
    '"foo@bar.com"'

    >>> quote_value('mail.example.com')
    'mail.example.com'

    >>> quote_value('A:1.2.3.4')
    '"A:1.2.3.4"'

    >>> quote_value('abc"def')
    '"abc\\\\"def"'

    >>> quote_value(r'abc\def')
    '"abc\\\\\\\\def"'

    >>> quote_value('abc..def')
    '"abc..def"'

    >>> quote_value('')
    '""'

    >>> quote_value(None)
    """
    if s is None or RE_DOT_ATOM.match(s):
        return s
    return '"' + s.replace('\\', r'\\').replace('"', r'\"'
                                                ).replace('\x00', r'\x00') + '"'


def parse_mechanism(str, d):
    """Breaks A, MX, IP4, and PTR mechanisms into a (name, domain,
    cidr,cidr6) tuple.  The domain portion defaults to d if not present,
    the cidr defaults to 32 if not present.

    Examples:
    >>> parse_mechanism('a', 'foo.com')
    ('a', 'foo.com', None, None)

    >>> parse_mechanism('exists','foo.com')
    ('exists', None, None, None)

    >>> parse_mechanism('a:bar.com', 'foo.com')
    ('a', 'bar.com', None, None)

    >>> parse_mechanism('a/24', 'foo.com')
    ('a', 'foo.com', 24, None)

    >>> parse_mechanism('A:foo:bar.com/16//48', 'foo.com')
    ('a', 'foo:bar.com', 16, 48)

    >>> parse_mechanism('-exists:%{i}.%{s1}.100/86400.rate.%{d}','foo.com')
    ('-exists', '%{i}.%{s1}.100/86400.rate.%{d}', None, None)

    >>> parse_mechanism('mx:%%%_/.Claranet.de/27','foo.com')
    ('mx', '%%%_/.Claranet.de', 27, None)

    >>> parse_mechanism('mx:%{d}//97','foo.com')
    ('mx', '%{d}', None, 97)

    >>> parse_mechanism('iP4:192.0.0.0/8','foo.com')
    ('ip4', '192.0.0.0', 8, None)
    """

    a = RE_DUAL_CIDR.split(str)
    if len(a) == 3:
        str, cidr6 = a[0], int(a[1])
    else:
        cidr6 = None
    a = RE_CIDR.split(str)
    if len(a) == 3:
        str, cidr = a[0], int(a[1])
    else:
        cidr = None

    a = str.split(':', 1)
    if len(a) < 2:
        str = str.lower()
        if str == 'exists':
            d = None
        return str, d, cidr, cidr6
    return a[0].lower(), a[1], cidr, cidr6


def reverse_dots(name):
    """Reverse dotted IP addresses or domain names.

    Example:
    >>> reverse_dots('192.168.0.145')
    '145.0.168.192'

    >>> reverse_dots('email.example.com')
    'com.example.email'
    """
    a = name.split('.')
    a.reverse()
    return '.'.join(a)


def domainmatch(ptrs, domainsuffix):
    """grep for a given domain suffix against a list of validated PTR
    domain names.

    Examples:
    >>> domainmatch(['FOO.COM'], 'foo.com')
    1

    >>> domainmatch(['moo.foo.com'], 'FOO.COM')
    1

    >>> domainmatch(['moo.bar.com'], 'foo.com')
    0

    """
    domainsuffix = domainsuffix.lower()
    for ptr in ptrs:
        ptr = ptr.lower()
        if ptr == domainsuffix or ptr.endswith('.' + domainsuffix):
            return True

    return False


def expand_one(expansion, str, joiner):
    if not str:
        return expansion
    ln, reverse, delimiters = RE_ARGS.split(str)[1:4]
    if not delimiters:
        delimiters = '.'
    expansion = split(expansion, delimiters, joiner)
    if reverse:
        expansion.reverse()
    if ln:
        expansion = expansion[-int(ln) * 2 + 1:]
    return ''.join(expansion)


def split(str, delimiters, joiner=None):
    """Split a string into pieces by a set of delimiter characters.  The
    resulting list is delimited by joiner, or the original delimiter if
    joiner is not specified.

    Examples:
    >>> split('192.168.0.45', '.')
    ['192', '.', '168', '.', '0', '.', '45']

    >>> split('terry@wayforward.net', '@.')
    ['terry', '@', 'wayforward', '.', 'net']

    >>> split('terry@wayforward.net', '@.', '.')
    ['terry', '.', 'wayforward', '.', 'net']
    """
    result, element = [], ''
    for c in str:
        if c in delimiters:
            result.append(element)
            element = ''
            if joiner:
                result.append(joiner)
            else:
                result.append(c)
        else:
            element += c
    result.append(element)
    return result


def insert_libspf_local_policy(spftxt, local=None):
    """Returns spftxt with local inserted just before last non-fail
    mechanism.  This is how the libspf{2} libraries handle "local-policy".

    Examples:
    >>> insert_libspf_local_policy('v=spf1 -all')
    'v=spf1 -all'
    >>> insert_libspf_local_policy('v=spf1 -all','mx')
    'v=spf1 -all'
    >>> insert_libspf_local_policy('v=spf1','a mx ptr')
    'v=spf1 a mx ptr'
    >>> insert_libspf_local_policy('v=spf1 mx -all','a ptr')
    'v=spf1 mx a ptr -all'
    >>> insert_libspf_local_policy('v=spf1 mx -include:foo.co +all','a ptr')
    'v=spf1 mx a ptr -include:foo.co +all'

    # FIXME: is this right?  If so, "last non-fail" is a bogus description.
    >>> insert_libspf_local_policy('v=spf1 mx ?include:foo.co +all','a ptr')
    'v=spf1 mx a ptr ?include:foo.co +all'
    >>> spf='v=spf1 ip4:1.2.3.4 -a:example.net -all'
    >>> local='ip4:192.0.2.3 a:example.org'
    >>> insert_libspf_local_policy(spf,local)
    'v=spf1 ip4:1.2.3.4 ip4:192.0.2.3 a:example.org -a:example.net -all'
    """
    # look to find the all (if any) and then put local
    # just after last non-fail mechanism.  This is how
    # libspf2 handles "local policy", and some people
    # apparently find it useful (don't ask me why).
    if not local:
        return spftxt
    spf = spftxt.split()[1:]
    if spf:
        # local policy is SPF mechanisms/modifiers with no
        # 'v=spf1' at the start
        spf.reverse()  # find the last non-fail mechanism
        for mech in spf:
            # map '?' '+' or '-' to 'neutral' 'pass'
            # or 'fail'
            if not RESULTS.get(mech[0]):
                # actually finds last mech with default result
                where = spf.index(mech)
                spf[where:where] = [local]
                spf.reverse()
                local = ' '.join(spf)
                break
        else:
            return spftxt  # No local policy adds for v=spf1 -all
    # Processing limits not applied to local policy.  Suggest
    # inserting 'local' mechanism to handle this properly
    # MAX_LOOKUP = 100
    return 'v=spf1 ' + local


if sys.version_info[0] == 2:
    def to_ascii(s):
        "Raise PermError if arg is not 7-bit ascii."
        try:
            return s.encode('ascii')
        except UnicodeError:
            raise PermError('Non-ascii characters found', repr(s))
else:
    def to_ascii(s):
        "Raise PermError if arg is not 7-bit ascii."
        try:
            return s.decode('ascii')
        except UnicodeError:
            raise PermError('Non-ascii characters found', repr(s))
