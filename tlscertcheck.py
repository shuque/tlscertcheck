#!/usr/bin/env python3
#

"""
tlscertcheck.py: TLS certificate checking tool.

"""

import os.path, sys, getopt, socket
from M2Crypto import SSL


class Opts:
    """Options class with initialized defaults"""
    port = 443
    verbose = False
    sni = None
    matchid = None
    usefp = False
    silent = False
    infile = None
    noverify = False
    cacert = "/etc/ssl/certs/ca-bundle.crt"
    onlyerror = False
    summary = False
    timeout = 10.0
    m2warn = False


class Stats:
    """Statistics class"""
    total_cnt = 0
    match_ok = 0
    match_fail = 0
    ok = 0
    error = 0


class M2HaveFuncs:
    """Class to record if we have certain SSL module functions"""
    set_tlsext_host_name = True
    set1_host = True
    def __init__(self):
        try:
            SSL.Connection.set_tlsext_host_name
        except AttributeError:
            self.set_tlsext_host_name = False
            if Opts.m2warn:
                print("WARNING: M2Crypto missing set_tlsext_host_name()")
        try:
            SSL.Connection.set1_host
        except AttributeError:
            self.set1_host = False
            if Opts.m2warn:
                print("WARNING: M2Crypto missing set1_host()")


def usage(msg=None):
    """Print usage string with optional error message, then exit"""
    if msg:
        print("{}\n".format(msg))
    print("""\
Usage: {} [Options] <host1> <host2> ...

    Options:
    --help            Print this help message
    --verbose         Verbose mode; print details of certificate
    --silent          No output, just set response code
    --sni=<name>      Set SNI extension to given server name
    --match=<id>      Check that certficates match given id
    --usefp           Use SHA1 fingerprint of DER-encoded cert as id
    --timeout=N       Timeout per connection in seconds (default: {})
    --infile=<file>   Read server addresses from given file
    --cacert=<file>   Use given file for trusted root CAs (PEM format)
    --noverify        Don't perform certificate verification
    --onlyerror       Only print errors for each server
    --summary         Print summary at the end
    --m2warn          Print warning if missing M2Crypto library features
""".format(os.path.basename(sys.argv[0]), Opts.timeout))
    sys.exit(1)


def process_args(arguments):
    """Process command line arguments"""

    longopts = [
        "help",
        "verbose",
        "silent",
        "sni=",
        "match=",
        "usefp",
        "timeout=",
        "infile=",
        "cacert=",
        "noverify",
        "onlyerror",
        "summary"
    ]

    try:
        (options, args) = getopt.getopt(arguments, "", longopts=longopts)
    except getopt.GetoptError as e:
        usage(e)

    for (opt, optval) in options:
        if opt == "--verbose":
            Opts.verbose = True
        elif opt == "--help":
            usage()
        elif opt == "--silent":
            Opts.silent = True
        elif opt == "--sni":
            Opts.sni = optval
        elif opt == "--match":
            Opts.matchid = optval
        elif opt == "--usefp":
            Opts.usefp = True
        elif opt == "--timeout":
            Opts.timeout = float(optval)
        elif opt == "--infile":
            Opts.infile = optval
        elif opt == "--cacert":
            Opts.cacert = optval
        elif opt == "--noverify":
            Opts.noverify = True
        elif opt == "--onlyerror":
            Opts.onlyerror = True
        elif opt == "--summary":
            Opts.summary = True
        elif opt == "--m2warn":
            Opts.m2warn = True

    if Opts.verbose and Opts.silent:
        usage("Error: contradictory options specified: --verbose and --silent")

    if Opts.infile and args:
        usage("Error: With --infile no IP/hosts are specified on command line")

    if not Opts.infile and not args:
        usage("Error: need list of IP addresses or hosts to check")

    return args


class CertDB:
    """
    A class to hold a hash table of certificates encountered.
    Hash table key is certid, value is (cert, list of ip) tuple.
    """

    def __init__(self):
        self.db = dict()

    def insert(self, certid, cert, ipaddr):
        if certid not in self.db:
            self.db[certid] = (cert, [ipaddr])
        else:
            iplist = self.db[certid][1]
            iplist.append(ipaddr)

    def printSummary(self):
        print("## Number of distinct certs seen: {}".format(len(self.db)))
        for certid, val in self.db.items():
            cert, iplist = val
            print("## [{}] {} {}".format(len(iplist), certid, ','.join(iplist)))


class Server:

    """
    Server Class: holds a server IP address, and its associated
    address family and hostname.
    """

    def __init__(self, ip=None, family=None, host=None):
        self.ip = ip
        self.family = family
        self.host = host

    def __str__(self):
        return "<Server>: {} {} {}".format(self.ip, self.family, self.host)


def getServers(arg):

    """
    Return a list of Server objects for each IP/host
    """

    try:
        _ = socket.inet_pton(socket.AF_INET, arg)
        return [Server(ip=arg, family=socket.AF_INET, host=get_hostname(arg))]
    except OSError:
        pass

    try:
        _ = socket.inet_pton(socket.AF_INET6, arg)
        return [Server(ip=arg, family=socket.AF_INET6, host=get_hostname(arg))]
    except OSError:
        pass

    slist = []
    try:
        ai_list = socket.getaddrinfo(arg, 443, socket.AF_UNSPEC,
                                     socket.SOCK_STREAM)
    except socket.gaierror as e:
        print("ERROR: getaddrinfo({}): {}".format(arg, e))
        return None
    else:
        for family, stype, proto, canonname, sockaddr in ai_list:
            ip = sockaddr[0]
            slist.append(Server(ip=ip, family=family, host=arg))

    return slist


def get_iplist_iterator(args):
    if args:
        return iter(args)
    elif Opts.infile:
        return open(Opts.infile)
    else:
        raise Exception("get_iplist_iterator(): value error")


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "NO_HOSTNAME"
    return hostname


def get_san_dns(cert):
    """return list of Subject Alt Name dNSName strings from certificate"""
    sandnslist = []
    try:
        san = cert.get_ext('subjectAltName').get_value()
        sandnslist = [y.lstrip('DNS:') for y in san.split(', ')
                      if y.startswith('DNS:')]
    except LookupError:
        pass
    return sandnslist


def get_ssl_context():
    """return SSL context object"""
    ctx = SSL.Context()
    if not Opts.noverify:
        ctx.load_verify_locations(cafile=Opts.cacert)
        ctx.set_verify(SSL.verify_peer, 10)
    return ctx


def get_ssl_connection(ctx, ipfamily):
    """return SSL connection object"""
    sock = socket.socket(ipfamily, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(Opts.timeout)
    conn = SSL.Connection(ctx, sock=sock)
    if Opts.sni:
        if m2have.set_tlsext_host_name:
            conn.set_tlsext_host_name(Opts.sni)
        if m2have.set1_host:
            conn.set1_host(Opts.sni)
    return conn


def get_certid(cert):
    """return certificate identification string"""
    if Opts.usefp:
        return cert.get_fingerprint(md='sha1')

    return "%x:%x" % (cert.get_serial_number(),
                      cert.get_issuer().as_hash())


def cert_inception(cert):
    """return certificate inception string"""
    dt = cert.get_not_before().get_datetime()
    tz = dt.tzname()
    return "{} {}".format(dt, tz)


def cert_expiration(cert):
    """return certificate expiration string"""
    dt = cert.get_not_after().get_datetime()
    tz = dt.tzname()
    return "{} {}".format(dt, tz)


def summary(certdb):
    """print summary of certfiicate examination stats"""
    print("\n## SUMMARY:")
    if Opts.matchid:
        print("## CertId to match: {}".format(Opts.matchid))
    print("## Number of servers: {}".format(Stats.total_cnt)),
    if Opts.matchid:
        print("(match {}, nomatch {}, error {})".format(
            Stats.match_ok, Stats.match_fail, Stats.error))
    else:
        print("(ok {}, error {})".format(Stats.ok, Stats.error))
    certdb.printSummary()
    return


def return_code():
    """calculate return code"""
    if Opts.matchid:
        if Stats.match_ok != Stats.total_cnt:
            return 1
    elif Stats.error > 0:
        return 1
    else:
        return 0


def print_verbose_cert(cert, ip, host, gotError=False):
    """Print details of certificate, if verbose option specified"""

    if not Opts.verbose:
        return

    if Opts.onlyerror and (not gotError):
        return

    serial = cert.get_serial_number()
    issuer = cert.get_issuer()
    subject = cert.get_subject()

    print("## Host {} address {}".format(host, ip))
    print("## Serial    : %x" % serial)
    print("## Issuer    : %s" % issuer.as_text())
    print("## Subject   : %s" % subject.as_text())
    print("## SAN DNS   : %s" % " ".join(get_san_dns(cert)))
    print("## Inception : %s" % cert_inception(cert))
    print("## Expiration: %s" % cert_expiration(cert))
    print('')

    return


def check_tls(ipaddr, ipfamily, hostname, ctx, certdb):
    """perform details of TLS connection and certificate inspection"""

    ### print("DEBUG: check_tls(): ip={}, hostname={}".format(ipaddr, hostname))

    gotError = False
    Stats.total_cnt += 1
    conn = get_ssl_connection(ctx, ipfamily)

    try:
        conn.connect((ipaddr, Opts.port))
    except SSL.SSLError as e:
        if not Opts.silent:
            print("ERROR: TLS error {} {}: {}\n".format(ipaddr, hostname, e))
        Stats.error += 1
        return
    except SSL.Checker.WrongHost:
        # Ignore name mismatch unless SNI was specified
        if Opts.sni:
            print("ERROR: Certificate name mismatch")
            Stats.error += 1

    Stats.ok += 1

    cert = conn.get_peer_cert()
    certid = get_certid(cert)
    certdb.insert(certid, cert, ipaddr)

    if not Opts.silent and not Opts.onlyerror:
        print("{}\t{} {}".format(certid, ipaddr, hostname))

    if Opts.matchid and (certid != Opts.matchid):
        gotError = True
        Stats.match_fail += 1
        if not Opts.silent:
            print("ERROR: {} {} certid match failed".format(ipaddr, hostname))
    else:
        Stats.match_ok += 1

    print_verbose_cert(cert, ipaddr, hostname, gotError)

    conn.close()
    return


if __name__ == '__main__':

    args = process_args(sys.argv[1:])
    certdb = CertDB()

    m2have = M2HaveFuncs()
    ctx = get_ssl_context()

    for ip_or_host in get_iplist_iterator(args):
        if Opts.infile:
            ip_or_host = ip_or_host.rstrip('\n')
        serverlist = getServers(ip_or_host)
        for server in serverlist:
            try:
                check_tls(server.ip, server.family, server.host, ctx, certdb)
            except socket.timeout as e:
                if not Opts.silent:
                    print("ERROR: connection timed out: {} {} {}".format(
                        server.ip, server.host, e))
                Stats.error += 1

    ctx.close()
    if Opts.summary:
        summary(certdb)

    sys.exit(return_code())
