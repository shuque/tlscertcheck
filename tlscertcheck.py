#!/usr/bin/env python3
#

"""
tlscertcheck.py: TLS certificate checking tool.

Author: Shumon Huque <shuque@gmail.com>
"""

import os.path
import sys
import getopt
import socket
from M2Crypto import SSL


class Opts:
    """Options class with initialized defaults"""
    port = 443
    verbose = False
    printchain = False
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


# from OpenSSL openssl/x509_vfy.h header file. M2Crypto doesn't appear to
# export them.
X509_VERIFY_RESULT = {
    0: "Ok",
    1: "Unspecified error",
    2: "Unable to get local issuer cert",
    3: "Unable to get CRL",
    4: "Unable to decrypt cert signature",
    5: "Unable to decrypt CRL signature",
    6: "Unable to decode issuer public key",
    7: "Cert signature failure",
    8: "CRL signature failure",
    9: "Cert not yet valid",
    10: "Cert has expired",
    11: "CRL not yet valid",
    12: "CRL has expired",
    13: "Error in CERT_NOT_BEFORE field",
    14: "Error in CERT_NOT_AFTER field",
    15: "Error in CRL_LAST_UPDATE field",
    16: "Error in CRL_NEXT_UPDATE field",
    17: "Out of memory",
    18: "Self Signed certificate",
    19: "Self Signed certificate in chain",
    20: "Unable to get issuer cert locally",
    21: "Unable to verify leaf signature",
    22: "Certificate chain too long",
    23: "Certificate revoked",
    24: "Invalid CA",
    25: "Path Length exceeded",
    26: "Invalid Purpose",
    27: "Certificate untrusted",
    28: "Certificate rejected",
}


def verify_result_string(code):
    """Return text string for verify_result() code"""
    if code in X509_VERIFY_RESULT:
        return X509_VERIFY_RESULT[code]
    return "Unknown error code: {}".format(code)


def usage(msg=None):
    """Print usage string with optional error message, then exit"""
    if msg:
        print("{}\n".format(msg))
    print("""\
Usage: {0} [Options] <host1> <host2> ...

    Options:
    --help            Print this help message
    --verbose         Verbose mode; print details of certificate
    --printchain      Print full certificate chain if verbose is specified
    --silent          No output, just set response code
    --port=N          Use specified port (default: {1})
    --sni=<name>      For IP address arguments, set SNI extension to given name
    --match=<id>      Check that certficates match given id
    --usefp           Use SHA1 fingerprint of DER-encoded cert as id
    --timeout=N       Timeout per connection in seconds (default: {2})
    --infile=<file>   Read server addresses from given file
    --cacert=<file>   Use given file for trusted root CAs (PEM format)
    --noverify        Don't perform certificate verification
    --onlyerror       Only print errors for each server
    --summary         Print summary at the end
    --m2warn          Print warning if missing M2Crypto library features
""".format(os.path.basename(sys.argv[0]), Opts.port, Opts.timeout))
    sys.exit(1)


def process_args(arguments):
    """Process command line arguments"""

    longopts = [
        "help",
        "verbose",
        "printchain",
        "silent",
        "port=",
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
        if opt == "--printchain":
            Opts.printchain = True
        elif opt == "--help":
            usage()
        elif opt == "--silent":
            Opts.silent = True
        elif opt == "--port":
            Opts.port = int(optval)
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

    if Opts.printchain and not Opts.verbose:
        usage("Error: --printchain requires --verbose option")

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

    def summary(self):
        print("## Number of distinct certs seen: {}".format(len(self.db)))
        for certid, val in self.db.items():
            _, iplist = val
            print("## [{}] {} {}".format(len(iplist), certid, ','.join(iplist)))


class Server:

    """
    Server Class: holds a server IP address, and its associated
    address family and hostname.
    """

    def __init__(self, ip=None, family=None, host=None, sni=None):
        self.ip = ip
        self.family = family
        self.host = host
        self.sni = sni

    def __str__(self):
        return "<Server>: {} {} {}".format(self.ip, self.family, self.host)


def get_servers(arg):

    """
    Return a list of Server objects for given IP address or hostname
    argument. There is one Server object per IP address. So if 'arg'
    is an IP address, we return a list with one Server object. If 'arg'
    is a hostname, we enumerate all its addresses, and return a list of
    Server objects corresponding to each address.
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
        for family, _, _, _, sockaddr in ai_list:
            ip = sockaddr[0]
            slist.append(Server(ip=ip, family=family, host=arg, sni=arg))

    return slist


def get_next_arg(args, infile=None):

    """Generator function that yields the next IP or hostname argument"""

    if args:
        for arg in args:
            yield arg
    elif infile:
        for line in open(infile, 'r'):
            yield line.rstrip('\n')
    else:
        raise Exception("")


def get_hostname(ip):

    """
    Return the hostname associated with a reverse (PTR) lookup of the
    given IP address. Return "NO_HOSTNAME" if no reverse DNS exists.
    """

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "NO_HOSTNAME"
    return hostname


def get_ssl_context():
    """return SSL context object"""
    context = SSL.Context()
    if not Opts.noverify:
        context.load_verify_locations(cafile=Opts.cacert)
        context.set_verify(SSL.verify_peer, 10)
    return context


def get_ssl_connection(ctx, server):
    """return SSL connection object"""
    sock = socket.socket(server.family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(Opts.timeout)
    conn = SSL.Connection(ctx, sock=sock)
    sni = server.sni if server.sni else Opts.sni
    if sni:
        if m2have.set_tlsext_host_name:
            conn.set_tlsext_host_name(sni)
        if m2have.set1_host:
            conn.set1_host(sni)
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
    print("## Number of servers: {} ".format(Stats.total_cnt), end='')
    if Opts.matchid:
        print("(match {}, nomatch {}, error {})".format(
            Stats.match_ok, Stats.match_fail, Stats.error))
    else:
        print("(ok {}, error {})".format(Stats.ok, Stats.error))
    certdb.summary()
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


def print_subjectaltnames(cert):

    """
    Print Subject Alternative Names in the certificate.
    """

    try:
        sanlist = cert.get_ext('subjectAltName').get_value()
    except LookupError:
        return
    else:
        for san in sanlist.split(', '):
            print("## SAN: {}".format(san))
        return


def print_otherextensions(cert):

    """
    Print other extensions present in the certificate.
    """

    for i in range(cert.get_ext_count()):
        extension = cert.get_ext_at(i)
        ext_name = extension.get_name()
        ext_value = extension.get_value()
        if ext_name == 'subjectAltName':
            continue                           # Printed elsewhere
        elif ext_name == 'keyUsage':
            print('## {}: {}'.format(ext_name, ext_value))
        elif ext_name == 'extendedKeyUsage':
            print('## {}: {}'.format(ext_name, ext_value))
        elif ext_name == 'basicConstraints':
            print('## {}: {}'.format(ext_name, ext_value))
        elif ext_name == 'basicConstraints':
            print('## {}: {}'.format(ext_name, ext_value))
        elif ext_name == 'subjectKeyIdentifier':
            print('## SKI: {}'.format(ext_value))
        elif ext_name == 'authorityKeyIdentifier':
            ext_value = ext_value.rstrip('\n')
            print('## AKI: {}'.format(ext_value))
        elif ext_name == 'authorityInfoAccess':
            ext_value = ext_value.rstrip('\n')
            for value in ext_value.split('\n'):
                print('## AuthorityInfoAccess: {}'.format(value))
        elif ext_name == 'certificatePolicies':
            ext_value = ext_value.rstrip('\n')
            for value in ext_value.split('\n'):
                value = value.lstrip(' ')
                if value.startswith('Policy: '):
                    value = value[8:]
                print('## Policy: {}'.format(value))
        else:
            print('## {}: <present>'.format(ext_name))

    return


def print_cert(cert):
    """Print details of certificate, if verbose option specified"""

    serial = cert.get_serial_number()
    issuer = cert.get_issuer()
    subject = cert.get_subject()

    print("## Serial    : %x" % serial)
    print("## Issuer    : %s" % issuer.as_text())
    print("## Subject   : %s" % subject.as_text())
    print_subjectaltnames(cert)
    print("## Inception : %s" % cert_inception(cert))
    print("## Expiration: %s" % cert_expiration(cert))
    print_otherextensions(cert)

    return


def print_cert_chain(chain, server):
    """Print details of certificate(s), if verbose option specified"""

    if Opts.printchain:
        for (i, cert) in enumerate(chain):
            print('## ----------- Certificate at Depth={}:'.format(i))
            print_cert(cert)
    else:
        print_cert(chain[0])

    print('')
    return


def print_tls_info(conn):
    """Print TLS version and cipher-suite"""
    print('## TLS: {} {}'.format(
        conn.get_version(), conn.get_cipher()))


def print_connection_details(server, connection, chain, got_error=False):
    """Print TLS connection and certificate details"""

    if Opts.onlyerror and (not got_error):
        return

    print("## Host {} address {}".format(server.host, server.ip))
    print_tls_info(connection)
    print_cert_chain(chain, server)
    return


def check_tls(server, ctx, certdb):
    """Connect to server with TLS, print connection and certificate details"""

    got_error = False
    Stats.total_cnt += 1
    conn = get_ssl_connection(ctx, server)

    try:
        conn.connect((server.ip, Opts.port))
    except SSL.SSLError as e:
        if not Opts.silent and not Opts.onlyerror:
            print("ERROR: TLS {}: {}: {} {}".format(
                e,
                verify_result_string(conn.get_verify_result()),
                server.ip, server.host))
        Stats.error += 1
        return
    except SSL.Checker.WrongHost:
        if server.sni or Opts.sni:
            got_error = True
            if not Opts.silent and not Opts.onlyerror:
                print("ERROR: Certificate name mismatch: {} {}".format(
                    server.ip, server.host))
            Stats.error += 1

    if not got_error:
        Stats.ok += 1

    chain = conn.get_peer_cert_chain()
    if chain is None:
        return

    cert = chain[0]
    certid = get_certid(cert)
    certdb.insert(certid, cert, server.ip)

    if not Opts.silent and not Opts.onlyerror:
        print("{}\t{} {}".format(certid, server.ip, server.host))

    if Opts.matchid and (certid != Opts.matchid):
        got_error = True
        Stats.match_fail += 1
        if not Opts.silent:
            print("ERROR: certificate match failed: {} {}".format(
                server.ip, server.host))
    else:
        Stats.match_ok += 1

    if Opts.verbose:
        print_connection_details(server, conn, chain, got_error=got_error)

    conn.close()
    return


if __name__ == '__main__':

    args = process_args(sys.argv[1:])
    certdb = CertDB()

    m2have = M2HaveFuncs()
    ctx = get_ssl_context()

    for ip_or_host in get_next_arg(args, infile=Opts.infile):
        for server in get_servers(ip_or_host):
            try:
                check_tls(server, ctx, certdb)
            except socket.timeout as e:
                if not Opts.silent:
                    print("ERROR: connection timed out: {} {} {}".format(
                        server.ip, server.host, e))
                Stats.error += 1
            except Exception as e:
                if not Opts.silent:
                    print("ERROR: {} {}: {}".format(
                        server.ip, server.host, e))
                Stats.error += 1

    ctx.close()
    if Opts.summary:
        summary(certdb)

    sys.exit(return_code())
