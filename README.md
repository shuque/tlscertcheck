# tlscertcheck
TLS certificate checking tool

Check the TLS certificates on a given set of HTTPS server IP addresses
and print out identifying information about the certificates. Optionally,
match those certificates against a specified certificate identifier. The
original purpose of this program was to provide a way to quickly inspect
the certificates of a pool of servers to see if they all had the expected
configuration.


Pre-requisites:
* Python 3
* OpenSSL
* M2Crypto module (Python interface to OpenSSL)
  (I recommend version 0.29 or later that includes the set1_host()
  function that correctly does certificate name checking.)

Usage and options:

```
$ tlscertcheck.py --help
Usage: tlscertcheck.py [Options] <host1> <host2> ...

    Options:
    --help            Print this help message
    --verbose         Verbose mode; print details of certificate
    --silent          No output, just set response code
    --sni=<name>      Set SNI extension to given name
    --match=<id>      Check that certficates match given id
    --usefp           Use SHA1 fingerprint of DER-encoded cert as id
    --timeout=N       Timeout per connection in seconds (default: 10.0)
    --infile=<file>   Read server addresses from given file
    --cacert=<file>   Use given file for trusted root CAs (PEM format)
    --noverify        Don't perform certificate verification
    --onlyerror       Only print errors for each server
    --summary         Print summary at the end
    --m2warn          Print warning if missing M2Crypto library features
```

The host1, host2 etc arguments can either be IP addresses or hostnames.
The main output format is the following, one line per server IP address:

```
<certid> <ipaddr> <hostname>
```

The "certid" is a combination of the serial number and issuer hash,
which should uniquely identify a certificate. This should provide an
easy way to inspect whether all of the servers have the same certificate.
The "--usefp" option can be specified to alternatively use the SHA1
fingerprint of the DER-encoding of the full certificate as the certid.

For an IP address argument, the "hostname" is the name returned by reverse
DNS lookup (PTR record) of the IP address. For a hostname argument, the
program resolves all IPv4 or IPv6 addresses of the hostname and checks each
one.

The "--match" option can be used to specify a certid that all the
server certificates are compared to. An error message is printed for
each server that does not match, and if any fail to match, the program's
exit code is set to 1 (zero otherwise).

The "--infile" option can be used to specify a file containing the list
of IP addresses (one per line) instead of specifying them on the command
line.

The "--verbose" option will print more verbose info about each certificate,
such as: serial number, issuer, subject, SAN dNSNames, inception and
expiration times.

The "--cacert" option can be used to specify a file containing root
certification authorities to trust (as a sequence of PEM format CA
certificates). The default cacert file is hardcoded into the program
(typically where it is found on many Linux distributions). Note: that
this program does not do certificate name checking, since it is designed
to connect to servers by IP address.

The "--noverify" option can be used to turn off certificate verification.

