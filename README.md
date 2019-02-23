# tlscertcheck
TLS certificate checking tool

Check the TLS certificates on a given set of HTTPS server IP addresses
and print out identifying information about the certificates. Optionally,
match those certificates against a specified certificate identifier. The
original purpose of this program was to provide a way to quickly inspect
the certificates of a pool of servers to see if they all had the expected
configuration.


### Pre-requisites:

* Python 3
* OpenSSL
* M2Crypto module (Python interface to OpenSSL)
  (I recommend version 0.29 or later that includes the set1_host()
  function that correctly does certificate name checking.)


### Usage and options:

```
$ tlscertcheck.py --help
Usage: tlscertcheck.py [Options] <host1> <host2> ...

    Options:
    --help            Print this help message
    --verbose         Verbose mode; print details of certificate
    --printchain      Print full certificate chain if verbose is specified
    --silent          No output, just set response code
    --port=N          Use specified port (default: 443)
    --sni=<name>      For IP address arguments, set SNI extension to given name
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

The "--printchain" option (when specified with --verbose) will also print
the details of the full certificate chain.

The "--cacert" option can be used to specify a file containing root
certification authorities to trust (as a sequence of PEM format CA
certificates). The default cacert file is hardcoded into the program
(typically where it is found on many Linux distributions). Note: that
this program does not do certificate name checking, since it is designed
to connect to servers by IP address.

The "--noverify" option can be used to turn off certificate verification.


### Example runs


```
$ tlscertcheck.py --summary 10.61.133.16 10.61.132.182 10.61.133.196
2e02c81977ca118098382df7e2ec96b:4bcd7fc5        10.61.133.16 host1.example.com
2e02c81977ca118098382df7e2ec96b:4bcd7fc5        10.61.132.182 host2.example.com
2e02c81977ca118098382df7e2ec96b:4bcd7fc5        10.61.133.196 host3.example.com

## SUMMARY:
## Number of servers: 3 (ok 3, error 0)
## Number of distinct certs seen: 1
## [3] 2e02c81977ca118098382df7e2ec96b:4bcd7fc5 10.61.133.16 10.61.132.182 10.61.133.196

$ echo $?
0
```

```
$ tlscertcheck.py --verbose --printchain 1.1.1.1
1cce318de9f567fab2b24901fada71d:35be5bbd        1.1.1.1 one.one.one.one
## Host one.one.one.one address 1.1.1.1
## TLS: TLSv1.2 ECDHE-ECDSA-CHACHA20-POLY1305-256
## ----------- Certificate at Depth=0:
## Serial    : 1cce318de9f567fab2b24901fada71d
## Issuer    : C=US, O=DigiCert Inc, CN=DigiCert ECC Secure Server CA
## Subject   : C=US, ST=California, L=San Francisco, O=Cloudflare, Inc., CN=cloudflare-dns.com
## SAN: DNS:cloudflare-dns.com
## SAN: DNS:*.cloudflare-dns.com
## SAN: DNS:one.one.one.one
## SAN: IP Address:1.1.1.1
## SAN: IP Address:1.0.0.1
## SAN: IP Address:162.159.132.53
## SAN: IP Address:2606:4700:4700:0:0:0:0:1111
## SAN: IP Address:2606:4700:4700:0:0:0:0:1001
## SAN: IP Address:2606:4700:4700:0:0:0:0:64
## SAN: IP Address:2606:4700:4700:0:0:0:0:6400
## SAN: IP Address:162.159.36.1
## SAN: IP Address:162.159.46.1
## Inception : 2019-01-28 00:00:00+00:00 UTC
## Expiration: 2021-02-01 12:00:00+00:00 UTC
## ----------- Certificate at Depth=1:
## Serial    : acb28ba465ee53908767470f3cdc612
## Issuer    : C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA
## Subject   : C=US, O=DigiCert Inc, CN=DigiCert ECC Secure Server CA
## Inception : 2013-03-08 12:00:00+00:00 UTC
## Expiration: 2023-03-08 12:00:00+00:00 UTC
```

```
$ tlscertcheck.py --verbose www.ietf.org
e8e7fa116fb7d651:f131ccf4       2606:4700:10::6814:155 www.ietf.org
## Host www.ietf.org address 2606:4700:10::6814:155
## TLS: TLSv1.2 ECDHE-RSA-CHACHA20-POLY1305-256
## Serial    : e8e7fa116fb7d651
## Issuer    : C=US, ST=Arizona, L=Scottsdale, O=Starfield Technologies, Inc., OU=http://certs.starfieldtech.com/repository/, CN=Starfield Secure Certificate Authority - G2
## Subject   : OU=Domain Control Validated, CN=*.ietf.org
## SAN: DNS:*.ietf.org
## SAN: DNS:ietf.org
## Inception : 2018-06-12 15:44:12+00:00 UTC
## Expiration: 2019-08-11 23:12:50+00:00 UTC

e8e7fa116fb7d651:f131ccf4       2606:4700:10::6814:55 www.ietf.org
## Host www.ietf.org address 2606:4700:10::6814:55
## TLS: TLSv1.2 ECDHE-RSA-CHACHA20-POLY1305-256
## Serial    : e8e7fa116fb7d651
## Issuer    : C=US, ST=Arizona, L=Scottsdale, O=Starfield Technologies, Inc., OU=http://certs.starfieldtech.com/repository/, CN=Starfield Secure Certificate Authority - G2
## Subject   : OU=Domain Control Validated, CN=*.ietf.org
## SAN: DNS:*.ietf.org
## SAN: DNS:ietf.org
## Inception : 2018-06-12 15:44:12+00:00 UTC
## Expiration: 2019-08-11 23:12:50+00:00 UTC

e8e7fa116fb7d651:f131ccf4       104.20.1.85 www.ietf.org
## Host www.ietf.org address 104.20.1.85
## TLS: TLSv1.2 ECDHE-RSA-CHACHA20-POLY1305-256
## Serial    : e8e7fa116fb7d651
## Issuer    : C=US, ST=Arizona, L=Scottsdale, O=Starfield Technologies, Inc., OU=http://certs.starfieldtech.com/repository/, CN=Starfield Secure Certificate Authority - G2
## Subject   : OU=Domain Control Validated, CN=*.ietf.org
## SAN: DNS:*.ietf.org
## SAN: DNS:ietf.org
## Inception : 2018-06-12 15:44:12+00:00 UTC
## Expiration: 2019-08-11 23:12:50+00:00 UTC

e8e7fa116fb7d651:f131ccf4       104.20.0.85 www.ietf.org
## Host www.ietf.org address 104.20.0.85
## TLS: TLSv1.2 ECDHE-RSA-CHACHA20-POLY1305-256
## Serial    : e8e7fa116fb7d651
## Issuer    : C=US, ST=Arizona, L=Scottsdale, O=Starfield Technologies, Inc., OU=http://certs.starfieldtech.com/repository/, CN=Starfield Secure Certificate Authority - G2
## Subject   : OU=Domain Control Validated, CN=*.ietf.org
## SAN: DNS:*.ietf.org
## SAN: DNS:ietf.org
## Inception : 2018-06-12 15:44:12+00:00 UTC
## Expiration: 2019-08-11 23:12:50+00:00 UTC
```
