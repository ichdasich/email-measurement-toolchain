# Overview

This repo contains the source code used for the measurements presented in "Not
that Simple: Email Delivery in the 21st Century", published at USENIX ATC'22.
Please refer to the paper for a further background on it's purpose: [TBD]

Below, you can find the setup-documentation, to run this toolchain yourself.

## Requirements

To setup this measurement toolchain, you need the following items:
- Seven (virtual) machines with a public IPv4 and IPv6 address. The
  documentation will assume that you have a single /64 IPv6 and a /28 IPv4 for
your machines.  These IP addresses must be inbound unfiltered on: tcp/25 as
well as udp/53 and tcp/53.  In the documentation, we will use 198.51.100.16/28
and   2001:DB8::/64.
- Delegation of reverse DNS for these IP addresses to the measurement setup
- A (sub)domain which you can delegate to a single server; Otherwise, you will
  need an additional machine to run a second authoritative DNS server on.
Furthermore, you must be able to setup DNSSEC for that subdomain.  We will use
measurement.example.com in the documentation.

For your reference, you can find the clustered configuration files from the 
instance used in the paper project in `example-setup/` in this repository.

## Host setup

### dns.measurement.example.com
```
IPv4: 198.51.100.28
IPv6: 2001:db8::28
```

#### Setup a DNS server

Setup an authoritative DNS server of your choice (nsd, bind9, powerdns etc.), 
and configure the following zones.

Make sure the DNS server logs all queries it receives.

##### measurement.example.com:
```
; Warning - every name in this file is ABSOLUTE!
$ORIGIN .
measurement.example.com    86400   IN      SOA     dns.measurement.example.com example.com 2022020915 28800 7200 604800 86400
measurement.example.com    300     IN      NS      dns.measurement.example.com
measurement.example.com    300     IN      CAA     1 issue "letsencrypt.org"
*.measurement.example.com  300     IN      CAA     1 issue "letsencrypt.org"
dns.measurement.example.com        300     IN      A       198.51.100.28
dns.measurement.example.com        300     IN      AAAA    2001:db8::28
dns-dnssec-broken.measurement.example.com  300     IN      A       198.51.100.30
dns-dnssec-broken.measurement.example.com  300     IN      AAAA    2001:db8::30
dns-dnssec-broken.measurement.example.com  300     IN      CAA     1 issue "letsencrypt.org"
dns-dnssec-broken-v4.measurement.example.com       300     IN      A       198.51.100.30
dns-dnssec-broken-v6.measurement.example.com       300     IN      AAAA    2001:db8::30
dns-v6.measurement.example.com     300     IN      A       198.51.100.29
dns-v6.measurement.example.com     300     IN      AAAA    2001:db8::29
dns-v6.measurement.example.com     300     IN      CAA     1 issue "letsencrypt.org"
dns-v6-v4.measurement.example.com  300     IN      A       198.51.100.29
dns-v6-v6.measurement.example.com  300     IN      AAAA    2001:db8::29
dnssec-broken.measurement.example.com      300     IN      NS      dns-dnssec-broken.measurement.example.com
dnssec-broken.measurement.example.com      300     IN      DS      29251 13 4 cdb03744c60c8c87996e2fcc5e49072af18493a72af4395fd9ef62b796fcd7786813a80f4e6a33f5cd52685bbc79a2a7
greylisting.measurement.example.com        300     IN      A       198.51.100.27
greylisting.measurement.example.com        300     IN      AAAA    2001:db8::27
greylisting-v4.measurement.example.com     300     IN      A       198.51.100.27
greylisting-v6.measurement.example.com     300     IN      AAAA    2001:db8::27
mail.measurement.example.com       300     IN      A       198.51.100.22
mail.measurement.example.com       300     IN      AAAA    2001:db8::22
mail-tls-force.measurement.example.com     300     IN      MX      10 tls-force.measurement.example.com
mail-tls-invalid.measurement.example.com   300     IN      MX      10 tls-invalid.measurement.example.com
mail-tlsa-invalid.measurement.example.com  300     IN      MX      10 tlsa-invalid.measurement.example.com
_25._tcp.mail-tlsa-invalid.measurement.example.com 300     IN      TLSA    3 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971
mail-v4.measurement.example.com    300     IN      A       198.51.100.22
mail-v6.measurement.example.com    300     IN      AAAA    2001:db8::22
rdns.measurement.example.com       300     IN      NS      dns.measurement.example.com
rdns.measurement.example.com       300     IN      DS      28380 13 4 6b49420156d95351d10385eef65c2d8d07c4463db3bf54f4f6c08eb60852c128d236517300fa827cf018844485e40cfc
tls-force.measurement.example.com  300     IN      A       198.51.100.25
tls-force.measurement.example.com  300     IN      AAAA    2001:db8::25
tls-force.measurement.example.com  300     IN      CAA     1 issue "letsencrypt.org"
tls-force-v4.measurement.example.com       300     IN      A       198.51.100.25
tls-force-v6.measurement.example.com       300     IN      AAAA    2001:db8::25
tls-invalid.measurement.example.com        300     IN      A       198.51.100.26
tls-invalid.measurement.example.com        300     IN      AAAA    2001:db8::26
tls-invalid-v4.measurement.example.com     300     IN      A       198.51.100.26
tls-invalid-v6.measurement.example.com     300     IN      AAAA    2001:db8::26
tlsa-invalid.measurement.example.com       300     IN      A       198.51.100.26
tlsa-invalid.measurement.example.com       300     IN      AAAA    2001:db8::26
_25._tcp.tlsa-invalid.measurement.example.com      300     IN      TLSA    3 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971
v4-mail.measurement.example.com    300     IN      MX      10 mail-v4.measurement.example.com
v4-mail-greylisting.measurement.example.com        300     IN      MX      10 greylisting-v4.measurement.example.com
v6-mail.measurement.example.com    300     IN      MX      10 mail-v6.measurement.example.com
v6-mail-greylisting.measurement.example.com        300     IN      MX      10 greylisting-v6.measurement.example.com
v6only.measurement.example.com     300     IN      NS      dns.v6only.measurement.example.com
v6only.measurement.example.com     300     IN      DS      55525 13 4 baebb56d4e88b211e988d41e203fadac4480ffb5636c9a1503c497e8da4b4278b3ae59c5a6fecf72b7426026533acfdb
dns.v6only.measurement.example.com 300     IN      AAAA    2001:db8::29
```

Please note:
- The `DS` entries will have to be adjusted to match values for _your_ DNSKEYs
  for _your_zones.
- The `DS` for dnssec-broken.measurement.example.com *MUST NOT* match the
  actual DNSKEY of that zone (see below).
- The `TLSA` records *MUST NOT* match the actual certificate of the
  corresponding host (see below).
- After adding this zone, add delegation of the zone in `example.com`.
- Make sure that you _do_ set glue/hint records for dns.measurement.example.com
  in example.com, as well as correct `DS` entries after enabling DNSSEC.


##### rdns.measurement.example.com:
```
; Warning - every name in this file is ABSOLUTE!
$ORIGIN .
rdns.measurement.example.com       86400   IN      SOA     dns.measurement.example.com example.com 2022021000 28800 7200 604800 86400
rdns.measurement.example.com       300     IN      NS      dns.measurement.example.com
host22.rdns.measurement.example.com        300     IN      PTR     mail.measurement.example.com
host25.rdns.measurement.example.com        300     IN      PTR     tls-force.measurement.example.com
host26.rdns.measurement.example.com        300     IN      PTR     tls-invalid.measurement.example.com
host27.rdns.measurement.example.com        300     IN      PTR     greylisting.measurement.example.com
host28.rdns.measurement.example.com        300     IN      PTR     dns.measurement.example.com
host29.rdns.measurement.example.com        300     IN      PTR     dns-v6.measurement.example.com
host30.rdns.measurement.example.com        300     IN      PTR     dns-dnssec-broken.measurement.example.com
```
Please note:
- The PTR records must be delegated from `100.51.198.in-addr.arpa.` using CNAMEs, see https://www.ietf.org/rfc/rfc2317.txt. See below for an example zone file:

```
; Warning - every name in this file is ABSOLUTE!
; Warning: Parent zone used for CNAME delegation of reverse DNS! Not deployed on same node but usually provided by network
;          provider/hoster!
$ORIGIN 
100.51.198.in-addr.arpa        3600    IN      SOA     dns.example.com hostmaster.example.com 2022042100 28800 7200 604800 86400
100.51.198.in-addr.arpa        300     IN      NS      dns.example.com
100.51.198.in-addr.arpa        300     IN      NS      dns2.example.com
22.100.51.198.in-addr.arpa     300     IN      CNAME   host22.rdns.measurement.example.com
25.100.51.198.in-addr.arpa     300     IN      CNAME   host25.rdns.measurement.example.com
26.100.51.198.in-addr.arpa     300     IN      CNAME   host26.rdns.measurement.example.com
27.100.51.198.in-addr.arpa     300     IN      CNAME   host27.rdns.measurement.example.com
28.100.51.198.in-addr.arpa     300     IN      CNAME   host28.rdns.measurement.example.com
29.100.51.198.in-addr.arpa     300     IN      CNAME   host29.rdns.measurement.example.com
30.100.51.198.in-addr.arpa     300     IN      CNAME   host30.rdns.measurement.example.com
```

##### 0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.zone
```
 Warning - every name in this file is ABSOLUTE!
$ORIGIN .
3.0.0.0.d.a.e.d.0.c.1.d.6.0.a.2.ip6.arpa        86400   IN      SOA     dns.measurement.example.com hostmaster.example.com 2022020908 28800 7200 604800 86400
2.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.0.0.d.a.e.d.0.c.1.d.6.0.a.2.ip6.arpa        300     IN      PTR     mail.measurement.example.com
5.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.0.0.d.a.e.d.0.c.1.d.6.0.a.2.ip6.arpa        300     IN      PTR     tls-force.measurement.example.com
6.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.0.0.d.a.e.d.0.c.1.d.6.0.a.2.ip6.arpa        300     IN      PTR     tls-invalid.measurement.example.com
7.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.0.0.d.a.e.d.0.c.1.d.6.0.a.2.ip6.arpa        300     IN      PTR     greylisting.measurement.example.com
8.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.0.0.d.a.e.d.0.c.1.d.6.0.a.2.ip6.arpa        300     IN      PTR     dns.measurement.example.com
9.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.0.0.d.a.e.d.0.c.1.d.6.0.a.2.ip6.arpa        300     IN      PTR     dns-v6.measurement.example.com
0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.0.0.d.a.e.d.0.c.1.d.6.0.a.2.ip6.arpa        300     IN      PTR     dns-dnssec-broken.measurement.example.com
```
Please note:
- We are assuming that you can get a zone delegation for your /64's rDNS
- If this is not possible, the CNAME approach from IPv4 works as well

### dns-dnssec-broken.measurement.example.com
```
IPv4: 198.51.100.30
IPv6: 2001:db8::30
```

#### Setup a DNS server
Setup an authoritative DNS server of your choice (nsd, bind9, powerdns etc.), 
and configure the following zones.

Make sure the DNS server logs all queries it receives.

This host receives a zone delegation from the main DNS server. DNSSEC should be
broken in that delegation, i.e., the `DS` record for
dnssec-broken.measurement.example.com in measurement.example.com should not
match the DNSKEY for dnssec-broken.measurement.example.com.

Make sure that you setup the correct `NS` delegations in the parent zone,
including IPv4 and IPv6 glue!

##### dnssec-broken.measurement.example.com

```
; Warning - every name in this file is ABSOLUTE!
$ORIGIN .
dnssec-broken.measurement.example.com      86400   IN      SOA     dns-dnssec-broken.measurement.example.com hostmaster.example.com 2022020901 28800 7200 604800 86400
dnssec-broken.measurement.example.com      300     IN      NS      dns-dnssec-broken.measurement.example.com
v4-mail.dnssec-broken.measurement.example.com      300     IN      MX      10 mail-v4.measurement.example.com
v4-mail-host.dnssec-broken.measurement.example.com 300     IN      A       198.51.100.163
v6-mail.dnssec-broken.measurement.example.com      300     IN      MX      10 mail-v6.measurement.example.com
v6-mail-host.dnssec-broken.measurement.example.com 300     IN      AAAA    2001:db8::22
```


### dns-dnssec-broken.measurement.example.com
```
IPv4: 198.51.100.29
IPv6: 2001:db8::29
```

#### Setup a DNS server
Setup an authoritative DNS server of your choice (nsd, bind9, powerdns etc.), 
and configure the following zones.

Make sure the DNS server logs all queries it receives.

This host receives a zone delegation from the main DNS server. 
However, for the zone v6only.measurement.example.com, only `AAAA` (IPv6) glue
should be in measurement.example.com!

Make sure that you setup the correct `NS`  delegations in the parent zone,
*only* including IPv6 glue, and make sure that the DNSSEC delegation is
correctly configured!

##### v6only.measurement.example.com
```
; Warning - every name in this file is ABSOLUTE!
$ORIGIN .
v6only.measurement.example.com     86400   IN      SOA     dns-v6.measurement.example.com hostmaster.aperture-labs.org 2022020900 28800 7200 604800 86400
v6only.measurement.example.com     300     IN      NS      dns.v6only.measurement.example.com
dns.v6only.measurement.example.com 300     IN      AAAA    2001:db8::29
v4-mail.v6only.measurement.example.com     300     IN      MX      10 mail-v4.measurement.example.com
v4-mail-host.v6only.measurement.example.com        300     IN      A       198.51.100.22
v6-mail.v6only.measurement.example.com     300     IN      MX      10 mail-v6.measurement.example.com
v6-mail-host.v6only.measurement.example.com        300     IN      AAAA    2001:db8::22
```

### mail.measurement.example.com
```
IPv4: 198.51.100.22
IPv6: 2001:db8::22
```

The mail-host receives emails for the 'base' cases of our email measurements.
For that, you need to:
- Setup a mailserver that allows you to pipe-deliver to a program. While not
  strictly necessary, we recommend configuring TLS with a valid certificate for
this host, but also allowing plaintext delivery. In our measurements, we did
not activate TLS for inbound connections.
- Configure the mail-server to accept mails for a set of measurement domains
  and the measurement user(s).
- Increase the debug-level in your mailserver to log full SMTP sessions
- Place the session parsing tool `parse.py` in `/usr/local/sbin/` (or any other
  convenient path) and configure cron to run it every 5 minutes; The supplied
tool supports postfix.
- Place the pipe delivery tool `local_delivery.py` in `/usr/local/sbin/`
- Create folders for received data in `/srv` and make sure the users executing
  the pipe-delivery and logfile-parser can write to them Our toolchain has been
built around postfix 3.6, but in general can be adapted to any other
mail-server.

#### Domains
The base mailserver must at least accept mail for the following domains:
- v4-mail.measurement.example.com
- v6-mail.measurement.example.com
- v4-mail.v6only.measurement.example.com 
- v6-mail.v6only.measurement.example.com
- v4-mail.dnssec-broken.measurement.example.com
- v6-mail.dnssec-broken.measurement.example.com

In addition, you might want to also add a virtual domain table to add spam
domains to replicate the spam measurements from the paper.

In our case, we configured postfix as follows:
```
mydestination = localhost.$mydomain, localhost, v4-mail.measurement.example.com, v6-mail.measurement.example.com, v4-mail.v6only.measurement.example.com, v6-mail.v6only.measurement.example.com, v4-mail.dnssec-broken.measurement.example.com, v6-mail.dnssec-broken.measurement.example.com, /etc/postfix/domains
```

#### Parsing/Analysis scripts

To make the python tools run, several python scripts have to be installed,
specifically:

- smtplib
- ipaddress
- timeit 
- dnspython

Apart from that, the scripts should run with python 3+.

Place the scripts from `/src` into `/usr/local/sbin/` and adjust the `HOST`
variable to match the hostname (`$ hostname`) of the systems your are running
it on.  `local_delivery.py` can be installed in three `flavors`, depending on
whether SPAM catch-all measurements are configured.  The difference between
these three versions is the path to which outputs are written, see, e.g.,
`/example-setup/mail.measurement.email-security-scans.org/usr/local/sbin/local_delivery*`
in this repository.  Make sure the scripts have the executable bit set, i.e.,
`chmod +x /usr/local/sbin/parse.py` and `chmod +x
/usr/local/sbin/local_delivery*`

#### Pipe Delivery

To create a local part under the configured domains to which emails are
accepted, we create aliases that deliver to a pipe pointing at the delivery
script.

We have two aliases for pipe-delivery, as well as a PCRE file that enables the
catch-all for SPAM measurements.

We include these files in postfix' main.cf via:
```
alias_maps = hash:/etc/mail/aliases, regexp:/etc/mail/catch-all
```

##### /etc/mail/aliases
```
measurement: "|/usr/local/sbin/local_delivery.py"
```

Please note: run `newaliases` after changing the file to update
`/etc/mail/aliases.db`

##### /etc/mail/catch-all
```
/^.*/   "|/usr/local/sbin/local_delivery_all.py"
```
This catch-all is for the untargeted spam measurements.

#### Increase debug level of postfix
In postfix' main.cf, set:
```
debug_peer_level = 10
```

#### Create folders in /srv
We use and create the following folders:
```
mkdir -p /srv/mails
mkdir /srv/json
mkdir /srv/sessions
mkdir -p /srv/all/mails
mkdir /srv/all/json
```

Make sure that these folders are writable by the delivery-user; On our systems
this is `nobody`:

```
# chown -R nobody: /srv
```

#### Creating the session parse cronjob
To regularly parse SMTP sessions, create the following cron job under a user
that can read your `/var/log/maillog` (or equivalent):
```
*/5 *   *   *   *   /usr/local/sbin/parse_sessions.py
```

#### Verification
After making the above changes, restart postfix and send a testmail to:
```
measurement@v4-mail.measurement.example.com
```
You should see the mail being processed when tailing `/var/log/maillog`. After
delivery you should find a corresponding file in `/srv/mail` and `/srv/json`.
After the `parse.py` tool ran, you should also find a session extract in
`/srv/sessions`.

### greylisting.measurement.example.com
```
IPv4: 198.51.100.27
IPv6: 2001:db8::27
```

This host is in place to test senders' abilities in handling greylisting.
Configuration is analogous to that of the base mail host. The following changes
apply:

#### Domains
```
mydestination = $myhostname, localhost.$mydomain, localhost, v4-mail-greylisting.measurement.example.com, v6-mail-greylisting.measurement.example.com, /etc/postfix/domains
```

#### Greylisting

We installed postgrey to activate greylisting, and started it with
`--inet=10023` to make it listen on `localhost:10023`.  We tell postfix to use
greylisting with the following statement in `main.cf`:

```
smtpd_recipient_restrictions = reject_unauth_destination, check_policy_service inet:127.0.0.1:10023
```


### tls-force.measurement.example.com
```
IPv4: 198.51.100.25
IPv6: 2001:db8::25
```

This host is in place to test senders' abilities in handling TLS.
Configuration is analogous to that of the base mail host. The following changes
apply:

#### Domains
```
mydestination = $myhostname, localhost.$mydomain, localhost, mail-tls-force.measurement.example.com, /etc/postfix/domains
```

#### TLS certificate

We obtained a TLS certificate via let's encrypt. Postfix was configured as
follows:

```
smtpd_tls_cert_file=/etc/ssl/acme/tls-force.measurement.example.com.fullchain.pem
smtpd_tls_key_file=/etc/ssl/acme/private/tls-force.measurement.example.com.key
smtpd_use_tls=yes
smtpd_tls_auth_only=yes
smtpd_enforce_tls=yes
smtp_tls_security_level=may
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3
smtpd_tls_loglevel = 2
```

While SSLv2 and SSLv3 are disabled in postfix, they are no longer supported by
the underlying TLS library anyway.

### tls-invalid.measurement.example.com
```
IPv4: 198.51.100.26
IPv6: 2001:db8::26
```

This host is in place to test senders' abilities in handling invalid TLS
certificates.  Configuration is analogous to that of the base mail host. The
following changes apply:

#### Domains
```
mydestination = $myhostname, localhost.$mydomain, localhost, mail-tls-invalid.measurement.example.com, mail-tlsa-invalid.measurement.example.com, /etc/postfix/domains
```

#### TLS certificate
To ensure an invalid certificate, we re-used the certificate from tls-force obtained via Let's Encrypt. 
Postfix was configured as follows:
```
smtpd_tls_cert_file=/etc/ssl/acme/tls-force.measurement.example.com.fullchain.pem
smtpd_tls_key_file=/etc/ssl/acme/private/tls-force.measurement.example.com.key
smtpd_use_tls=yes
smtpd_tls_auth_only=yes
smtpd_enforce_tls=yes
smtp_tls_security_level=may
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3
smtpd_tls_loglevel = 2
```

While SSLv2 and SSLv3 are disabled in postfix, they are no longer supported by
the underlying TLS library anyway.

## Triggering a full measurement

To measure an email provider, you can now send an email to the following list
of email addresses:

```
measurement@v4-mail.measurement.example.com
measurement@v6-mail.measurement.example.com
measurement@v6-mail.v6only.measurement.example.com
measurement@v4-mail.v6only.measurement.example.com
measurement@v6-mail.dnssec-broken.measurement.example.com
measurement@v4-mail.dnssec-broken.measurement.example.com
measurement@v4-mail-greylisting.measurement.example.com
measurement@v6-mail-greylisting.measurement.example.com
measurement@mail-tls-force.measurement.example.com
measurement@mail-tls-invalid.measurement.example.com
measurement@mail-tlsa-invalid.measurement.example.com
```

For reference on what it means if these emails do (not) arrive at your
measurement setup (and to interpret the bounces you may receive), we would like
to direct you to the main paper.
