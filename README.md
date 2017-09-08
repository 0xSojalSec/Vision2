# Vision

Nmap's XML result parse and NVD's CPE correlation to search CVE. You can use that to find public vulnerabilities in services... 

```..::: VISION v0.1 :::...
Nmap\'s XML result parser and NVD's CPE correlation to search CVE

Example:
python vision2.py -f result_scan.xml -l 3 -o txt

Coded by Mthbernades and CoolerVoid

- https://github.com/mthbernardes
- https://github.com/CoolerVoid

usage: vision2.py [-h] -f NMAPFILE [-l LIMIT] [-o OUTPUT]
vision2.py: error: argument -f/--nmap-file is required

```

## Example of results:
```
$ python Vision-cpe.py -f result_scan.xml -l 3 -o txt

::::: Vision v0.1 - nmap NVD's cpe correlation - Coded by CoolerVoid
Host: 127.0.0.1
Port: 53
cpe:/a:isc:bind:9.8.1:p1

	URL: https://nvd.nist.gov/vuln/detail/CVE-2016-9131
	Description: named in ISC BIND 9.x before 9.9.9-P5, 9.10.x before 9.10.4-P5, and 9.11.x before 9.11.0-P2 allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a malformed response to an RTYPE ANY query.

	URL: https://nvd.nist.gov/vuln/detail/CVE-2016-8864
	Description: named in ISC BIND 9.x before 9.9.9-P4, 9.10.x before 9.10.4-P4, and 9.11.x before 9.11.0-P1 allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a DNAME record in the answer section of a response to a recursive query, related to db.c and resolver.c.

	URL: https://nvd.nist.gov/vuln/detail/CVE-2016-2848
	Description: ISC BIND 9.1.0 through 9.8.4-P2 and 9.9.0 through 9.9.2-P2 allows remote attackers to cause a denial of service (assertion failure and daemon exit) via malformed options data in an OPT resource record.
::::: Vision v0.1 - nmap NVD's cpe correlation - Coded by CoolerVoid

Host: 127.0.0.1
Port: 22
cpe:/o:linux:linux_kernel

	URL: https://nvd.nist.gov/vuln/detail/CVE-2017-14156
	Description: The atyfb_ioctl function in drivers/video/fbdev/aty/atyfb_base.c in the Linux kernel through 4.12.10 does not initialize a certain data structure, which allows local users to obtain sensitive information from kernel stack memory by reading locations associated with padding bytes.

	URL: https://nvd.nist.gov/vuln/detail/CVE-2017-14140
	Description: The move_pages system call in mm/migrate.c in the Linux kernel before 4.12.9 doesn't check the effective uid of the target process, enabling a local attacker to learn the memory layout of a setuid executable despite ASLR.

	URL: https://nvd.nist.gov/vuln/detail/CVE-2017-14106
	Description: The tcp_disconnect function in net/ipv4/tcp.c in the Linux kernel before 4.12 allows local users to cause a denial of service (__tcp_select_window divide-by-zero error and system crash) by triggering a disconnect within a certain tcp_recvmsg code path.


::::: Vision v0.1 - nmap NVD's cpe correlation - Coded by CoolerVoid

Host: 127.0.0.1
Port: 53
cpe:/a:isc:bind:none


::::: Vision v0.1 - nmap NVD's cpe correlation - Coded by CoolerVoid

Host: 127.0.0.1
Port: 80
cpe:/a:igor_sysoev:nginx:1.4.1

	URL: https://nvd.nist.gov/vuln/detail/CVE-2014-0133
	Description: Heap-based buffer overflow in the SPDY implementation in nginx 1.3.15 before 1.4.7 and 1.5.x before 1.5.12 allows remote attackers to execute arbitrary code via a crafted request.

	URL: https://nvd.nist.gov/vuln/detail/CVE-2013-4547
	Description: nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 allows remote attackers to bypass intended restrictions via an unescaped space character in a URI.


::::: Vision v0.1 - nmap NVD's cpe correlation - Coded by CoolerVoid

Host: 127.0.0.1
Port: 465
cpe:/a:postfix:postfix

	URL: https://nvd.nist.gov/vuln/detail/CVE-2012-0811
	Description: Multiple SQL injection vulnerabilities in Postfix Admin (aka postfixadmin) before 2.3.5 allow remote authenticated users to execute arbitrary SQL commands via (1) the pw parameter to the pacrypt function, when mysql_encrypt is configured, or (2) unspecified vectors that are used in backup files generated by backup.php.

	URL: https://nvd.nist.gov/vuln/detail/CVE-2011-1720
	Description: The SMTP server in Postfix before 2.5.13, 2.6.x before 2.6.10, 2.7.x before 2.7.4, and 2.8.x before 2.8.3, when certain Cyrus SASL authentication methods are enabled, does not create a new server handle after client authentication fails, which allows remote attackers to cause a denial of service (heap memory corruption and daemon crash) or possibly execute arbitrary code via an invalid AUTH command with one method followed by an AUTH command with a different method.

	URL: https://nvd.nist.gov/vuln/detail/CVE-2011-0411
	Description: The STARTTLS implementation in Postfix 2.4.x before 2.4.16, 2.5.x before 2.5.12, 2.6.x before 2.6.9, and 2.7.x before 2.7.3 does not properly restrict I/O buffering, which allows man-in-the-middle attackers to insert commands into encrypted SMTP sessions by sending a cleartext command that is processed after TLS is in place, related to a "plaintext command injection" attack.


::::: Vision v0.1 - nmap NVD's cpe correlation - Coded by CoolerVoid

Host: 127.0.0.1
Port: 8443
cpe:/a:lighttpd:lighttpd

	URL: https://nvd.nist.gov/vuln/detail/CVE-2015-3200
	Description: mod_auth in lighttpd before 1.4.36 allows remote attackers to inject arbitrary log entries via a basic HTTP authentication string without a colon character, as demonstrated by a string containing a NULL and new line character.

	URL: https://nvd.nist.gov/vuln/detail/CVE-2014-2324
	Description: Multiple directory traversal vulnerabilities in (1) mod_evhost and (2) mod_simple_vhost in lighttpd before 1.4.35 allow remote attackers to read arbitrary files via a .. (dot dot) in the host name, related to request_check_hostname.

	URL: https://nvd.nist.gov/vuln/detail/CVE-2014-2323
	Description: SQL injection vulnerability in mod_mysql_vhost.c in lighttpd before 1.4.35 allows remote attackers to execute arbitrary SQL commands via the host name, related to request_check_hostname.


...

```

## Common questions:

## How to write XML output on Nmap ?
https://nmap.org/book/output-formats-xml-output.html

## What is a CPE  ?

https://nmap.org/book/output-formats-cpe.html

https://nvd.nist.gov/products/cpe

## What is a CVE ?

https://cve.mitre.org/


## This is a true vulnerability scanner ?

Nop, this script is util to audit banners of services, this tool don't test inputs... Vulnerability scanner its complex, look that following http://www.openvas.org/




## Authors: 

# mthbernades and CoolerVoid 

https://github.com/mthbernardes

https://github.com/CoolerVoid

Old version using SAX style parse:
https://github.com/CoolerVoid/Vision

Date: Ter Set  5 02:00:09 2017


