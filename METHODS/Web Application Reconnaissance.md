## Google Dorking
A technique using advanced search operators to find specific, often sensitive, information on the internet through standard searches. It exploits Google's algorithms to locate exposed login portals, private files, or security vulnerabilities, often utilized by security professionals, journalists, and hackers.

#### FILTERS
* `allintext:"keyword"` - allintext
* `intext:"keyword"` - intext
* `inurl:"keyword"` - inurl
* `allinurl:"keyword"` - allinurl
* `intitle:"keyword"` - intitle
* `allintitle:"keyword"` - allintitle
* `site:"google.com"` - site
* `filetype:"pdf"` - filetype
* `link:"keyword"` - link
* `numrange:321-325` - numrange
* `filetype:pdf & (before:2000-01-01 after:2001-01-01)` - before and after
* `inanchor:rat` - inanchor
* `allinpostauthor:"keyword"` - allinpostauthor
* `related:google.com` - related
* `cache:google.com` - cache

## Certificate Transparency
Certificate transparency reveals subdomains that might not be linked anywhere on the main site, and it allows users to see historical records and real-time monitoring. Traditionally, if a **Certificate Authority** issued a TLS certificate for a domain without the owner's permission, it could go unnoticed for months. 

#### USAGE
* Query: `%.example.com` - Returns every logged subdomain for `example.com` that has ever had an **SSL/TLS certificate issued**
* Query: `Target Corp` - Find certificates issued to a specific legal entity
* Query: `target.com` - Find only the root certificate details

## Discovering Subdomains
It is the process of identifying all the sub-domains associated with a primary domain. 
A tool that I can recommend to use for finding subdomains
[Subfinder by Project Discovery](https://github.com/projectdiscovery/subfinder)

#### USAGE
The tool **Subfinder** uses the `-d` flag to specify the domain to enumerate its subdomains 
	`subfinder -d hackerone.com`

You can also pipe results to other tools
	`subfinder -d hackerone.com | httpx -silent`

More info on how to use the tool [Subfinder Docs](https://docs.projectdiscovery.io/opensource/subfinder/running)


## Using Shodan
It is a specialized search engine that scans the internet to index devices, servers, and IoT gadgets directly connected to the web. Often called a "hacker search engine", it allows users to find exposed systems, open ports, and vulnerabilities using filters for location, organization, or service type.

#### USAGE
Basic query examples are the following:

Find a specific product 
	`product:Apache`
Services that has the word "Apache" in their headings 
	`Apache`
Services with a hostname containing either "google.com" OR "facebook.com" 
	`hostname:google.com,facebook.com`
Websites that have the word "Apache" in their HTML
	`http.html:Apache`
Websites that are using the Bootstrap CSS framework
	`http.component:bootstrap`
Websites that support TLS 1.3
	`ssl.version:tlsv1.3 HTTP`
Websites that support HTTP/2
	`ssl.alpn:h2`
SSH on port 22 or 3333
	`ssh port:22,3333`
SSH on non-standard ports
	`ssh -port:22`
Public VNC services hiding behind common web ports
	`has_screenshot:true rfb disabled port:80,443`
Industrial control systems identified using machine learning
	`screenshot.label:ics`
Search the OCR in Remote Desktops for compromised by ransomware
	`has_screenshot:true encrypted attention`
More query examples at [Shodan Search Query Examples](https://www.shodan.io/search/examples)
As an option, you can install [shodan-cli](https://help.shodan.io/command-line-interface/0-installation)

#### Info Gathering with httpx
httpx is a fast and multi-purpose HTTP toolkit built to support running multiple probes using a public library. Probes are specific tests or checks to gather information about web servers, URLs, or other HTTP elements.

A Docs on how to install this tool [Installing httpx](https://docs.projectdiscovery.io/opensource/httpx/install)

#### USAGE
* The tool httpx accepts a list `-l string`, request `-rr string`, and target hosts(s) `-u string[]`
* The tool will fall-back to HTTP if HTTPS is not reachable
* You can use the flag `-no-fallback` to probe and display both HTTP and HTTPS result
* Custom scheme for ports can be defined with `-ports http:443,http:80,https:8443`
More details can be read here [httpx tool usage](https://docs.projectdiscovery.io/opensource/httpx/usage)

## Port Scanning
Web ports are like specific doors or channels through which internet traffic flows. There are some tools I could recommend when port scanning

[Nmap](https://nmap.org/) - is a free and open source utility for network discovery and security auditing. This is a go to tool if you're trying to probe and fingerprint a port with details to help you enumerate
[RustScan](https://github.com/bee-san/RustScan) - a modern port scanner written in Rust to find ports quickly. You can use this tool if you're trying to probe for open ports fast. The output is automatically piped to nmap to fingerprint the services for enumeration.

Common ports are using **443** for **HTTPS**, while port **80** for **HTTP**. However, web applications often run on various other ports, especially in development environments and for specific services.

Port **3000** is a standard for development servers particularly for **Node.js** ecosystem. Developers often see their application running in `localhost:3000`

Port **8080** is an alternative for **HTTP** port, this is frequently used when port **80** is unavailable or when running multiple web services on the same machine. Java applications, particularly those running in Apache Tomcat, traditionally use this port.

Port **5000** is for python developers that use **Flask** applications. It is commonly used for backend services and APIs, particularly in microservices architectures where multiple small services need to run independently.

Port **4200** is used by **Angular** developers, and is the default port for Angular development server. Developers access their applications through `localhost:4200`

Port **9000** is often used for development tools and services. An example would be **SonarQube**, a popular code quality tool, uses port 9000 by default. Many organizations also use this port range (9000-9999) for internal tools and services.

Port **8888** Commonly associated with **Jupyter Notebooks**, frequently used in data science and analytics applications

Port **8443** is an alternative for **HTTPS**, often used in enterprise environments where the standard port 443 is reserved for primary web traffic. It provides the same level of security as 443 but allows organizations to run multiple secure services on the same server.

Port **5432** this is used by **PostgreSQL** databases. Modern web applications often need to expose database ports for direct connections from development tools or other services.

Port **27017** **MongoDB**'s default port is another example of a service-specific port that web developers regularly work with. While it's not serving web pages, it's crucial for many web applications that use MongoDB as their database.

Port **6379** is **Redis**, an in-memory data structure store often used for caching and real-time data in web applications. 

## Wordlists
A wordlists is a text file containing a collection of words, phrases, numbers, or characters used to automate attacks. They act as the "dictionary" in dictionary attacks, providing a list of potential inputs for password cracking, username enumeration, or discovering hidden web directories.

A common wordlists that is mostly used is [rockyou](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz). This repository is the common go to also [SecLists](https://github.com/danielmiessler/SecLists)

Other wordlists which you can also access is [AssetNote](https://wordlists.assetnote.io/)

## DNS Resolution
It is essentially the "address book" service of the internet. Since computer communicate using IP addresses (like `192.168.1.1`), but humans prefer names (like `google.com`), DNS resolution is the multi-step process of translating that hostname into a machine-readable IP address. 

#### TOOLS
[massDNS](https://github.com/blechschmidt/massdns) is significantly more efficient that traditional DNS resolvers or tools like [httpx](https://github.com/projectdiscovery/httpx) when validating large sets of subdomains, particularly those generated by enumeration tools like [subfinder](https://github.com/projectdiscovery/subfinder). The key advantage lies in its asynchronous DNS resolution capabilities and raw socket usage, allowing it to perform tens of thousands of DNS queries per seconds compared to the much slower sequential resolution of standard tools.

## Subdomain Brute forcing
Is an active reconnaissance technique where an attacker or ethical hacker attempts to guess valid subdomains by systematically testing a massive list of potential names against a target's DNS server.

#### METHOD
You would need a [DNS wordlists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS) that a **fuzzer** tool would use to put the values. Then I recommend using [shuffleDNS](https://github.com/projectdiscovery/shuffledns), it is a wrapper around [massDNS](https://github.com/blechschmidt/massdns), written in go, that allows you to enumerate valid subdomains using active bruteforcing, as well as resolve subdomains with wildcard handling and easy input-output support. Then you would need [resolvers](https://github.com/proabiral/Fresh-Resolvers) to validate DNS from [public-dns.info](https://public-dns.info/nameservers.txt)

#### EXAMPLE
`shuffledns -d example.com -w /dns_wordlists -r /resolvers.txt -mode bruteforce -m massdns --silent`
	`-w` - The flag that points to your wordlists to be used
	`-r` - Resolvers to validate DNS
	`-mode` - Specify the execution mode
	`--silent` - Show only subdomains in output

## DNS Permutations
Also known as **DNS Alteration** is a sophisticated reconnaissance technique used to discover subdomains by taking already known subdomains and shuffling them with common prefixes, suffixes, and numbers.

#### TOOL
A tool that I would use is [dnsgen](https://github.com/AlephNullSK/dnsgen) it generates intelligent domain name variations to assist in subdomain discovery and security assessments.

#### USAGE
Basic domain permutation
	`dnsgen domains.txt`
With custom wordlist and output file
	`dnsgen -w custom_wordlist.txt -o results.txt domains.txt`
Using fast mode for quick assessment
	`dnsgen -f domains.txt`
Pipe with [massDNS](https://github.com/blechschmidt/massdns) for resolution
	`cat domains.txt | dnsgen - | massdns -r resolvers.txt -t A -o J --flush 2>/dev/null`

A sample output for [permutation techniques](https://github.com/AlephNullSK/dnsgen?tab=readme-ov-file#%EF%B8%8F-permutation-techniques) can be found here:

## FFUF Basics
This tool is a web fuzzer written in Go language. It is an automated security tool that injects massive amounts of random, malformed, or unexpected data into web application inputs (forms, URL parameters, headers) to identify bugs, security vulnerabilities, and hidden files.

#### USAGE
Two things are mandatory when using Ffuf:
- Having a wordlist, or a command that provides different inputs
- Setting up a `FUZZ` keyword in some part of the request
`ffuf -w wordlists.txt -u 'https://example.com/FUZZ'`

You can also supply ffuf with multiple wordlists, the catch is to configure a custom keyword for them. THe behavior differs from the operation mode selected.
`ffuf -w domains.txt:DOMAIN -w wordlists.txt:WORD -u 'https://example.com`

**Clusterbomb mode** is possible and is the default mode for multi-wordlists, it is active if no other `-mode` is selected.
`ffuf -mode clusterbomb -w domains.txt:DOMAIN -w wordlists.txt:WORD -u 'https://DOMAIN/WORD'`

**Pitchfork mode** is an alternative multi-wordlist mode. When running a pitchfork operation, the words from the wordlists are read in lockstep.
`ffuf -mode pitchfork -w usernames.txt:USER -w user_ids.txt:UID -u 'https://example.com/u/UID/profile/USER'`

More information can be found [here](https://github.com/ffuf/ffuf/wiki)

Ffuf can also be used to enumerate virtual host to uncover hidden subdomains. An `-H` flag is needed to refer to the host header then place the word `FUZZ` at the beginning of the domain to indicate the fuzzing position.
`ffuf -w wordlists.txt -u 'http://10.10.10.1' -H "Host: FUZZ.inlanefreight.htb"`