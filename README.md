# mpdtls-vpn

A simple VPN application using Multipath DTLS
[![DOI](https://zenodo.org/badge/13220/MultipathDTLS/mpdtls-vpn.svg)](http://dx.doi.org/10.5281/zenodo.17920)


## Installation

You should have wolfSSL-MPDTLS installed [![DOI](https://zenodo.org/badge/13220/MultipathDTLS/wolfssl-mpdtls.svg)](http://dx.doi.org/10.5281/zenodo.17919)
and do not forget to install it with the option --enable-mpdtls when executing the configure.

According to the cipher suite used, you may need to specify additional options such as --enable-ecc (for elliptic curves) or others.

Then you can run make and you should have two executables (client and server). Each of them has a -h (help) option to help you understand the different commands available.

## How to use ?

Run the server first, then run the client and indicate the server IP address with the -s option. 
Warning ! If your client or server is behind a NAT, you will have troubles with the multipath.

A TUN interface should have appeared if you run "ifconfig" and an IP address has been attributed  to this interface. You may now send traffic to this address and all packets will be sent to the server using Multipath DTLS
