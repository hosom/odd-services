Bro Module for Funny Stuff on Networks
======================================

This is a grouping of Bro scripts which seeks to locate traffic that is considered to be anomalous on corporate networks. These aren't meant to indicate malicious activity, but should help you find funny stuff on a network you are either new to, or simply don't know well.

Installation
------------

::

		cd <prefix>/share/bro/site/
		git clone git://github.com/hosom/bro-odd-services.git odd-services
		echo "@load odd-services" >> local.bro

Configuration
-------------

There is no configuration necessary, however, it might be beneficial to use the hook located at OddServices::monitored. This hook can be used to tune the individual alerts within the package. For example, you could use this hook to ignore notices associated to SSH on port 2222/tcp--if that were normal in your environment. 