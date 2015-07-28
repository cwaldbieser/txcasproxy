*********************
The Twisted CAS Proxy
*********************

*txcasproxy* is a reverse authenticating proxy that is capable of authenticating
a user with an instance of the `Central Authentication Service`_ (CAS).  The 
proxy then passes a special header (**REMOTE_USER**) to the proxied target, which
allows application code to retrieve the user ID of the authenticated user.

*txcasproxy* is not unlike the combination of the Apache web server using the
module `mod_auth_cas`_.  The main difference is that *txcasproxy* is a 
dedicated proxy.  This highly specialized nature means that its configuration
is rather straightforward.  In many cases, the proxy can be configured with 
just a few command line options.

Because it uses an event-driven reactor rather than a thread
based approach, *txcasproxy* can sustain a high volume of connections.

*txcasproxy* can be customized via the Twisted plugin system.  Plugins
written in Python can be included when running the proxy from the command line.


.. _Central Authentication Service: https://github.com/Jasig/cas
.. _mod_auth_cas: https://github.com/Jasig/mod_auth_cas
