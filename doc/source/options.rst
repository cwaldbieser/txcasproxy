=======
Options
=======

.. code-block:: console

    Usage: twistd [options] casproxy [options]
    Options:
          --help-plugins           Help about available plugins.
      -e, --endpoint=              An endpoint connection string.
      -p, --proxied-url=           The base URL to proxy.
      -c, --cas-login=             The CAS /login URL.
      -s, --cas-service-validate=  The CAS /serviceValidate URL.
          --fqdn=                  Explicitly specify the FQDN that should be
                                   included in URL callbacks.
      -a, --auth-info-endpoint=    Endpoint for the authentication info service.
      -A, --auth-info-resource=    Resource on the main site that provides
                                   authentication info.
          --help-plugin=           Help or a specific plugin.
          --version                Display Twisted version and exit.
          --addCA=                 Add a trusted CA public cert (PEM format).
          --help                   Display this help and exit.
          --plugin=                Include a plugin.

-----------------------
Endpoint Specifications
-----------------------

Endpoints are string descriptions of a socket connection a client or
server makes.  For more details, see the `Twisted endpoints documentation`_.

----------------------------------
Authentication Information Service
----------------------------------

If you specify an endpoint for the :option:`auth-info-endpoint` option, a
web site will be created at that endpoint.  The site responds to HTTP GET 
requests for resources of the form `/$USERNAME`, where `$USERNAME` must be
a user name that has authenticated with the proxy.  The response will be
a JSON document that maps attribute names to lists of values.

.. NOTE::

    Even attributes that are single-valued have their values expressed as
    a list with a sigle element.

The intention is that access to this site should be limited to the protected 
service (e.g. with a host based firewall).  The protected service can then
use this site to retreive attributes for authenticated users using a simple
RESTful web service.

-----------------------------------
Authentication Information Resource
-----------------------------------

The :option:`auth-info-resource` can be used to specify a resource on the main
site which will respond with a JSON document containing mappings for *username*
and *attributes*.  The *attributes* key maps to an attribute map identical to
the one provided by the authentication information service.

This resource is valid only for requests associated with an already 
authenticated session.  It is therefore more convenient for a client which
has authenticated with the proxy to access than for code from the protected
service.

.. _Twisted endpoints documentation: https://twistedmatrix.com/documents/current/core/howto/endpoints.html
