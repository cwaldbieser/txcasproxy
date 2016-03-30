=======
Options
=======

.. code-block:: console

    Usage: twistd [options] casproxy [options]
    Options:
          --help-plugins            Help about available plugins.
      -d, --debug                   Errors served as HTML.
      -v, --verbose                 Verbose logging.
          --logout-passthrough      Pass the logout request through to backend
                                    service prior to intercepting and redirecting.
      -e, --endpoint=               An endpoint connection string.
      -p, --proxied-url=            The base URL to proxy.
      -c, --cas-login=              The CAS /login URL.
      -s, --cas-service-validate=   The CAS /serviceValidate URL.
      -l, --cas-logout=             The CAS /logout URL.  Requires `logout` option
                                    to be set.
      -H, --header=                 The name of the header in which to pass the
                                    authenticated user ID. [default: REMOTE_USER]
          --fqdn=                   Explicitly specify the FQDN that should be
                                    included in URL callbacks.
      -a, --auth-info-endpoint=     Endpoint for the authentication info service.
      -A, --auth-info-resource=     Resource on the main site that provides
                                    authentication info.
          --help-plugin=            Help or a specific plugin.
      -t, --template-dir=           Folder containing templates.
      -T, --template-resource=      Base resource for templates. [default:
                                    /_templates]
      -S, --session-length=         Session length in seconds. [default: 900]
      -P, --proxy-client-endpoint=  An endpoint connection string for the proxy web
                                    client.
      -C, --cas-client-endpoint=    An endpoint connection string for the back
                                    channel CAS web client.
          --help                    Display this help and exit.
          --plugin=                 Include a plugin.
          --version                 Display Twisted version and exit.
          --addCA=                  Add a trusted CA public cert (PEM format).
          --exclude=                Exclude a specific resource from being proxied.
      -L, --logout=                 Add a logout resource pattern to intercept and
                                    terminate the proxy session.
          --excludeBranch=          Exclude a resource and all its children from
                                    being proxied

-----------------------
Endpoint Specifications
-----------------------

Endpoints are string descriptions of a socket connection a client or
server makes.  For more details, see the `Twisted endpoints documentation`_.

-----------
TLS Options
-----------

Whenever the software attempts to make an HTTPS connection to a proxied site or
to a CAS service, it must establish a trust model based on certificates that
are signed by some authority.  By default, the service uses the platform's
underlying certificate authority (CA) trust store.  You can extend the 
default trust store using the :option:`addCA` option.

You can exercise complete and independent control over the trust stores for the
CAS web client and/or the proxy web client by specifying `client TLS endpoints`_.
Client endpoints allow you to control many aspects of the underlying connection,
including client certificates, trust roots, and even the type of underlying
connetion (e.g. TCP IP address or UNIX domain socket).

.. note::

    Client endpoints do *not* work in conjunction with the 
    :option:`addCA` option.  That option only affects the default web client.

''''''''''''''''''''''''
More on Client Endpoints
''''''''''''''''''''''''

Because client endpoints must necessarilly specify the connection details, the
scheme, host, and port of the URL become superfluous.  When using client 
endpoints it is therefore permissable (and preferable) to omit the URL scheme,
host, and port.  E.g. '///cas/serviceValidate' rather than 
'https://cas.example.net:443/cas/serviceValidate'.  In fact, if a client
endpoint is used, those parts of the actual URL will be ignored when retieving
the resource.

----------------------
The REMOTE_USER Header
----------------------
The reverse proxy attempts to transmit the authenticated user name to the proxied
web site as the HTTP header, 'REMOTE_USER'.  Some web servers will modify or
reject certain headers.  

For example, Apache2 will discard 'REMOTE_USER'.  It will convert 'Remote-User' 
into 'HTTP_REMOTE_USER' by the time it reaches the proxied site.

The :option:`--header` option lets you specify the name of the header to pass on
to the proxied site.

------------------
Ending the Session
------------------

The :option:`logout` option allows you to specify a URL pattern that will be
intercepted by the proxy and cause it to terminate its authenticated session.
This option may be specified multiple times.

The logout pattern may be a regular URL less the scheme and netlocation.  
Additionally, the path may include globbing meta-characters.

A query string does not need to be supplied in the pattern.  In this case, 
*any* query string will match the pattern.  This is also the case if the 
entire query string for the pattern is '*'.  If the pattern query string 
is '!', then a URL will *only* match if it has no query string (or an 
empty query string).

If the pattern contains query string parameters, then a URL will *only* match
if it contains *all* the query parameters and values specified in the pattern.
A URL *may* contain addtional query string parameters and still match.

If the :option:`cas-logout` URL option is also specified, an HTTP redirect is 
issued to that URL to terminate the SSO session.

If the :option:`cas-logout` option is not specified, the proxy will reverse 
proxy the resource (it is not protected).  This can be useful if your application
allows you to specify a logout URL which you can point to the CAS logout URL.
This allows the application to perform its own session termination before the
SSO session is ended.  It is also useful if the service does not participate in
an SSO session but simply uses a CAS service to authenticate.

The :option:`logout-passthrough` option can be used to alter the 
:option:`cas-logout` behavior.  The initial request will be passed through to
the proxied service, but its response will be silently discarded.  The proxy
will issue a response to redirect the requesting agent to the CAS logout
URL.  This is useful if you require the proxied service to terminate its
own local session in addition to terminating the CAS session.

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
    a list with a single element.

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

--------------
Error Handling
--------------

The :option:`debug` option causes any *unexpected* errors (i.e. bugs) to be output to HTML.

There are two expected error scenarios when the proxy may be required to display its own content.
If a browser presents a URL to the proxy which contains a CAS service ticket that fails validation,
the proxy will emit a 403 (Forbidden) HTTP response code.  By default, no content is included.

The second case is when something external to the proxy has gone wrong (perhaps the CAS service
is unavailable).  In this case, a HTTP 500 response code is returned by the proxy.  Again, there
is no content by default.

You can provide custom error pages by specifying the :option:`template_dir` option.  This should
be the path to a folder that contains subfolders :file:`static` and :file:`error`.  The 
:file:`error` folder should contain templates :file:`403.jinja2` and :file:`500.jinja2`, which
should be `Jinja2 templates`_.  These templates can access the HTTP request object as the name 
`request`.  The :file:`static` folder may contain any static assets required for rendering the
final HTML pages (e.g. images, stylesheets, scripts).  These will be served from 
`/_templates/static` by default.  You can change the root resource with the 
:option:`template-resource` option.  The name `static_base` is made available to the templates
and can be used as a prefix for static resources (the prefix includes a trailing slash).

.. note::

    Only the top-level resource can be changed.  For example, if you change the resource to
    `/foo`, the content will be served from `/foo/static/`.


.. _Twisted endpoints documentation: https://twistedmatrix.com/documents/current/core/howto/endpoints.html
.. _client TLS endpoints: https://twistedmatrix.com/documents/current/core/howto/endpoints.html#clients
.. _Jinja2 templates: http://jinja.pocoo.org/
