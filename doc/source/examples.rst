====================
Example Integrations
====================

The following are examples for integrating `txcasproxy` with different web 
technologies.

------------
Apache + PHP
------------

.. literalinclude:: ../../examples/proxy-test.php
    :linenos:
    :language: php

Full example: :download:`proxy-test.php <../../examples/proxy-test.php>`

Serve `proxy-test.php` from Apache (or some other web server that will server 
up PHP).  Protect the URL with txcasproxy.  Browse to the web page to
see info about the logged in user and associated attributes.

Example command line:

.. code-block:: console

    $ twistd -n casproxy \
        -e 'ssl:9443:certKey=/path/to/server.crt.pem:privateKey=/path/to/server.key.pem' \
        -c 'https://cas.example.net/login' \
        -s 'https://cas.example.net/serviceValidate' \
        -p 'http://protected.example.org/' \
        -a 'tcp:9444'


