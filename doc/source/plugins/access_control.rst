==============
Access Control
==============

This plugin provides some basic access control based on CAS attributes provided
to the proxy during ticket validation.  Attribute matching is based on a 
configuration file in YAML format.  The top-level keys of the configuration are
attributes that must have been released to the proxy for the authenticated user.
If those attributes are not released.  If the presence of an attribute is 
sufficient, then the literal `null` may be used for the value.

If an `allowed_values` key is present as the value, then a list of allowed 
values is expected to follow.  If *any* of the values matches a corresponding
value in the released attributes, then that test is passed.

If one or more tests are failed, then access will be denied, and the user-agent
will be presented with the 403 ("Forbidden") template as a response.

Example:

.. code-block:: yaml

    ---
    memberOf:
        allowed_values:
            - cn=authorized,ou=groups,dc=example,dc=org
    objectClass: null

In the above example, the attributes 'memberOf' and 'objectClass' must both have
been released to the proxy during ticket validation or the authenticated user 
will be denied access.  Further, the 'memberOf' attribute must have at least one
value that matches 'cn=authorized,ou=groups,dc=example,dc=org'.

