#! /usr/bin/env python

from __future__ import print_function
from fnmatch import fnmatch
import urlparse
import sys

def parse_url_pattern(pattern):
    if pattern is None:
        return None
    return urlparse.urlparse(pattern)

def normalize_netloc(scheme, netloc):
    if scheme == 'http':
        if not ':' in netloc:
            netloc = '{0}:80'.format(netloc)
    elif scheme == 'https':
        if not ':' in netloc:
            netloc = '{0}:443'.format(netloc)
    parts = netloc.split(':', 1)
    host = parts[0]
    if len(parts) == 2:
        try:
            port = int(parts[1])
        except ValueError:
            port = None
    else:
        port = None
    return (host, port)

def does_url_match_pattern(url, parsed_pattern):
    if parsed_pattern is None:
        return None
    p = urlparse.urlparse(url)
    scheme0 = p.scheme.lower()
    if scheme0 not in ('http', 'https', ''):
        return False
    scheme1 = parsed_pattern.scheme.lower()
    if scheme1 != '' and scheme0 != scheme1:
        return False
    host0, port0 = normalize_netloc(scheme0, p.netloc)
    host1, port1 = normalize_netloc(scheme1, parsed_pattern.netloc)
    if host1 != '*' and host0 != host1:
        return False
    if port1 not in ('*', None) and port0 != port1:
        return False
    if not fnmatch(p.path, parsed_pattern.path):
        return False
    if p.query != '':
        if parsed_pattern.query != '*':
            qs0 = set(urlparse.parse_qsl(p.query))
            qs1 = set(urlparse.parse_qsl(parsed_pattern.query))
            if qs0 != qs1:
                return False
    return True

if __name__ == "__main__":
    urls = [
        ('http://same.example.com/', 'http://same.example.com/'),
        ('http://different.example.com/', 'http://notthesame.example.net'),
        ('http://differentscheme.example.org/', 'https://differentscheme.example.org/'),
        ('http://sameport.example.net/', 'http://sameport.example.net:80/'),
        ('https://sameport.example.net/', 'https://sameport.example.net:443/'),
        ('http://differentport.example.net/', 'http://differentport.example.net:8080/'),
        ('http://differentpath.example.org/baz', 'http://differentpath.example.org/baz/'),
        (
            'http://differentquery.example.org/baz/?uno=1&dos=2', 
            'http://differentquery.example.org/baz/?uno=one&dos=two'
        ),
        (
            'http://samequery.example.org/baz/?quarter=25&nickle=5&penny=1', 
            'http://samequery.example.org/baz/?quarter=25&nickle=5&penny=1', 
        ),
        (
            'http://samequery.example.org/baz/?nickle=5&quarter=25&penny=1', 
            'http://samequery.example.org/baz/?quarter=25&nickle=5&penny=1', 
        ),
        ('http://same.example.com/', '//same.example.com/'),
        ('http://same.example.com/', '//*/'),
        ('http://different.example.com/', '//notthesame.example.net'),
        ('http://differentscheme.example.org/', 'https://*/'),
        ('http://sameport.example.net/', 'http://*:80/'),
        ('https://sameport.example.net/', 'https://*:443/'),
        ('http://differentport.example.net/', '//*:8080/'),
        ('http://samepath.example.org/baz/bar/bang', 'http://differentpath.example.org/baz/*'),
        (
            'http://samequery.example.org/baz/?quarter=25&nickle=5&penny=1', 
            'http://samequery.example.org/baz/?*', 
        ),
        ('/logout', '/logout'),
    ]         
    for url, pattern in urls:
        print("URL => {0}".format(url))
        print("Pattern => {0}".format(pattern))
        print("Match? => {0}".format(does_url_match_pattern(url, parse_url_pattern(pattern))))
        print("") 
