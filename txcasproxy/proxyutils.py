

import urlparse

def is_proxy_path_or_child(proxied_path, path):
    """
    """
    if path == proxied_path:
        return True
    if path.startswith(proxied_path):
        if path[len(proxied_path)] == '/':
            return True
    return False

def proxied_url_to_proxy_url(proxy_fqdn, proxy_port, proxied_netloc, proxied_path, target_url):
    """
    """
    p = urlparse.urlparse(target_url)
    if p.netloc == proxied_netloc:
        target_path = p.path
        if p.path.startswith(proxied_path):
            new_target_path = target_path[len(proxied_path):]
            proxy_netloc = "%s:%d" % (proxy_fqdn, proxy_port)
            p = urlparse.ParseResult(*tuple(p[:1] + (proxy_netloc, new_target_path) + p[3:]))
            new_target_url = urlparse.urlunparse(p)
            return new_target_url
    return None
    
def proxy_url_to_proxied_url(proxy_fqdn, proxy_port, proxied_netloc, proxied_path, target_url):
    """
    """
    proxy_netloc = "%s:%d" % (proxy_fqdn, proxy_port)
    p = urlparse.urlparse(target_url)
    if p.netloc == proxy_netloc:
        target_path = p.path
        if target_path == '':
            new_target_path = proxied_path
        else:
            if not target_path.startswith('/'):
                target_path = '/' + target_path
            new_target_path = proxied_path + target_path
        p = urlparse.ParseResult(*tuple(p[:1] + (proxied_netloc, new_target_path) + p[3:]))
        new_target_url = urlparse.urlunparse(p)
        return new_target_url
    return None
        
