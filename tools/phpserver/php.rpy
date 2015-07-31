
from twisted.web import static, twcgi
import os

class PHPScript(twcgi.FilteredScript):
    filter = '/usr/bin/php-cgi'

    def runProcess(self, env, request, qargs=[]):
        env['REDIRECT_STATUS'] = ''
        return twcgi.FilteredScript.runProcess(self, env, request, qargs)

resource = static.File(os.path.abspath("./www"))
resource.processors = {".php": PHPScript}
resource.indexNames = ['index.php']

