#!/usr/bin/env python
# Run this with
# PYTHONPATH=</path/to/server> DJANGO_SETTINGS_MODULE=mobile.settings </path/to/server/>tornado_server.py
# Serves by default at
# http://localhost:8000/hello-tornado
 
from tornado.options import options, define, parse_command_line
from config.wsgi import application
from django.conf import settings
import logging
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.wsgi

from meterproxy import ProxyHandler
 
define('port', type=int, default=8000)
# tornado.options.options['log_file_prefix'].set('/var/www/myapp/logs/tornado_server.log')
tornado.options.parse_command_line()
 
def main():
 
    logger = logging.getLogger(__name__)
    wsgi_app = tornado.wsgi.WSGIContainer(
        application)

    ProxyHandler.proxy_to = settings.HANDLER_URL

    tornado_app = tornado.web.Application(
        [
            ('/proxy/', ProxyHandler),
            ('.*', tornado.web.FallbackHandler, dict(fallback=wsgi_app)),
        ], debug=True)
    logger.info("Tornado server starting...")
    server = tornado.httpserver.HTTPServer(tornado_app)
    server.listen(options.port)

    tornado.ioloop.IOLoop.instance().start()
 
if __name__ == '__main__':
    main()
