#!/usr/bin/env python
#
# Simple asynchronous HTTP proxy. 
#
# GET/POST proxying based on
# http://groups.google.com/group/python-tornado/msg/7bea08e7a049cf26
# 
# Modified from "tornado_proxy" 
# https://github.com/senko/tornado-proxy
# Copyright (C) 2012 Senko Rasic <senko.rasic@dobarkod.hr>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

import logging
import os
import sys
import socket
from urlparse import urlparse
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO

import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
import tornado.httpclient

from base64 import b64encode, b64decode 

import code

logger = logging.getLogger('proxy_to_meterpreter')
file_logger = logging.FileHandler('./meterproxy.log')
logger.addHandler(file_logger)
logger.setLevel(logging.DEBUG)

phost = None
pport = None

__all__ = ['ProxyHandler', 'run_proxy']

def decode(data):
    # logger.debug("[!] DECODE BEFORE: %s",data)
    # logger.debug("[!] DECODE: %s", b64decode(data))
    return b64decode(data)

def encode(data):
    # logger.debug("[!] ENCODE BEFORE: %s",data)
    # logger.debug("[!] ENCODE: %s", b64encode(data))
    return b64encode(data)

def fetch_request(url, callback, **kwargs):
    logger.debug("[!] Fetching for %s", url)
    req = tornado.httpclient.HTTPRequest(url, **kwargs)
    client = tornado.httpclient.AsyncHTTPClient()
    client.fetch(req, callback)


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

        if hasattr(self, 'headers') and self.headers is not None:
            content_len = int(self.headers.getheader('content-length', 0))
            self.body = self.rfile.read(content_len)
        else:
            self.body = 0

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message



class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST']
    proxy_to = None

    @tornado.web.asynchronous
    def get(self):
        logger.debug('Handle %s request to %s', self.request.method,
                     self.request.uri)

        def handle_response(response):
            # code.interact(local=dict(globals(), **locals()))
            logger.debug("[!] Handling Response: %s",response)
            if (response.error and not
                    isinstance(response.error, tornado.httpclient.HTTPError)):
                self.set_status(500)
                self.write('Internal server error:\n' + str(response.error))
            else:
                self.set_status(response.code)
                for header in ('Date', 'Cache-Control', 'Server','Content-Type', 'Location'):
                    v = response.headers.get(header)
                    if v:
                        self.set_header(header, v)
                v = response.headers.get_list('Set-Cookie')
                if v:
                    for i in v:
                        self.add_header('Set-Cookie', i)

                content = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: Keep-Alive\r\nServer: Apache\r\nContent-Length: {content_length}\r\n\r\n{body}\r\n".format(content_length=len(response.body), body=response.body)

                if response.body:
                    self.write(encode(content))
            self.finish()

        # The body contains the raw request from the client, base64-encoded. So we decode it
        # and send it off to the handler as if it were the original request. Then we take the
        # handler's response, package it up, base64-encode it, then send it as our response body.
        body = decode(self.request.body)
        if not body:
            logger.debug('Empty body')
            body = None
            self.set_status(200)
            self.write('200 OK')
            self.finish()
            return

        parsed_request = HTTPRequest(body)

        logger.debug("[!] Request for: %s", parsed_request.path)

        logger.debug('METHOD: {}'.format(parsed_request.command))
        logger.debug('HEADERS: {}'.format(parsed_request.headers))
        logger.debug('BODY: ({}) {}'.format(len(parsed_request.body), parsed_request.body))

        request_uri = self.proxy_to + '/' + parsed_request.path.lstrip('/')

        try:
            fetch_request(
                request_uri, handle_response,
                method=parsed_request.command, body=parsed_request.body,
                headers=None, follow_redirects=False,
                allow_nonstandard_methods=True)
        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                handle_response(e.response)
                logger.debug("[!] Handle Response Exception")
            else:
                logger.debug("[!] Exception after else")
                self.set_status(500)
                self.write('Internal server error:\n' + str(e))
                self.finish()

    @tornado.web.asynchronous
    def post(self):
        logger.debug("[!] Post!")
        return self.get()

def run_proxy(host, port, start_ioloop=True):
    """
    Run proxy on the specified port. If start_ioloop is True (default),
    the tornado IOLoop will be started immediately.
    """
    app = tornado.web.Application([
        (r'.*', ProxyHandler),
    ])
    app.listen(port, address=str(host))
    ioloop = tornado.ioloop.IOLoop.instance()
    if start_ioloop:
        ioloop.start()

if __name__ == '__main__':
    if len(sys.argv) == 5:
        lhost = str(sys.argv[1])
        lport = int(sys.argv[2])
        phost = str(sys.argv[3])
        pport = int(sys.argv[4])
        hdl='http://{host}:{port}'.format(host=phost, port=pport)
    else:
        print "HELP: <ip to listen> <port to listen> <ip to send> <port to send>\n"
        print "HELP: Ex. script.py 10.0.0.2 8080 1.2.3.4 80\n" 
        exit('Arguments could not be parsed: %s' % sys.argv)

    print "\nStarting HTTP proxy on %s:%s and proxying to %s:%d" % (lhost, str(lport), phost, pport)
    run_proxy(lhost,lport)
