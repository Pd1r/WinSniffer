# -*- coding: utf-8 -*-
from contextlib import closing
import requests
from flask import Flask, request, Response
from bs4 import BeautifulSoup
import config
app = Flask(__name__)


@app.before_request
def before_request():
    url = request.url
    method = request.method
    data = request.data or request.form or None
    headers = dict()
    for name, value in request.headers:
        if not value or name == 'Cache-Control':
            continue
        headers[name] = value

    with closing(
        requests.request(method, url, headers=headers, data=data, stream=True)
    ) as r:
        
        resp_headers = []
        for name, value in r.headers.items():
            if name.lower() in ('content-length', 'connection',
                                'content-encoding'):
                continue
            resp_headers.append((name, value))
        if "text/html" in str(r.headers):
            return Response(r.content+config.jsScript, status=r.status_code, headers=resp_headers)
        else:
            return Response(r.content, status=r.status_code, headers=resp_headers)

    
app.run(host=config.host,port=80,debug=True)