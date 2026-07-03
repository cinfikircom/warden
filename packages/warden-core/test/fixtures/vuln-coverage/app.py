# Kapsam-genişletme fixture'ı (Python) — bilerek açıklı. Üretimde KULLANMA.
import pickle
import requests
from flask import request, render_template_string


def render(name):
    # SSTI
    return render_template_string("<h1>Hello " + name + "</h1>")


def fetch():
    # SSRF
    return requests.get(request.args["url"]).text


def load():
    # Güvensiz deserialization
    return pickle.loads(request.data)


def read():
    # Path traversal
    return open(request.args["file"]).read()
