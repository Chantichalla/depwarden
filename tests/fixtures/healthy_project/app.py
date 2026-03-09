"""A sample app that uses flask and requests."""

from flask import Flask
import requests

app = Flask(__name__)


def fetch_data():
    return requests.get("https://example.com")
