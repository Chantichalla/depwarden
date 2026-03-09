"""App for vulnerable project fixture."""
import requests

def call_api():
    return requests.get("https://api.example.com")
