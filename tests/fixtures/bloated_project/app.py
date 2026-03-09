"""App that only uses flask — everything else is unused bloat."""

from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "Hello"
