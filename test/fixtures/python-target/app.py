# Deliberately vulnerable sample code for the vulnicide CLI smoke test. Never deploy.
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)
