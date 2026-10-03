from lxml import etree
from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_descriptor():
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    doc = etree.fromstring(request.data, parser)
    return doc.findtext("name") or ""
