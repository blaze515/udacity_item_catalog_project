#!/usr/bin/python
import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, "/var/www/catalog/")
from project import app as application
application.secret_key = '7y3s4iPOub3F7GN9tyEodJzt'
