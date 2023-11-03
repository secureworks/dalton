from flask import Flask
from flask_caching import Cache
from flask_compress import Compress
from app.dalton import dalton_blueprint
from app.flowsynth import flowsynth_blueprint
import logging

# create
daltonfs = Flask(__name__, static_folder='app/static')

# register modules
#
# dalton
daltonfs.register_blueprint(dalton_blueprint)

# flowsynth
daltonfs.register_blueprint(flowsynth_blueprint, url_prefix='/flowsynth')

daltonfs.debug = True

# Apparently the werkzeug default logger logs every HTTP request
#  which bubbles up to the root logger and gets output to the
#  console which ends up in the docker logs.  Since each agent
#  checks in every second (by default), this can be voluminous
#  and is superfluous for my current needs.
try:
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
except Exception as e:
    pass

compress = Compress()
cache = Cache(daltonfs, config={"CACHE_TYPE": "simple"})
compress.init_app(daltonfs)

if __name__ == "__main__":
    daltonfs.run(host='0.0.0.0', port=8080)
