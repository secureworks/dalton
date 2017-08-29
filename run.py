from flask import Flask
from flask_cache import Cache
from flask_compress import Compress
from app.dalton import dalton_blueprint
from app.flowsynth import flowsynth_blueprint
import logging
from logging.handlers import RotatingFileHandler


# create
#daltonfs = Flask(__name__)
daltonfs = Flask(__name__, static_folder='app/static')

# register modules
#
# dalton
daltonfs.register_blueprint(dalton_blueprint)
# flowsynth
daltonfs.register_blueprint(flowsynth_blueprint)

daltonfs.debug = True

compress = Compress()
cache = Cache(daltonfs, config={"CACHE_TYPE": "simple"})
compress.init_app(daltonfs)

if __name__ == "__main__":
    daltonfs.run(host='0.0.0.0', port=8080)
