import logging
import os

from flask import Flask
from flask_caching import Cache
from flask_compress import Compress

from app.dalton import dalton_blueprint, ensure_rulesets_exist, setup_dalton_logging
from app.flowsynth import flowsynth_blueprint, setup_flowsynth_logging

__version__ = "3.4.0"


def create_app(test_config=None):
    """Create the flask app."""
    curdir = os.path.dirname(os.path.abspath(__file__))
    static_folder = os.path.join(curdir, "static")
    daltonfs = Flask("app", static_folder=static_folder)
    if test_config:
        # load the test config if passed in
        daltonfs.config.from_mapping(test_config)

    if not daltonfs.testing:
        setup_dalton_logging()
        setup_flowsynth_logging()
        ensure_rulesets_exist()

    # register modules
    #
    # dalton
    daltonfs.register_blueprint(dalton_blueprint)

    # flowsynth
    daltonfs.register_blueprint(flowsynth_blueprint, url_prefix="/flowsynth")

    daltonfs.debug = True

    # Apparently the werkzeug default logger logs every HTTP request
    #  which bubbles up to the root logger and gets output to the
    #  console which ends up in the docker logs.  Since each agent
    #  checks in every second (by default), this can be voluminous
    #  and is superfluous for my current needs.
    try:
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
    except Exception:
        pass

    compress = Compress()
    _ = Cache(daltonfs, config={"CACHE_TYPE": "simple"})
    compress.init_app(daltonfs)
    return daltonfs
