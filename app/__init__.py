import logging
import os

from flask import Flask

from app.dalton import dalton_blueprint, ensure_rulesets_exist
from app.flowsynth import flowsynth_blueprint

__version__ = "3.4.1"


def create_app(test_config=None):
    """Create the flask app."""
    curdir = os.path.dirname(os.path.abspath(__file__))
    static_folder = os.path.join(curdir, "static")
    daltonfs = Flask("app", static_folder=static_folder)
    if test_config:
        # load the test config if passed in
        daltonfs.config.from_mapping(test_config)

    if not daltonfs.testing:
        ensure_rulesets_exist()

    # register modules
    #
    # dalton
    daltonfs.register_blueprint(dalton_blueprint)

    # flowsynth
    daltonfs.register_blueprint(flowsynth_blueprint, url_prefix="/flowsynth")

    class NoRequestJobFilter(logging.Filter):
        def filter(self, record):
            do_not_want = (
                "GET /dalton/sensor_api/request_job",
                "GET /static/",
                "GET /dalton/controller_api/job_status",
                "GET /dalton/job/",
            )
            msg = record.getMessage()
            if any(item in msg for item in do_not_want):
                return False
            return True

    logging.getLogger("werkzeug").addFilter(NoRequestJobFilter())
    logging.getLogger("dalton").setLevel(logging.DEBUG)
    logging.getLogger("flowsynth").setLevel(logging.DEBUG)

    return daltonfs
