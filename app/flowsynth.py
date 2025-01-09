import hashlib
import json
import logging
import os
import random
import re
import shlex
import subprocess
import tempfile
from logging.handlers import RotatingFileHandler

from flask import Blueprint, Response, redirect, render_template, request

from . import certsynth
from .dalton import FS_BIN_PATH as BIN_PATH
from .dalton import FS_PCAP_PATH as PCAP_PATH

# setup the flowsynth blueprint
flowsynth_blueprint = Blueprint(
    "flowsynth_blueprint", __name__, template_folder="templates/"
)

logger = logging.getLogger("flowsynth")


def setup_flowsynth_logging():
    """Set up logging."""
    file_handler = RotatingFileHandler(
        "/var/log/flowsynth.log", "a", 1 * 1024 * 1024, 10
    )
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
    )
    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)

    logger.info("Logging started")


def get_pcap_path():
    """Return the configured path for storing pcaps."""
    return PCAP_PATH


def check_pcap_path(path=None):
    """Ensure the pcap path exists."""
    path = path or get_pcap_path()
    if not os.path.isdir(path):
        os.mkdir(path)
        os.chmod(path, 0o755)


def get_pcap_file_path(basename, path=None):
    """Return a full path to a PCAP file based on basename."""
    path = path or get_pcap_path()
    return os.path.join(path, f"{basename}.pcap")


def payload_raw(formobj):
    """parse and format a raw payload"""

    synth = ""

    if (str(formobj["payload_ts"])) != "":
        synth = 'default > (content:"%s";);' % fs_replace_badchars(
            str(formobj.get("payload_ts"))
        )

    if (str(formobj.get("payload_tc"))) != "":
        if synth != "":
            synth = "%s\n" % synth
        tcpayload = 'default < (content:"%s";);' % fs_replace_badchars(
            str(formobj.get("payload_tc"))
        )
        synth = "%s%s" % (synth, tcpayload)

    return synth


def payload_http(formobj):
    """Parse and generate an http payload."""

    # the raw flowsynth we'll return
    synth = ""

    # we must have a request header.
    try:
        request_header = (
            fs_replace_badchars(
                unicode_safe(formobj.get("request_header")).strip("\r\n")
            )
            .replace("\r", "\\x0d\\x0a")
            .replace("\n", "\\x0d\\x0a")
        )
        request_body = (
            fs_replace_badchars(unicode_safe(formobj.get("request_body")).strip("\r\n"))
            .replace("\r", "\\x0d\\x0a")
            .replace("\n", "\\x0d\\x0a")
        )
        request_body_len = len(request_body) - (request_body.count("\\x") * 3)
    except Exception as e:
        logger.error("Problem parsing HTTP Wizard payload request content: %s" % e)
        return None

    # the start of the flowsynth
    synth = 'default > (content:"%s";' % request_header

    if "payload_http_request_contentlength" in formobj:
        # add or update request content length
        # doesn't add 'Content-Length: 0' if empty request body unless POST
        # will do inline update of Content-Length value if exists in submitted data
        if re.search(
            r'\\x0d\\x0acontent-length\\x3a(\\x20)*\d+("|\\x0d\\x0a)', synth.lower()
        ):
            synth = re.sub(
                r'(\\x0d\\x0acontent-length\\x3a(?:\\x20)*)\d+("|\\x0d\\x0a)',
                "\g<1>%d\g<2>" % request_body_len,
                synth,
                flags=re.I,
            )
        elif request_body != "" or request_header.lower().startswith("post\\x20"):
            synth = '%s content:"\\x0d\\x0aContent-Length\x3a\x20%s";' % (
                synth,
                request_body_len,
            )

    # add an 0d0a0d0a
    synth = '%s content:"\\x0d\\x0a\\x0d\\x0a";' % synth
    if request_body != "":
        # add http_client_body
        synth = '%s content:"%s"; );\n' % (synth, request_body)
    else:
        synth = "%s );\n" % synth

    if "payload_http_response" in formobj:
        # include http response
        try:
            response_header = (
                fs_replace_badchars(
                    unicode_safe(formobj.get("response_header")).strip("\r\n")
                )
                .replace("\r", "\\x0d\\x0a")
                .replace("\n", "\\x0d\\x0a")
            )
            response_body = (
                fs_replace_badchars(
                    unicode_safe(formobj.get("response_body")).strip("\r\n")
                )
                .replace("\r", "\\x0d\\x0a")
                .replace("\n", "\\x0d\\x0a")
            )
            response_body_len = len(response_body) - (response_body.count("\\x") * 3)
        except Exception as e:
            logger.error("Problem parsing HTTP Wizard payload response content: %s" % e)
            return None

        if "payload_http_response_contentlength" in formobj:
            # add or update response content length; include "Content-Length: 0" if body empty
            # will do inline update of Content-Length value if exists in submitted data
            if re.search(
                r"\\x0d\\x0acontent-length\\x3a(\\x20)*\d+($|\\x0d\\x0a)",
                response_header.lower(),
            ):
                response_header = re.sub(
                    r"(\\x0d\\x0acontent-length\\x3a(?:\\x20)*)\d+($|\\x0d\\x0a)",
                    "\g<1>%d\g<2>" % response_body_len,
                    response_header,
                    flags=re.I,
                )
                synth = '%sdefault < (content:"%s";' % (synth, response_header)
            else:
                synth = '%sdefault < (content:"%s";' % (synth, response_header)
                synth = '%s content:"\\x0d\\x0aContent-Length\x3a\x20%s";' % (
                    synth,
                    response_body_len,
                )
        else:
            synth = '%sdefault < (content:"%s";' % (synth, response_header)

        # add an 0d0a0d0a
        synth = '%s content:"\\x0d\\x0a\\x0d\\x0a";' % synth
        if response_body != "":
            synth = '%s content:"%s"; );\n' % (synth, response_body)
        else:
            synth = "%s );\n" % synth

    return synth


def payload_cert(formobj):
    # Make sure we have stuff we need
    if not ("cert_file_type" in formobj and "cert_file" in request.files):
        logger.error("No cert submitted")
        return None

    try:
        file_content = request.files["cert_file"].read()
        cert_file_type = formobj.get("cert_file_type")
        if cert_file_type == "pem":
            file_content = file_content.decode("utf-8")
            if certsynth.pem_cert_validate(file_content.strip()):
                return certsynth.cert_to_synth(file_content.strip(), "PEM")
            else:
                logger.error("Unable to validate submitted pem file.")
                return None
        elif cert_file_type == "der":
            return certsynth.cert_to_synth(file_content, "DER")
        else:
            # this shouldn't happen if people are behaving
            logger.error(f"Invalid certificate format given: '{cert_file_type}'")
            return None
    except Exception as e:
        logger.error(f"Error processing submitted certificate file: {e}")
        return None


def fs_replace_badchars(payload):
    """Replace characters that conflict with the flowsynth syntax."""
    badchars = ['"', "'", ";", ":", " "]
    for char in badchars:
        payload = payload.replace(char, "\\x%s" % str(hex(ord(char)))[2:])
    payload = payload.replace("\r\n", "\\x0d\\x0a")
    return payload


def unicode_safe(string):
    """return an ascii repr of the string"""
    # Jun 21, 2019 - DRW - I'm not sure the reason for this
    # or if it is still necessary in Python3....
    return string.encode("ascii", "ignore").decode("ascii")


@flowsynth_blueprint.route("/index.html", methods=["GET", "POST"])
def index_redirect():
    return redirect("/")


@flowsynth_blueprint.route("/")
def page_index():
    """return the packet generator template"""
    return render_template("pcapwg/packet_gen.html", page="")


@flowsynth_blueprint.route("/generate", methods=["POST", "GET"])
def generate_fs():
    """Receive and handle a request to generate a PCAP."""

    formobj = request.form

    # Generate flowsynth file
    flow_init_opts = ""

    # build src ip statement
    src_ip = str(formobj.get("l3_src_ip"))
    if src_ip == "$HOME_NET":
        src_ip = "192.168.%s.%s" % (random.randint(1, 254), random.randint(1, 254))
    else:
        src_ip = "172.16.%s.%s" % (random.randint(1, 254), random.randint(1, 254))

    # build dst ip statement
    dst_ip = str(formobj.get("l3_dst_ip"))
    if dst_ip == "$HOME_NET":
        dst_ip = "192.168.%s.%s" % (random.randint(1, 254), random.randint(1, 254))
    else:
        dst_ip = "172.16.%s.%s" % (random.randint(1, 254), random.randint(1, 254))

    # build src port statement
    src_port = str(formobj.get("l4_src_port"))
    if src_port.lower() == "any":
        src_port = random.randint(10000, 65000)

    # build dst port statement
    dst_port = str(formobj.get("l4_dst_port"))
    if dst_port.lower() == "any":
        dst_port = random.randint(10000, 65000)

    # initialize the tcp connection automatically, if requested.
    if "l3_flow_established" in formobj:
        flow_init_opts = " (tcp.initialize;)"

    # define the actual flow in the fs syntax
    synth = "flow default %s %s:%s > %s:%s%s;" % (
        str(formobj.get("l3_protocol")).lower(),
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        flow_init_opts,
    )

    payload_fmt = str(formobj.get("payload_format"))
    payload_cmds = ""
    if payload_fmt == "raw":
        payload_cmds = payload_raw(formobj)
    elif payload_fmt == "http":
        payload_cmds = payload_http(formobj)
        if payload_cmds is None:
            return render_template(
                "pcapwg/error.html",
                error_text="Unable to process submitted HTTP Wizard content. See log for more details.",
            )
    elif payload_fmt == "cert":
        payload_cmds = payload_cert(formobj)
        if payload_cmds is None:
            return render_template(
                "pcapwg/error.html",
                error_text="Unable to process submitted certificate. See log for more details.",
            )

    synth = "%s\n%s" % (synth, payload_cmds)
    return render_template("pcapwg/compile.html", page="compile", flowsynth_code=synth)


@flowsynth_blueprint.route("/pcap/compile_fs", methods=["POST"])
def compile_fs():
    """Compile a flowsynth file into a downloadable PCAP."""

    check_pcap_path()

    # write flowsynth data to file
    fs_code = str(request.form.get("code"))
    hashobj = hashlib.md5()
    hashobj.update(f"{fs_code}{random.randint(1, 10000)}".encode("utf-8"))
    fname = hashobj.hexdigest()[0:15]

    inpath = tempfile.mkstemp()[1]
    outpath = get_pcap_file_path(fname)

    # write to temp input file
    with open(inpath, "w") as fptr:
        fptr.write(fs_code)

    # run the flowsynth command
    command = "%s %s -f pcap -w %s --display json --no-filecontent" % (
        BIN_PATH,
        inpath,
        outpath,
    )
    logger.debug(command)
    proc = subprocess.Popen(
        shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    output, errors = proc.communicate()

    # parse flowsynth json
    try:
        synthstatus = json.loads(output)
    except ValueError:
        # there was a problem producing output.
        logger.error("Problem processing Flowsynth output: %s" % output)
        return render_template(
            "pcapwg/error.html", error_text=output + b"\n\n" + errors
        )

    # delete the tempfile
    os.unlink(inpath)

    # render the results page
    return render_template(
        "pcapwg/packet.html", buildstatus=synthstatus, filename=fname
    )


@flowsynth_blueprint.route("/compile", methods=["GET", "POST"])
def compile_page():
    flowsynth = request.values.get("flowsynth", "")
    return render_template(
        "pcapwg/compile.html", page="compile", flowsynth_code=flowsynth
    )


@flowsynth_blueprint.route("/about")
def about_page():
    return render_template("pcapwg/about.html", page="about")


@flowsynth_blueprint.route("/pcap/get_pcap/<pcapid>")
def retrieve_pcap(pcapid):
    """Returns a PCAP to the user."""
    if not re.match(r"^[A-Za-z0-9\x5F\x2D\x2E]+$", pcapid):
        logger.error("Bad pcapid in get_pcap request: '%s'" % pcapid)
        return render_template(
            "pcapwg/error.html", error_text="Bad pcapid: '%s'" % pcapid
        )
    path = get_pcap_file_path(os.path.basename(pcapid))
    if not os.path.isfile(path):
        logger.error(
            "In get_pcap request: file not found: '%s'" % os.path.basename(path)
        )
        return render_template(
            "pcapwg/error.html",
            error_text="File not found: '%s'" % os.path.basename(path),
        )
    filedata = open(path, "rb").read()
    return Response(
        filedata,
        mimetype="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": "attachment;filename=%s.pcap" % pcapid},
    )
