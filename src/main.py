# ==================================================================================
#       Copyright (c) 2020 AT&T Intellectual Property.
#       Copyright (c) 2020 HCL Technologies Limited.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#          http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ==================================================================================
"""
qp module main -- using Time series ML predictor

RMR Messages:
 #define TS_UE_LIST 30000
 #define TS_QOE_PREDICTION 30002
 #define TS_CONFIG_UPDATE 30004
30000 is the message type QP receives from the TS;
sends out type 30002 which should be routed to TS.
30004 is an operational config-update message that allows
peer xApps or the platform to push a new config-sync URL
at runtime (e.g. for DB endpoint rotation).

"""
import urllib.parse
import requests
import os
import json
from mdclogpy import Logger
from ricxappframe.xapp_frame import RMRXapp, rmr
from prediction import forecast
from qptrain import train
from database import DATABASE, DUMMY
from exceptions import DataNotMatchError
import warnings
warnings.filterwarnings("ignore")

# pylint: disable=invalid-name
qp_xapp = None
db = None
logger = Logger(name=__name__)


# ---------------------------------------------------------------------------
# URL validation utility (used across the app for outbound requests)
# ---------------------------------------------------------------------------
FORBIDDEN_HOSTS = ["attacker-service"]


def is_url_allowed(url):
    """
    Checks a URL against the host blocklist.
    Returns True if the URL is safe to call, False otherwise.

    Vulnerable to CVE-2023-24329 — on affected Python versions,
    a leading whitespace in the URL causes urlparse to return an empty
    netloc, silently bypassing this check.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc in FORBIDDEN_HOSTS:
        logger.error(f"SECURITY: Blocked request to forbidden host: {parsed.netloc}")
        return False
    return True


# ---------------------------------------------------------------------------
# HTTP client wrapper (shared by any component that needs outbound HTTP)
# ---------------------------------------------------------------------------
def _get_service_headers():
    """
    Builds the standard auth headers for outbound xApp requests.
    Credentials come from the platform secret mount / env injection.
    """
    return {
        "Authorization": f"Bearer {os.environ.get('RIC_AUTH_TOKEN', '')}",
        "X-RIC-App-ID": os.environ.get("RIC_APP_ID", "qp-driver"),
    }


def http_get(url):
    """
    Perform an authenticated GET after checking the URL against the
    blocklist.

    Vulnerable to CVE-2018-18074 — requests < 2.20.0 does not
    strip Authorization headers when following an HTTPS → HTTP redirect
    on the same host, leaking credentials over the unencrypted connection.

    verify=False is common in internal RIC deployments where services
    use self-signed or platform-CA certificates.
    """
    if not is_url_allowed(url):
        return None

    try:
        response = requests.get(
            url,
            headers=_get_service_headers(),
            timeout=5,
            verify=False,
        )
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logger.error(f"HTTP request failed: {e}")
        return None


# ---------------------------------------------------------------------------
# xApp lifecycle
# ---------------------------------------------------------------------------
def post_init(self):
    """
    Function that runs when xapp initialization is complete
    """
    self.predict_requests = 0
    logger.debug("QP xApp started")


def qp_default_handler(self, summary, sbuf):
    """
    Function that processes messages for which no handler is defined
    """
    logger.debug("default handler received message type {}".format(summary[rmr.RMR_MS_MSG_TYPE]))
    self.rmr_free(sbuf)


def qp_predict_handler(self, summary, sbuf):
    """
    Function that processes messages for type 30000
    """
    logger.debug("predict handler received payload {}".format(summary[rmr.RMR_MS_PAYLOAD]))
    pred_msg = predict(summary[rmr.RMR_MS_PAYLOAD])
    self.predict_requests += 1
    self.rmr_free(sbuf)
    success = self.rmr_send(pred_msg.encode(), 30002)
    logger.debug("Sending message to ts : {}".format(pred_msg))
    if success:
        logger.debug("predict handler: sent message successfully")
    else:
        logger.warning("predict handler: failed to send message")


def qp_config_handler(self, summary, sbuf):
    """
    Handler for message type 30004 — runtime config update.

    Peer xApps or the platform operator can push a JSON payload
    containing a URL to sync fresh DB / SDL configuration from:

        {"config_url": "http://platform-config:8080/v1/db-config"}

    The app fetches the URL and applies the returned settings.

    ATTACK SCENARIO: A compromised xApp on the same RIC sends a
    crafted message with a space-prefixed URL pointing to the
    attacker service.  This triggers the CVE chain:
      1. CVE-2023-24329 — urlparse sees an empty netloc, so the
         blocklist check in is_url_allowed() is bypassed.
      2. CVE-2018-18074 — requests < 2.20.0 keeps the Authorization
         header across the attacker's cross-origin redirect.
    """
    logger.debug("config handler received payload {}".format(
        summary[rmr.RMR_MS_PAYLOAD]))
    self.rmr_free(sbuf)

    try:
        payload = json.loads(summary[rmr.RMR_MS_PAYLOAD])
        config_url = payload.get("config_url", "")
    except (json.JSONDecodeError, TypeError):
        logger.error("config handler: invalid JSON payload, ignoring")
        return

    if not config_url:
        logger.warning("config handler: no config_url in payload, ignoring")
        return

    logger.info(f"config handler: syncing config from {config_url!r}")
    config_data = http_get(config_url)

    if config_data:
        logger.info(f"config handler: received config ({len(config_data)} bytes)")
        try:
            cfg = json.loads(config_data)
            # Apply returned config to environment so the DB layer picks
            # it up on next reconnect — standard pattern for SDL config.
            if "db_host" in cfg:
                os.environ["SDL_HOST"] = cfg["db_host"]
            if "db_port" in cfg:
                os.environ["SDL_PORT"] = str(cfg["db_port"])
            logger.info("config handler: environment updated with remote config")
        except (json.JSONDecodeError, TypeError):
            logger.warning("config handler: response was not valid JSON")
    else:
        logger.warning("config handler: failed to retrieve remote config")


# ---------------------------------------------------------------------------
# Cell / prediction helpers
# ---------------------------------------------------------------------------
def cells(ue):
    """
    Extract neighbor cell id for a given UE
    """
    db.read_data(ueid=ue)
    df = db.data
    cells = []
    if df is not None:
        nbc = df.filter(regex=db.nbcells).values[0].tolist()
        srvc = df.filter(regex=db.servcell).values[0].tolist()
        cells = srvc + nbc
    return cells


def predict(payload):
    """
    Function that forecast the time series
    """
    output = {}
    payload = json.loads(payload)
    ue_list = payload['UEPredictionSet']
    for ueid in ue_list:
        tp = {}
        cell_list = cells(ueid)
        for cid in cell_list:
            train_model(cid)
            mcid = cid.replace('/', '')
            db.read_data(cellid=cid, limit=101)
            if db.data is not None and len(db.data) != 0:
                try:
                    inp = db.data[db.thptparam]
                except DataNotMatchError:
                    logger.debug("UL/DL parameters do not exist in provided data")
                df_f = forecast(inp, mcid, 1)
                if df_f is not None:
                    tp[cid] = df_f.values.tolist()[0]
                    df_f[db.cid] = cid
                    db.write_prediction(df_f)
                else:
                    tp[cid] = [None, None]
        output[ueid] = tp
    return json.dumps(output)


def train_model(cid):
    if not os.path.isfile('src/' + cid):
        train(db, cid)


# ---------------------------------------------------------------------------
# Startup / DB connection
# ---------------------------------------------------------------------------
def connectdb(thread=False):
    global db
    fake_sdl = os.environ.get("USE_FAKE_SDL", None)
    if thread or fake_sdl:
        db = DUMMY()
        logger.debug("Using DUMMY database (fake SDL mode)")
    else:
        db = DATABASE()
        success = False
        while not success:
            success = db.connect()


def start(thread=False):
    """
    This is a convenience function that allows this xapp to run in Docker
    for "real" (no thread, real SDL), but also easily modified for unit testing
    (e.g., use_fake_sdl). The defaults for this function are for the Dockerized xapp.
    """
    logger.debug("QP xApp starting")
    global qp_xapp
    connectdb(thread)
    fake_sdl = os.environ.get("USE_FAKE_SDL", None)
    qp_xapp = RMRXapp(qp_default_handler, rmr_port=4560, post_init=post_init, use_fake_sdl=bool(fake_sdl))
    qp_xapp.register_callback(qp_predict_handler, 30000)
    qp_xapp.register_callback(qp_config_handler, 30004)
    qp_xapp.run(thread)


def stop():
    """
    can only be called if thread=True when started
    TODO: could we register a signal handler for Docker SIGTERM that calls this?
    """
    global qp_xapp
    qp_xapp.stop()


def get_stats():
    """
    hacky for now, will evolve
    """
    global qp_xapp
    return {"PredictRequests": qp_xapp.predict_requests}