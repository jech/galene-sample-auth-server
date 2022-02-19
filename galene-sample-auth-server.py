#!/usr/bin/python3
"""Sample authorisation server for Galene."""

import logging
import argparse
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import json
import jwt
from aiohttp import web
import aiohttp_cors

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", metavar="PORT", type=int, required=True,
                    help="port to listen on")
parser.add_argument("-k", "--key", metavar="FILE", required=True,
                    help="private key in JWK format")
parser.add_argument("--log", metavar="LEVEL",
                    help="logging level (DEBUG, INFO, WARNING, ERROR)")
args = parser.parse_args()

if args.log != None:
    level = getattr(logging, args.log.upper(), None)
    if not isinstance(level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(level=level)

def read_key(filename):
    with open(filename) as f:
        jwk = f.read()
        alg = json.loads(jwk)["alg"]

    if alg in ["HS256", "HS384", "HS512"]:
        key = jwt.algorithms.HMACAlgorithm.from_jwk(jwk)
    elif alg in ["ES256", "ES384", "ES512"]:
        key = jwt.algorithms.ECAlgorithm.from_jwk(jwk)
    else:
        raise TypeError("Uknown alg " + key_alg)

    return (key, alg)

(key, key_alg) = read_key(args.key)

groups = {
    "auth": {
        "john": "secret",
        "jack": "secret2",
    }
}

# This function should be replaced with one that authentifies users,
# e.g. by checking with an LDAP server.
def user_permissions(location, username, password):
    '''returns a list of permissions if the user is authorised to log into
       the group, None otherwise.  The returned list may contain the strings
       "present", "record" and "op".
    '''

    url = urlparse(location)
    # we should probably check url.scheme and url.netloc at this point

    if not url.path.startswith("/group/"):
        logging.debug("Bad location %s" % url.path)
        return None
    group = url.path.removeprefix('/group/').removesuffix('/')

    try:
        users = groups[group]
    except KeyError:
        logging.debug("Unknown group %s" % group)
        return None

    if not (username in users):
        logging.debug("Unknown user %s in group %s" % (username, group))
        return None

    if password == users[username]:
        logging.debug("User %s in group %s success" % (username, group))
        return ["present"]

    logging.debug("User %s in group %s failure" % (username, group))
    return None

async def handler(request):
    if request.method != "POST":
        logging.debug("Bad method %s" % request.method)
        return web.HTTPMethodNotAllowed(request.method, ["POST"])
    try:
        body = await request.json()
    except json.decoder.JSONDecodeError as err:
        logging.debug("Bad request: %s" % err)
        return web.HTTPBadRequest()

    if not ("username" in body and "location" in body and "password" in body):
        logging.debug("Bad request: missing fields")
        return web.HTTPBadRequest()

    perms = user_permissions(
        body["location"], body["username"], body["password"],
    )
    if perms is None:
        return web.HTTPUnauthorized()

    now = datetime.now(tz=timezone.utc)
    token = {
        "sub": body["username"],
        "aud": body["location"],
        "permissions": perms,
        "iat": now,
        "exp": now + timedelta(seconds=30),
        "iss": str(request.url),
    }

    signed = jwt.encode(token, key, algorithm=key_alg)
    return web.Response(
        headers={"Content-Type": "aplication/jwt"},
        body=signed,
    )

app = web.Application()
route = app.router.add_route("POST", "/", handler)
cors = aiohttp_cors.setup(app, defaults={
    "*": aiohttp_cors.ResourceOptions(
        expose_headers="*",
        allow_headers="*",
    )
})
cors.add(route)
web.run_app(app, port=args.port)
