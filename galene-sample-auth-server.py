#!/usr/bin/python3
"""Sample authorisation server for Galene."""

import logging
import argparse
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urljoin
import json
import jwt
from aiohttp import web
import aiohttp_cors

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", metavar="PORT", type=int, required=True,
                    help="port to listen on")
parser.add_argument("-k", "--key", metavar="FILE", required=True,
                    help="private key in JWK format")
parser.add_argument("-r", "--redirect", metavar="URL",
                    help="behave as an authorisation portal")
parser.add_argument("--log", metavar="LEVEL",
                    help="logging level (DEBUG, INFO, WARNING, ERROR)")
args = parser.parse_args()

if args.log != None:
    level = getattr(logging, args.log.upper(), None)
    if not isinstance(level, int):
        raise ValueError('Invalid log level: %s' % level)
    logging.basicConfig(level=level)

redirect = None
if args.redirect != None:
    redirect = urlparse(args.redirect)

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

# user_permissions should be replaced with one that authentifies users,
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

# makeToken generates a signed token carrying the given data
def makeToken(issuer, location, username, password):
    perms = user_permissions(location, username, password)
    if perms is None:
        return None

    now = datetime.now(tz=timezone.utc)
    token = {
        "sub": username,
        "aud": location,
        "permissions": perms,
        "iat": now,
        "exp": now + timedelta(seconds=30),
        "iss": issuer,
    }

    return jwt.encode(token, key, algorithm=key_alg)

# serverHandler implements the authorisation server
async def serverHandler(request):
    try:
        data = await request.json()
    except json.decoder.JSONDecodeError as err:
        logging.debug("Bad request: %s" % err)
        return web.HTTPBadRequest()

    if not ("username" in data and "location" in data and "password" in data):
        logging.debug("Bad request: missing fields")
        return web.HTTPBadRequest()

    token = makeToken(
        str(request.url), data["location"], data["username"], data["password"],
    )
    if token is None:
        return web.HTTPUnauthorized()

    return web.Response(
        headers = {"Content-Type": "application/jwt"},
        body = token,
    )

# portalHandler implements the landing page of the portal.
async def portalHandler(request):
    return web.Response(
        headers = {"Content-Type": "text/html; charset=utf-8"},
        body = (
            '<!DOCTYPE html>'
            '<html lang="en">'
            '<head>'
            '<title>Galene login page</title>'
            '</head>'
            '<body>'
            '<form action="/redirect" method="post">'
            '<label for="group">Group:</label>'
            '<input id="group" type="text" name="group"/>'
            '<label for="username">Username:</label>'
            '<input id="username" type="text" name="username"/>'
            '<label for="password">Password:</label>'
            '<input id="password" type="password" name="password"/>'
            '<input type="submit" value="Join"/>'
            '</form>'
            '</body>'
            '</html>'
        )
    )

# redirectHandler parses the form from the landing page
async def redirectHandler(request):
    data = await request.post()
    if not ("username" in data and "group" in data and "password" in data):
        logging.debug("Bad request: missing fields")
        return web.HTTPBadRequest()

    location = urljoin(urljoin(args.redirect, "group/"), data["group"] + "/")
    token = makeToken(
        str(request.url), location, data["username"], data["password"],
    )
    if token is None:
        return web.HTTPUnauthorized()
    return web.HTTPFound(urljoin(location, "?token=" + token))

app = web.Application()
route = app.router.add_route("POST", "/", serverHandler)
if not (redirect is None):
    app.router.add_route("GET", "/", portalHandler)
    app.router.add_route("POST", "/redirect", redirectHandler)

cors = aiohttp_cors.setup(app, defaults={
    "*": aiohttp_cors.ResourceOptions(
        expose_headers="*",
        allow_headers="*",
    )
})
cors.add(route)

web.run_app(app, port=args.port)
