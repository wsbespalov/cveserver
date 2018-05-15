import urllib.request as req
import zipfile
from io import BytesIO
import gzip
import bz2
import sys
import json
import ast
from datetime import datetime
from dateutil.parser import parse as parse_datetime


def to_string_formatted_cpe(cpe, autofill=False):
    """Convert CPE to formatted string"""
    cpe = cpe.strip()
    if not cpe.startswith('cpe:2.3:'):
        if not cpe.startswith('cpe:/'):
            return False
        cpe = cpe.replace('cpe:/', 'cpe:2.3:')
        cpe = cpe.replace('::', ':-:')
        cpe = cpe.replace('~-', '~')
        cpe = cpe.replace('~', ':-:')
        cpe = cpe.replace('::', ':')
        cpe = cpe.strip(':-')
    if autofill:
        element = cpe.split(':')
        for _ in range(0, 13 - len(element)):
            cpe += ':-'
    return cpe


def convert_list_data_to_json(data):
    if isinstance(data, list):
        serialized = []
        for element in data:
            serialized.append(json.dumps(element))
        return serialized
    else:
        return []


def unify_time(dt):
    if isinstance(dt, str):
        if 'Z' in dt:
            dt = dt.replace('Z', '')
        return parse_datetime(dt)

    if isinstance(dt, datetime):
        return parse_datetime(str(dt))


def print_list(items_to_print):
    for item in items_to_print:
        print("-> {}".format(item))


def print_short(items_to_print):
    for item in items_to_print:
        print("Component: {}, version: {}, CVE: {}, CP: {}, VCONF: {}".format(
            item["component"],
            item["version"],
            item["cve_id"],
            item["cpe"],
            item["vulnerable_configuration"]["data"]))


def serialize_json__for_postgres(source):
    try:
        return json.dumps(ast.literal_eval(source))
    except ValueError:
        return json.dumps(source)


def deserialize_json__for_postgres(source):
    a = ast.literal_eval(source)
    if isinstance(a, dict):
        return a
    return json.loads(a)


def serialize_as_json__for_cache(element):
    def dt_converter(o):
        if isinstance(o, datetime):
            return o.__str__()
    try:
        return json.dumps(element, default=dt_converter)
    except Exception as ex:
        print("{}".format(ex))
        return None


def deserialize_as_json__for_cache(element):
    try:
        return json.loads(element)
    except:
        return None


def progressbar(it, prefix="Processing ", size=50):
    count = len(it)

    def _show(_i):
        if count != 0 and sys.stdout.isatty():
            x = int(size * _i / count)
            sys.stdout.write("%s[%s%s] %i/%i\r" % (prefix, "#" * x, " " * (size - x), _i, count))
            sys.stdout.flush()

    _show(0)
    for i, item in enumerate(it):
        yield item
        _show(i + 1)
    sys.stdout.write("\n")
    sys.stdout.flush()


def get_file(getfile, unpack=True, raw=False, HTTP_PROXY=None):
    try:
        if HTTP_PROXY:
            proxy = req.ProxyHandler({'http': HTTP_PROXY, 'https': HTTP_PROXY})
            auth = req.HTTPBasicAuthHandler()
            opener = req.build_opener(proxy, auth, req.HTTPHandler)
            req.install_opener(opener)

        data = response = req.urlopen(getfile)

        if raw:
            return data

        if unpack:
            if 'gzip' in response.info().get('Content-Type'):
                buf = BytesIO(response.read())
                data = gzip.GzipFile(fileobj=buf)
            elif 'bzip2' in response.info().get('Content-Type'):
                data = BytesIO(bz2.decompress(response.read()))
            elif 'zip' in response.info().get('Content-Type'):
                fzip = zipfile.ZipFile(BytesIO(response.read()), 'r')
                length_of_namelist = len(fzip.namelist())
                if length_of_namelist > 0:
                    data = BytesIO(fzip.read(fzip.namelist()[0]))
        return data, response
    except Exception as ex:
        return None, str(ex)
