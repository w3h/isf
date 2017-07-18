#!/usr/bin/env python
import sys
import requests
import os.path

class Colors:
    WHITE = '\033[97m'
    RED = '\033[0;31m'
    DEFAULT = '\033[0m'
    BLUE = '\033[94m'
    RED = '\033[91m'

try:
    from censys.export import CensysExport
except ImportError:
    print Colors.RED + "[-] Error importing Censys module. Be sure it's installed (pip install censys)" + Colors.DEFAULT
    sys.exit(1)

# Feel free to change the fields gathered (https://censys.io/overview)
modbus_q = 'SELECT [%(x)s.ip] as ip, [%(x)s.location.city] as location.city, [%(x)s.location.country] as location.country, ' \
           '[%(x)s.metadata.product] as metadata.product, [%(x)s.metadata.description] as metadata.description, ' \
           '[%(x)s.metadata.device_type] as metadata.device, [%(x)s.metadata.manufacturer] as metadata.manufacturer, ' \
           '[%(x)s.metadata.revision] as metadata.revision, FROM [%(x)s] WHERE [%(x)s.p502.modbus.device_id.function_code] = 43;'


# Set your ID and Secret API here:
api_id = ""
api_secret = ""


# Returns the response to the Censys API
def api_request_data(api):
    try:
        r = requests.get(api, auth=(api_id, api_secret))
    except requests.exceptions.RequestException as conn:
        print conn
        sys.exit(1)

    return r

# Download a json file (Censys BigQuery)
def file_download(path):
    file = path.rsplit('/', 1)[-1]
    try:
        r = requests.get(path, stream=True)
    except requests.exceptions.RequestException as e:
        print (e)
        sys.exit(1)

    f = open(file, 'wb')

    for chunk in r.iter_content(chunk_size=1024):
        if chunk:
            f.write(chunk)
            f.flush()
    f.close()
    return file


# Download each of the json files
def download_paths(res):
    if "download_paths" not in res:
        print Colors.RED + "[-] There was an error with the query (no \"download_paths\" found) :(" + Colors.DEFAULT
        sys.exit(1)
    else:
        print Colors.WHITE + "[*] Number of files to download: " + Colors.DEFAULT + "%s" % len(res["download_paths"])
        for path in res["download_paths"]:
            file_dwn = file_download(path)
            if os.path.isfile(file_dwn):
                print Colors.WHITE + "[+] File downloaded: " + Colors.DEFAULT + "%s" % file_dwn


# Download manager (CensysExport Class)
def download_modbus(ipv4):
    # fill the modbus query with the last table
    q = modbus_q % {"x": ipv4}

    c = CensysExport(api_id=api_id, api_secret=api_secret)
    job = c.new_job(q)
    if job["status"] not in ("success", "pending"):
        print Colors.RED + "[-] There was an error with the query :(" + Colors.DEFAULT
        sys.exit(1)

    print Colors.WHITE + "[*] Censys status query: " + Colors.DEFAULT + " OK "
    job_id = job["job_id"]
    res = c.check_job_loop(job_id)
    download_paths(res)


def main():
    resource = "/query_definitions/ipv4"
    url_api = "https://www.censys.io/api/v1"

    print Colors.RED + "<< PLC MODBUS DOWNLOAD (@BorjaMerino) >>" + Colors.DEFAULT
    print "Downloading Modbus devices exposed to Internet ...\n"

    if not api_id or not api_secret:
        print Colors.RED + "[-] Please add the Censys API" + Colors.DEFAULT
        sys.exit(1)

    r = api_request_data(url_api + resource)
    tables = r.json()["tables"]
    ipv4 = tables[-1].encode("utf8")

    download_modbus(ipv4)

if __name__ == '__main__':
    main()
