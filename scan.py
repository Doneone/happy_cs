import argparse
import requests
import urllib3
from urllib.parse import urljoin
from lib import decrypt_beacon, decode_config, JsonEncoder


def scan_beacon(HOST):
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print("Checking {}".format(HOST))
    try:
        r = requests.get(urljoin("http://"+HOST, "/aaa9"), headers={'user-agent': ua}, verify=False, timeout=5)
        if r.status_code == 200:
            data = r.content
            if data.startswith(b"\xfc\xe8"):
                beacon = decrypt_beacon(data)
                if beacon:
                    config = decode_config(beacon)
                    if config:
                        print("Configuration of the x86 payload:")
                        for d in config:
                            if isinstance(config[d], bytearray):
                                pass
                                #print("{:30} {}".format(d, config[d].hex()))
                            else:
                                pass
                                #print("{:30} {}".format(d, config[d]))
                        print("")
                        return(config["publickey"].strip(b'\x00'))
                    else:
                        print("x86: Impossible to extract the configuration")
                else:
                    print("x86: Impossible to extract beacon")
            elif data.startswith(b"MZ"):
                # Sometimes it returns a PE directly
                config = decode_config(data)
                if config:
                    print("Configuration of the x86 payload")
                    for d in config:
                        if "publickey" in d:
                            pass
                            #print(config[d])
                        if isinstance(config[d], bytearray):
                            pass
                            #print(d)
                            #print("{:30} {}".format(d, config[d].hex()))
                        else:
                            pass
                            #print("{:30} {}".format(d, config[d]))
                    print("")
                    return(config["publickey"].strip(b'\x00'))
                else:
                    print("x86: Impossible to extract the configuration")
            else:
                print("x86: Payload not found")
        else:
            print("x86: HTTP Status code {}".format(r.status_code))

        r = requests.get(urljoin("http://"+HOST, "aab9"), headers={'user-agent': ua}, verify=False, timeout=5)
        if r.status_code == 200:
            data = r.content
            if data.startswith(b"\xfc\xe8"):
                beacon = decrypt_beacon(data)
                if beacon:
                    config = decode_config(beacon)
                    if config:
                        for d in config:
                            print("Configuration of the x86_64 payload")
                            if isinstance(config[d], bytearray):
                                print("{:30} {}".format(d, config[d].hex()))
                            else:
                                print("{:30} {}".format(d, config[d]))
                        print("")
                        return(config["publickey"].strip(b'\x00'))
                    else:
                        print("x86_64: Impossible to extract the configuration")
                else:
                    print("x86_64: Impossible to extract beacon")
            elif data.startswith(b"MZ"):
                # Sometimes it returns a PE directly
                config = decode_config(data)
                if config:
                    print("Configuration of the x86_64 payload:")
                    for d in config:
                        if isinstance(config[d], bytearray):
                            print("{:30} {}".format(d, config[d].hex()))
                        else:
                            print("{:30} {}".format(d, config[d]))
                    print("")
                    return(config["publickey"].strip(b'\x00'))
                else:
                    print("x86_64: Impossible to extract the configuration")
            else:
                print("x86_64: Payload not found")
        else:
            print("x86_64: HTTP Status code {}".format(r.status_code))
    except (requests.exceptions.ChunkedEncodingError, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ContentDecodingError):
        #print("Request failed")
        pass


if __name__ == "__main__":
        # parser = argparse.ArgumentParser(description='Extract Cobalt Strike beacon and configuration from a server')
        # parser.add_argument('HOST', help='Domain or IP address of the Cobalt Strike server')
        # parser.add_argument('--dump', '-D', help='Extract the beacon (only if the beacon is encrypted)')
        # args = parser.parse_args()
    pass

