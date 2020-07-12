import fileinput
import json
import base64

input_json = ""

for line in fileinput.input():
    input_json = input_json + line

secret = json.loads(input_json)

for key in secret["data"]:
    print key
    binary = base64.b64decode(secret["data"][key])
    f = open(key, 'wb')
    f.write(binary)
    f.close()