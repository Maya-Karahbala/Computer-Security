import json
import base64

data = [0, 1, 0, 0, 83, 116, -10]
dataStr = json.dumps(data)

base64EncodedStr = base64.b64encode(dataStr.encode('utf-8'))
print(base64EncodedStr)

print('decoded', base64.b64decode(base64EncodedStr))