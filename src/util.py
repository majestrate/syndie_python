
from base64 import b64decode
from base64 import b64encode

b64d = lambda x : b64decode(x,b'-~')
b64e = lambda x : b64encode(x,b'-~')
