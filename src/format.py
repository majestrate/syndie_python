import logging
import io 
import zipfile

from base64 import b64decode
from base64 import b64encode

b64d = lambda x : b64decode(x,b'-~')
b64e = lambda x : b64encode(x,b'-~')

from Crypto.Cipher import AES
from Crypto.PublicKey import ElGamal

from . import bencode

#
# CAFFINE REMINDER: ---------> DOCUMENT EVERYTHING
#
#
# TODO: unit tests must not be left for later
#

def to_header_val(val):
    """
    take python object and turn it into a string that can be written to a header
    """
    if val is None:
        return None
    # why do booleans need to have uppercase first letters :<
    elif instance(val,bool):
        return str(val).lower()
    else:
        return str(val)
    
def from_header_val(val):
    """
    take string from header and convert to python object
    """
    val = val.strip()
    if val == b'true':
        return True
    if val == b'false':
        return False
    if val.isdigit():
        return int(val)
    return val



class SyndueURI:

    logger = logging.getLogger('syndie_uri')

    def __init__(self,raw=None,refType='url',attributes={}):
        """
        construct
        """
        self.raw = str(raw)
        if raw is None:
            self.refType = refType
            self.attributes = attributes
        else:
            val = self.raw
            if val.startswith('urn:syndie:'):
                val = val[11:]
            i = val.index(':')
            self.refType = val[:i]
            attr = bytearray(val[i+1:],'utf-8')
            self.attributes = bencode.decode(attr)
        self.logger.debug('made syndie uri: %s'%self)

    def as_str(self):
        """
        return a string representation of this URI
        """
        try:
            return 'urn:syndie:'+ self.refType+ ':' + bencode.encode(self.attributes).decode('utf-8') 
        except Exception as e: # this is probably a bad idea
            self.logger.error('failed to render URI: %s'%e)
            return None
       

    def __str__(self):
        return self.as_str() or '<Invalid URI: %s>'%self.raw

class Message:
    """
    A .syndie file contains signed and potentially encrypted data for passing
    Syndie channel metadata and posts around. It is made up of two parts- a 
    UTF-8 encoded header and a body. The header begins with a type line, 
    followed by name=value pairs, delimited by the newline character ('\n' or 
    0x0A). After the pairs are complete, a blank newline is included, followed 
    by the line "Size=$numBytes\n", where $numBytes is the size of the body 
    (base10). After that comes that many bytes making up the body of the 
    enclosed message, followed by two newline delimited signature lines - 
    AuthorizationSig=$signature and AuthenticationSig=$signature. There can be 
    any arbitrary amount of data after the signature lines, but it is not 
    currently interpreted.
    """

    logger = logging.getLogger("message")

    required_headers = ['AuthorizationSig',
                        'AuthenticationSig',
                        'Edition','EncryptKey',
                        'Identity','PostURI']


    def __init__(self,fname=None):
        self._headers = {}
        self._header_type = None
        self.body = None
        if fname is not None:
            with open(fname,'rb') as f:
                self._load(f)
                self._decrypt(f)
            self._unpack()

    def is_message_type(self,type):
        header = 'Syndie.MessageType'
        return self.has_header(header) and self.get_header(header).lower() == type.lower()

    def _load(self,f):
        """
        load from file
        """
        self.logger.debug('load from file %s'%f)

        # this should be "Syndie.Message.1.0"
        line = f.readline()
        self._header_type = line
        if self._header_type_valid():
            raise Exception('invalid header type: %s'%self._header_type)
    
        # CAFINE REMINDER: 
        #
        # don't forget to document things
        #  -----------------^
        #
  
        # get headers
        for line in iter(f.readline,''):
            line = line.strip()
            if len(line) == 0:
                break
            self._load_header(line)

        # get size of body
        line = f.readline()
        k,v = self._get_header(line)
        if k != b'Size':
            raise Exception('size header not found, got: %s'%k)
        self.bodysize = int(v)
        if self.bodysize % 16 != 0 :
            raise Exception('Invalid Body size provided: %d bytes'%self.bodysize)



    def _unpack(self):
        """
        unpack decrypted body
        """

        self.logger.debug('unpacking')

        # copy body into buffer
        f = io.BytesIO()
        f.write(self.body)
        f.seek(0)
        # unpack
        try:
            if not zipfile.is_zipfile(f):
                raise Exception('We do not appear to be a syndie file, decryption failed(?)')
            with zipfile.ZipFile(f) as zf:
                self.logger.debug('verify internals')
                # test integrity
                badfile = zf.testzip()
                if badfile:
                    self.logger.error('malfomred part: %s'%badfile)
                    raise Exception('syndie file has broken part called: %s'%badfile)
                self.logger.debug('internals okay')
                files = zf.namelist()
                self.logger.debug('internal parts: %s'%files)

                # get internal headers
                if 'headers.dat' in files:
                    data = io.BytesIO()
                    data.write(zf.read('headers.dat'))
                    data.seek(0)

                    for line in iter(data.readline,''):
                        line = line.strip()
                        if len(line) == 0:
                            break
                        self._load_header(line)
                        
                # load post pages
                
                # load references

                # load everything else
        finally:
            f.close()



    def get_post_uri(self):
        return b

    def _decrypt(self,f):
        """
        decrypt body
        """

        self.logger.debug('decrypt')

        if self.has_header('BodyKey'): # we are a public message
            iv = f.read(16)
            key = self.get_header('BodyKey')
            self.logger.debug('BodyKey is %s'%key)
            key = b64d(key)
        else: # we are not a public message
            data = f.read(512)
            

        aes = AES.new(key,AES.MODE_CBC,iv)
        self.logger.debug('attempting decryption: k=%s iv=%s'%([key],[iv]))
        self.body = aes.decrypt(f.read(self.bodysize))
        self.logger.debug('decrypted body with size %d bytes'%(len(self.body)))

    def _verify(self):
        """
        verify cryptographic signatures for body
        """
        pass

    def _check_required_headers(self):
        """
        ensure we have the required headers
        otherwise throw exception
        """
        for header in SyndieFile.required_headers:
            if not self.has(header):
                raise Exception('Missing Required Header: %s'%header)
        self.logger.debug('have all headers')


    def _load_header(self,line,internal=False):
        """
        given a line load value and set it
        """
        k, v = self._get_header(line)
        self.logger.debug('header: %s is set to %s'%(k,v))
        self.set_header(k,v,internal=internal)

    def _get_header(self,line):
        """
        given line parse into key value pair
        """
        i = line.index(b'=')
        k,v = line[:i], line[i+1:]
        return k,from_header_val(v)
        

    def has_header(self,k):
        """
        do we have a header with key?
        """
        return k in self._headers

    def get_header(self,k):
        """
        get header with key
        """
        k = isinstance(k,str) and bytes(k,'ascii') or k
        return self.has_header(k) and self._headers[k][0] or None

    def set_header(self,k,v,internal):
        """
        set header value given key
        """
        self._headers[k] = ( v , internal is True )

    def __iter__(self):
        """
        iterate over headers
        """
        return iter(self._headers)

    def _header_type_valid(self):
        """
        ensure the header type, the first line in the file is valid
        this means that it is "Syndie.Message.1.0" 
        """
        return self._header_type is 'Syndie.Message.1.0'
        

    def _dump(self,f):
        """
        dump to file
        """
        # TODO: implement
        pass
        
