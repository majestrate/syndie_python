# -*- coding: utf-8 -*-
#
#

__author__ = 'jeff'
__doc__ = """
    common syndie components
"""

import struct
import logging
import itertools
import io
import os
import zipfile

import requests

from Crypto.Cipher import AES
from Crypto.PublicKey import ElGamal

from . import uri

from . import util



class Channel:

    logger = logging.getLogger("Channel")

    def __init__(self,fd=None):
        if fd is None:
            self.hash = None
            self.edition = None
            self.info_encrypted = False
            self.publish_read_key = False
            self.updated = False
            self.update_metadata = False
            self.update_messages = False
        else:
            self._load(fd)

    def _load(self, fd):
        self.hash = fd.read(32)
        self.edition, data = struct.unpack('>QB', fd.read(9))
        self.info_encrypted = util.check_bit(7, data)
        self.publish_read_key = util.check_bit(6, data)
        self.updated = util.check_bit(5, data)
        self.update_metadata = util.check_bit(4, data)
        self.update_messages = util.check_bit(3, data)

    def dump(self,fd):
        # TODO: implement
        pass

    def to_hash(self):
        """
        encode channel hash to string
        """
        return util.b64e(self.hash).decode("utf-8")


class Message:
    pass


class HttpArchive:
    #TODO: put convoluted spec here

    logger = logging.getLogger('SharedIndex')

    default_proxy = "http://127.0.0.1:8118/"

    _rebuild_frequencies = {
        0: 3600,
        1: 21600,
        2: 43200,
        4: 86400
    }

    def __init__(self, url):
        self.url = url
        self.only_recent = False
        self.only_known = False
        self.accept_encrypted = False
        self.accept_privmsg = False
        self.requires_passphrase = False
        self.hashcash = None
        self.rebuild_frequency = None
        self.max_message_size = None
        self.alternative_uri = []
        self.channels = []
        self.messages = []

    def _load_flags(self, fd):
        self.logger.debug("load flags")
        d = fd.read(2)
        self.logger.debug("data %s" % [d])
        data = struct.unpack('>H', d)[0]

        self.only_recent = util.check_bit(15, data)
        self.only_known = util.check_bit(14, data)
        self.accept_encrypted = util.check_bit(13, data)
        self.accept_privmsg = util.check_bit(12, data)
        self.requires_passphrase = util.check_bit(11, data)

        # TODO: how do I parse hash cash?
        self.hashcash = (data & 0x7c0) >> 7
        self.logger.debug("hash cash %s" % [self.hashcash])

        # bit magic hacks :<
        self.rebuild_frequency = ( 2 ** ((data & 0x60) >> 5) ) * 1024
        self.max_message_size = (data & 0x07) * 1024

        self.logger.debug("rebuild freq %s" % self.rebuild_frequency)
        self.logger.debug("max message size %s" % self.max_message_size)

    def _load_uris(self,fd):
        num_uri = struct.unpack('>B', fd.read(1))[0]
        self.logger.debug("%d uri" % num_uri)
        for n in range(num_uri):
            uri = util.read_string(fd)
            self.logger.debug("got uri %s" % uri)
            self.alternative_uri.append(uri)

    def _load_adminchan(self, fd):
        self.logger.debug("read adminchan")
        self._adminchan = fd.read(4)

    def _load_rest(self,fd):
        self.logger.debug("load rest")
        num_chans = struct.unpack('>I', fd.read(4))[0]
        self.logger.debug("%d chans" % num_chans)
        for n in range(num_chans):
            self.channels.append(Channel(fd))

        num_msgs = struct.unpack('>I', fd.read(4))[0]
        self.logger.debug("%d messages" % num_msgs)
        for n in range(num_msgs):
            msg_id = struct.unpack('>Q', fd.read(8))[0]
            scope = struct.unpack('>I', fd.read(4))[0]
            target, msg_flags = struct.unpack('>IB', fd.read(5))
            self.messages.append((msg_id, self.channels[scope], self.channels[target], msg_flags))





    def _load(self,fd):
        """
        load contents from a file descriptor
        """
        self.logger.debug("load from file descriptor")
        self._load_flags(fd)
        self._load_adminchan(fd)
        self._load_uris(fd)
        self._load_rest(fd)

    def get_index(self, proxy):
        """
        obtain index file
        """
        self.alternative_uri = []
        self.channels = []
        self.messages = []
        self.logger.debug("download %s via proxy %s" % (self.url, proxy))
        req = util.url_get(self.url + "/shared-index.dat", proxy)
        if req.status_code is 200:
            self._load(req.raw)
        else:
            self.logger.error("status code %d failed to load" % req.status_code)

    def _download_msg(self, directory, proxy, msg_id, scope, target, flags):
        self.logger.debug("download %s %s"%(msg_id, scope.to_hash()))
        self._download(directory, proxy, "%s.syndie" % msg_id, scope)

    def _download_chan(self,directory, proxy, chan):
        self.logger.debug("download chan %s" % chan.to_hash())
        self._download(directory, proxy, "meta.syndie", chan)

    def _download(self,directory, proxy, fname, chan):

        url = self.url + "/" + chan.to_hash() + "/" + fname
        directory = os.path.join(directory, chan.to_hash())
        util.ensure_dir(directory)
        self.logger.info("download %s" % url)
        req = util.url_get(url, proxy)

        if req.status_code is 200:
            with open(os.path.join(directory, fname), "wb") as fd:
                for chunk in req.iter_content(1024):
                    fd.write(chunk)

    def download(self, directory, proxy):
        """
        return generator with functions with no arguments that download a message
        """
        for chan in self.channels:
            self.logger.debug("gen download channel %s"%chan.to_hash())
            self._download_chan(directory, proxy, chan)
        for msg_id, scope, target, flags in self.messages:
            self.logger.debug("gen download message %s %s" % (msg_id, scope.to_hash() ))
            self._download_msg(directory, proxy, msg_id, scope, target, flags)



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
    elif isinstance(val,bool):
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


class SyndieFile:
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

    required_headers = []


    def __init__(self,fname=None):
        self._headers = {}
        self._header_type = None
        self._body = None
        self._key, self._iv = None, None
        self.pages = []
        self.attachments = []
        self._loaded = False
        if fname is not None:
            self.load(fname)

    def load(self,fname):
        """
        load file contents
        """
        if not self._loaded:
            with open(fname,'rb') as f:
                self._load(f)
            self._unpack()
            self._check_required_headers()
            self._loaded = True

    def _is_message_type(self,type):
        """
        determine if this message is a certain message type
        i.e. meta or post
        """
        header = 'Syndie.MessageType'
        return self.has_header(header) and self.get_header(header).lower() == type.lower()

    def is_meta(self):
        """
        are we a meta message
        """
        return self._is_message_type('meta')

    def is_post(self):
        """
        are we a post message
        """
        return self._is_message_type('post')


    def get_encrypted_body(self):
        """
        obtain the encrypted body of this message
        """
        return self._body

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

        # CAFFINE REMINDER:
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
        #if self.bodysize % 16 != 0 :
        #    raise Exception('Invalid Body size provided: %d bytes'%self.bodysize)


        # obtain information for decryption
        self._get_channel_keys()
        self._get_keys(f)

        # load message body
        self.logger.debug('load message body')
        self._body = f.read(self.bodysize)


    def _get_channel_keys(self):
        """
        get decryption keys for appropriate channels
        """
        pass


    def _unpack(self):
        """
        unpack decrypted body
        """
        self.logger.debug('unpacking')
        # decrypt body
        body = self.decrypt_body()
        if body is None:
            self.logger.warning('could not decrypt body')
            return
        # copy body into buffer
        f = io.BytesIO()
        f.write(body)
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
                        self._load_header(line,internal=True)
                    data.close()
                # load post pages
                for n in itertools.count():
                    fname = 'page%d'%n
                    if fname+'.dat' in files and fname+'.cfg' in files: # load page
                        self.logger.debug('load page number %d'%n)
                        page = {'headers':{}}
                        data = io.BytesIO()
                        data.write(zf.read(fname+'.cfg'))
                        data.seek(0)

                        for line in iter(data.readline, ''):
                            line = line.strip()
                            if len(line) == 0:
                                break
                            k,v = self._get_header(line)
                            if k in page['headers']:
                                continue
                            page['headers'][k] = from_header_val(v)
                        data.close()
                        # load into memory
                        # TODO: is this a bad idea?
                        page['data'] = zf.read(fname+'.dat')
                        self.pages.append(page)

                    else: # done
                        self.logger.debug('at page %d, no more pages'%n)
                        break

                # load attachments
                for n in itertools.count():
                    fname = 'attach%d.dat'%n
                    if fname in files:
                        self.logger.debug('load attachment %d'%n)
                        self.attachments.append(zf.read(fname))
                    else:
                        self.logger.debug('did not find attachment %d, no more attachments'%n)
                        break
                # load references
                if 'references.cfg' in files:
                    fname = 'references.cfg'

                # load everything else
                # TODO: implement

        finally:
            f.close()


    def get_post_uri(self):
        """
        get uri
        """
        header = 'PostURI'
        return self.has_header(header) and uri.SyndieURI(self.get_header(header)) or None

    def _get_keys(self,f):
        """
        get decryption keys from body
        """

        self.logger.debug('get keys')

        if self.has_header('BodyKey'): # we are a public message
            self._iv = f.read(16)
            key = self.get_header('BodyKey')
            self.logger.debug('BodyKey is %s' % key)
            self._key = util.b64d(key)
        else: # we are not a public message
            # implement later
            #raise Exception('can not read non public message')
            #data = f.read(512)
            pass

    def decrypt_body(self):
        """
        get decrypt body
        """
        if self._key and self._iv:
            aes = AES.new(self._key,AES.MODE_CBC, self._iv)
            self.logger.debug('attempting decryption: k=%s iv=%s' % ([self._key], [self._iv]))
            body = aes.decrypt(self._body)
            self.logger.debug('decrypted body with size %d bytes' % (len(body)))
            return body
        else:
            self.logger.warning('could not decrypt, iv or key missing')

    def _verify(self):
        """
        verify cryptographic signatures for body
        """
        # not sure how to do that...
        pass

    def _check_required_headers(self):
        """
        ensure we have the required headers
        otherwise throw exception
        """
        for header in self.required_headers:
            if not self.has_header(header):
                raise Exception('Missing Required Header: %s'%header)
        self.logger.debug('have all headers')


    def _load_header(self,line,internal=False):
        """
        given a line load value and set it
        """
        k, v = self._get_header(line)
        self.logger.debug('header: %s is set to %s' % (k, v))
        self.set_header(k, v, internal=internal)

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

        k = isinstance(k,str) and bytes(k,'ascii') or k
        return k.lower() in self._headers

    def get_header(self,k):
        """
        get header with key
        """
        k = isinstance(k,str) and bytes(k,'ascii') or k
        return self.has_header(k) and self._headers[k.lower()][1] or None

    def get_header_as_str(self,k):
        return self.has_header(k) and self.get_header(k).decode('utf-8') or None

    def set_header(self,k,v,internal):
        """
        set header value given key
        """

        self._headers[k.lower()] = (k, v, internal is True)

    def headers(self):
        """
        get copy of headers
        """
        return dict(self._headers)

    def iter_headers(self):
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

