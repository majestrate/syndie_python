
#
# CAFFINE REMINDER: ---------> DOCUMENT EVERYTHING
#


def to_header_val(val):
    """
    take python object and turn it into
    """
    

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

    logger = logging.getLogger("marshal")


    def __init__(self):
        pass



class SyndieFileHeader:

    def __init__(self):
        self._headers = {}
        self._header_type = None

    def _load_headers(self,f):
        """
        load headers from file
        """
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
            i = line.index('=')
            k,v = line[:i], line[i+1:]
            if k in self._headers:
                continue
            self._headers[k] = v
        
    def has(self,v):
        if v is True:
            v = 'true'
        elif v is False:
            v = 'false'
            

    def _header_type_valid(self):
        return self._header_type is 'Syndie.Message.1.0'
        

    def _dump_headers(self,f):
        """
        dump headers to file
        """


class SyndieFileBody:
    pass
