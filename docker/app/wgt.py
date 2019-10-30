#
#  WhoGoesThere - web service to interface with Azure credentials store
#
#  Presents a single URL to retrieve the credentials associated with the provided key
#
from azure.keyvault import KeyVaultClient
from azure.common.credentials import ServicePrincipalCredentials
import cherrypy


#  Constants
#
ID_WGT_PORT = 27182  #  port is e

#  Errors and return values
ID_ERR_MISSING_SID = '__noSecret__'  #  no secret ID was placed on the URL
ID_STATUS_OK = 0
ID_STATUS_MISSING_SECRET = 1000
ID_STATUS_SECRET_NOT_FOUND = 1001


#  hard-code this stuff for now; eventually will pick it up from kubernetes
sbdVaultCreds = ServicePrincipalCredentials(
    client_id = '46ee1ba2-dec2-493b-b2c4-4a81ffcd37dc',
    secret = 'xgo?iK.t19-6dGw:0fwbXLhbDP0W_6FL',
    tenant = 'e86183dc-d7cc-4132-8b39-a8de37272433' )

sbdVaultURL = 'https://mics-kv.vault.azure.net/'


class SBDSecret( object ):

#  This is dumb but I can't figure out how to handle arguments after the url in the handler;
#  i.e.
#    /secret/mysecret?bad=news
#  WHY!!!!  
#  So, hook the pipeline before the handler and if there are any parameters the length will be >1
#  and just remove them.  Would be nice to force an error since the URL was malformed but this is
#  fine for now.
    @cherrypy.tools.register('before_handler')
    def handleArgs():
        if( len( cherrypy.request.params ) > 0 ):  #  some arguments on URL so remove them (?, ?=a, etc)
            cherrypy.request.params.clear()  #  empty it out


#  handle the URL without any argument or just /
    @cherrypy.expose
    @cherrypy.tools.handleArgs()
    @cherrypy.tools.json_out()
    def index( self ):
        return { 'status':ID_STATUS_MISSING_SECRET }


#  handle anything that isn't handled via index() above or has any form that isn't
#  URL/secret/secretID which is captured below.  That means all url paths that are
#  *not* "secret/<something"
    @cherrypy.expose
    @cherrypy.tools.handleArgs()
    @cherrypy.tools.json_out()
    def default( self, *args ):
        return { 'status':ID_STATUS_MISSING_SECRET }


#  Accept
#    URL:/secret/<secret ID>
#  which is valid and all forms of
#    URL:/secret/<secret ID>/anything else
#  all of which are invalid (so return an error)
    @cherrypy.expose
    @cherrypy.tools.handleArgs()
    @cherrypy.tools.json_out()
    def secret( self, secretID=ID_ERR_MISSING_SID, *args ):  #  secretID='__noSecret__' to catch if no secretID is provided
        rc = { 'status':ID_STATUS_MISSING_SECRET, 'secretID':secretID }  #  assume an error
        if( len( args ) == 0 and not secretID == ID_ERR_MISSING_SID ):  #  if properly formatted args will be empty and secretID will be something other than ID_SEC_MISSING_SID
            vaultClient = KeyVaultClient( sbdVaultCreds )
            try:
                sBundle = vaultClient.get_secret( sbdVaultURL, secretID, '' )  #  regarding the ''. . .should really use vC.get_secret_versions() but I fiddled with that all day and it seems broken (thanks Zach for the simple workaround!)
                secretVal = sBundle.value
                rc = { 'status':ID_STATUS_OK, 'secretID':secretID, 'secret':secretVal }
            except:  #  any exception just return error
                rc = { 'status':ID_STATUS_SECRET_NOT_FOUND, 'secretID':secretID }

        return rc


if __name__ == '__main__':
    cherrypy.config.update({'server.socket_host':'0.0.0.0', 'server.socket_port': ID_WGT_PORT})
    cherrypy.quickstart( SBDSecret() )

