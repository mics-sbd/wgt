#
#  WhoGoesThere - web service to interface with Azure credentials store
#
#  Presents a single URL to retrieve the credentials associated with the provided key
#
from azure.keyvault import KeyVaultClient
from azure.common.credentials import ServicePrincipalCredentials
import os
import cherrypy
import jwt

#  Constants
#
ID_WGT_PORT = 27182  #  port is e
ID_WGT_JWT_ENCODE = 'HS256'

#  Environment vars configurable per-deployment; these are set by Terraform per deployment so that
#  code doesn't need to be changed.  Terraform injects these variables into the environment so they can be
#  accessed by the container.  If any of them are missing then this subsystem should fail
#
ID_WGT_ENV_JWT_KEY = 'SBD_JWT_KEY'  #  encryption key for the JWT header
ID_WGT_ENV_JWT_SECRET = 'SBD_JWT_SECRET'  #  agreed shared secret value
ID_WGT_JWT_PAYLOAD_JSON_KEY = 'JWTToken'  #  JSON key name in payload that has the provided shared secret from the caller (must match SBD_JWT_SECRET)
ID_WGT_AZURE_CLIENT_ID = 'TF_VAR_client_id'  #  Azure vault credentials
ID_WGT_AZURE_SECRET    = 'TF_VAR_client_secret'  #  ditto
ID_WGT_AZURE_TENANT    = 'TF_VAR_tenantId'  #  ditto
ID_WGT_AZURE_VAULT_URL = 'SBD_VAULT_URL'  #  Azure vault URL

#  Errors and return values
ID_ERR_MISSING_SID = '__noSecret__'  #  no secret ID was placed on the URL
ID_STATUS_OK = 0
ID_STATUS_MISSING_SECRET = 1000
ID_STATUS_SECRET_NOT_FOUND = 1001


#  Handle the JWT part since it's several steps.  Any failure along the way just raise
#  a 401 response
#
def confirmJWT():
    try:
        auth = cherrypy.request.headers.get('authorization')  #   cherrypy docs say can use headers('authorization') but it fails. . .oi vey*
        bearer = auth.split(' ')
        if( len( bearer ) == 2 ):  #  should be "Bearer JWTToken"; so two parts
            scheme = bearer[ 0 ]  #  should be "Bearer"
            token = bearer[ 1 ]  #  should be the token
            if( scheme == 'Bearer' ):
                jwtPayload = jwt.decode( token, jwtKey, algorithms=[ID_WGT_JWT_ENCODE] )
                wgtTokenVal = jwtPayload[ID_WGT_JWT_PAYLOAD_JSON_KEY]  #  get the value for the key if it's there
                if( jwtSecret != wgtTokenVal ):  #  if the key provided doesn't match what we got from the environment. . .
                    raise cherrypy.HTTPError( "401 Unauthorized" )  #  . . .then fail the request
            else:
                raise cherrypy.HTTPError( "401 Unauthorized" )
        else:
            raise cherrypy.HTTPError( "401 Unauthorized" )
    except:  #  any exception just raise an exception
        raise cherrypy.HTTPError( "401 Unauthorized" )


class SBDSecret( object ):

#  This is dumb but I can't figure out how to handle arguments after the url in the handler;
#  i.e.
#    /secret/mysecret?bad=news
#  WHY!!!!  
#  So, hook the pipeline before the handler and if there are any parameters the length will be >1
#  and just remove them.  Would be nice to force an error since the URL was malformed but this is
#  fine for now.
    @cherrypy.tools.register('before_handler')
    def beforeHandler():
        confirmJWT()
        if( len( cherrypy.request.params ) > 0 ):  #  some arguments on URL so remove them (?, ?=a, etc)
            cherrypy.request.params.clear()  #  empty it out


#  handle the URL without any argument or just /
    @cherrypy.expose
    @cherrypy.tools.beforeHandler()
    @cherrypy.tools.json_out()
    def index( self ):
        return { 'status':ID_STATUS_MISSING_SECRET }


#  handle anything that isn't handled via index() above or has any form that isn't
#  URL/secret/secretID which is captured below.  That means all url paths that are
#  *not* "secret/<something"
    @cherrypy.expose
    @cherrypy.tools.beforeHandler()
    @cherrypy.tools.json_out()
    def default( self, *args ):
        return { 'status':ID_STATUS_MISSING_SECRET }


#  Accept
#    URL:/secret/<secret ID>
#  which is valid and all forms of
#    URL:/secret/<secret ID>/anything else
#  all of which are invalid (so return an error)
    @cherrypy.expose
    @cherrypy.tools.beforeHandler()
    @cherrypy.tools.json_out()
    def secret( self, secretID=ID_ERR_MISSING_SID, *args ):  #  secretID='__noSecret__' to catch if no secretID is provided
        rc = { 'status':ID_STATUS_MISSING_SECRET, 'secretID':secretID }  #  assume an error
        if( len( args ) == 0 and not secretID == ID_ERR_MISSING_SID ):  #  if properly formatted args will be empty and secretID will be something other than ID_SEC_MISSING_SID
            vaultClient = KeyVaultClient( sbdVaultCreds )  #  reauthenticate each time so if anything changed we will fail (is this a good idea?)
            try:
                sBundle = vaultClient.get_secret( sbdVaultURL, secretID, '' )  #  regarding the ''. . .should really use vC.get_secret_versions() but I fiddled with that all day and it seems broken (thanks Zach for the simple workaround!)
                secretVal = sBundle.value
                rc = { 'status':ID_STATUS_OK, 'secretID':secretID, 'secret':secretVal }
            except:  #  any exception just return error
                rc = { 'status':ID_STATUS_SECRET_NOT_FOUND, 'secretID':secretID }

        return rc


if __name__ == '__main__':
#  If any of the steps in __main__ fail then just fail the startup.  This is OK since if this component doesn't start up
#  then something is wrong and we want to fail all requests
#
#  Get the JWT items from the environment
    jwtKey = os.environ[ ID_WGT_ENV_JWT_KEY ]  #  They encryption key used to encrypt the JWT authorization header
    jwtSecret = os.environ[ ID_WGT_ENV_JWT_SECRET ]  #  the secret encoded in the JWT payload; will have been injected by kubernetes

#  get the vault items from the environment
    sbdVaultCreds = ServicePrincipalCredentials(
        client_id = os.environ[ ID_WGT_AZURE_CLIENT_ID ],
        secret =    os.environ[ ID_WGT_AZURE_SECRET ],
        tenant =    os.environ[ ID_WGT_AZURE_TENANT ] )

    sbdVaultURL = os.environ[ ID_WGT_AZURE_VAULT_URL ]

#  Configure cherrypy so it listens properly (0.0.0.0 is in docs somewhere; Daren says it's OK if we configure the firewall correctly)
#  and startup cherrypy
    cherrypy.config.update({'server.socket_host':'0.0.0.0', 'server.socket_port': ID_WGT_PORT})
    cherrypy.quickstart( SBDSecret() )

