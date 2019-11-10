#
#  WhoGoesThere - web service to interface with Azure credentials store
#
#  Presents a single URL to retrieve the credentials associated with the provided key
#
#  SBD_JWT_KEY='abcd'; SBD_JWT_SECRET='123'; export SBD_JWT_KEY; export SBD_JWT_SECRET
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
ID_WGT_ENV_JWT_KEY = 'SBD_JWT_KEY'  #  environment variable with encryption key for the JWT header (from kubernetes)
ID_WGT_ENV_JWT_SECRET = 'SBD_JWT_SECRET'  #  Environment variable with shared secret value (injected by kubernetes)
ID_WGT_JWT_PAYLOAD_JSON_KEY = 'JWTToken'  #  JSON key name in payload that has the provided shared secret (must match SBD_JWT_SECRET)

#  Errors and return values
ID_ERR_MISSING_SID = '__noSecret__'  #  no secret ID was placed on the URL
ID_STATUS_OK = 0
ID_STATUS_MISSING_SECRET = 1000
ID_STATUS_SECRET_NOT_FOUND = 1001


#  hard-code this stuff for now; eventually will pick it up from kubernetes
#
#  REMOVE THESE TWO BEFORE CHECKIN
sbdVaultCreds = ServicePrincipalCredentials(
    client_id = '',
    secret =    '',
    tenant =    '' )

sbdVaultURL = 'https://mics-kv.vault.azure.net/'


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
            vaultClient = KeyVaultClient( sbdVaultCreds )
#            try:
            sBundle = vaultClient.get_secret( sbdVaultURL, secretID, '' )  #  regarding the ''. . .should really use vC.get_secret_versions() but I fiddled with that all day and it seems broken (thanks Zach for the simple workaround!)
            secretVal = sBundle.value
            rc = { 'status':ID_STATUS_OK, 'secretID':secretID, 'secret':secretVal }
#            except:  #  any exception just return error
#                rc = { 'status':ID_STATUS_SECRET_NOT_FOUND, 'secretID':secretID }

        return rc


if __name__ == '__main__':
    jwtKey = os.environ[ ID_WGT_ENV_JWT_KEY ]  #  They encryption key used to encrypt the JWT authorization header
    jwtSecret = os.environ[ ID_WGT_ENV_JWT_SECRET ]  #  the secret encoded in the JWT payload; will have been injected by kubernetes
    cherrypy.config.update({'server.socket_host':'0.0.0.0', 'server.socket_port': ID_WGT_PORT})
    cherrypy.quickstart( SBDSecret() )

