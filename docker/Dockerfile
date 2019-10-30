#  Dockerfile for whogoesthere secrets interface
#  to Azure secrets
#
#  Use the official alpine + python image as the base
#
FROM python:3.8.0-alpine

WORKDIR /usr/local/py

#  This Alpine is missing a bunch of stuff so add it
#  need gcc (from build-base) and crypto support for azure-keyvault (from libressl-dev, musl-dev, libffi-dev)
RUN apk add --no-cache build-base libressl-dev musl-dev libffi-dev
RUN pip install cherrypy azure-keyvault

COPY app/wgt.py /usr/local/py


#  Expose the service
EXPOSE 27182

#  Start the wgt service
#
CMD ["python", "wgt.py"]
