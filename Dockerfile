FROM python:3.8-slim-buster

LABEL version="1.4.1"

# copy DeTT&CT and install the requirements
COPY . /opt/DeTTECT
WORKDIR /opt/DeTTECT
RUN pip install --no-cache-dir -r requirements.txt

# create an input and output directory
# within this directory, you can put your data source, technique and group YAML administration files.
RUN mkdir -p input
# within this directory, the output files from DeTT&CT are written. Such as ATT&CK Navigator layer files.
RUN mkdir -p output

# set an environment variable for the DeTT&CT Editor and expose port 8080
ENV DeTTECT_DOCKER_CONTAINER 1
EXPOSE 8080/tcp
