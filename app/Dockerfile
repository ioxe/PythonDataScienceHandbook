FROM ubuntu:16.04

USER root

RUN apt-get -qq update && \
	apt-get -y dist-upgrade
    
RUN apt-get -y install python3 python3-dev python3-pip pkg-config

RUN pip3 install --upgrade pip

RUN apt-get -y install build-essential curl git libpng-dev libfreetype6-dev libgeos-dev build-essential

WORKDIR /app

COPY ./app/requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

RUN pip install https://github.com/matplotlib/basemap/archive/v1.1.0.tar.gz psutil

COPY ./notebooks notebooks

WORKDIR notebooks

RUN curl https://s3.amazonaws.com/openrecipes/20170107-061401-recipeitems.json.gz > recipeitems-latest.json.gz && gunzip recipeitems-latest.json.gz \
&& curl -o FremontBridge.csv https://data.seattle.gov/api/views/65db-xm6k/rows.csv?accessType=DOWNLOAD \
&& curl -O https://raw.githubusercontent.com/jakevdp/marathon-data/master/marathon-data.csv \
&& curl -O https://data.giss.nasa.gov/pub/gistemp/gistemp250.nc.gz && gunzip gistemp250.nc.gz

EXPOSE 8888

CMD ["jupyter", "notebook", "--ip=0.0.0.0", "--no-browser", "--allow-root", "--port=8888", "--notebook-dir=/app/notebooks", "--NotebookApp.token=''"]
