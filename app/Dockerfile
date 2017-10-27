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

ENV NOTEBOOK_DIR '/pv/data/notebooks'

EXPOSE 8888

ENTRYPOINT [ "sh" ]
CMD ["-c", "jupyter notebook --no-browser --allow-root --ip=127.0.0.1 --port=8888 --notebook-dir=${NOTEBOOK_DIR} --NotebookApp.token=''"]
