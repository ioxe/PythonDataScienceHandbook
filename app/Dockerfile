FROM python:3.5.4-jessie

WORKDIR /app

COPY ./app/requirements.txt requirements.txt

RUN apt-get -y update \
&& apt-get -y install python-pip python-dev build-essential git libpng-dev pkg-config libgeos-dev build-essential \
&& pip install -r requirements.txt

WORKDIR ~

COPY ./app/custom.js ~/.jupyter/custom/custom.js

COPY ./notebooks /notebooks

RUN echo jupyter notebook --version

CMD ["jupyter", "notebook", "--ip=0.0.0.0", "--no-browser", "--allow-root", "--port=8888", "--notebook-dir=/notebooks"]
