# ==================================================================================
#   Copyright (c) 2020 HCL Technologies Limited.    
#   Copyright (c) 2020 AT&T Intellectual Property.
# ==================================================================================

# Vulnerable to CVE-2023-24329
FROM python:3.11.3-slim

# RMR setup
RUN mkdir -p /opt/route/

# Install system dependencies
# Added wget for RMR and libc6 to ensure binary compatibility
RUN apt update && apt install -y gcc musl-dev wget libc6

# RMR Libraries
ARG RMRVERSION=4.9.0
RUN wget --content-disposition https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/rmr_${RMRVERSION}_amd64.deb/download.deb && dpkg -i rmr_${RMRVERSION}_amd64.deb
RUN wget --content-disposition https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/rmr-dev_${RMRVERSION}_amd64.deb/download.deb && dpkg -i rmr-dev_${RMRVERSION}_amd64.deb
RUN rm -f rmr_${RMRVERSION}_amd64.deb rmr-dev_${RMRVERSION}_amd64.deb

ENV LD_LIBRARY_PATH /usr/local/lib/:/usr/local/lib64
COPY tests/fixtures/local.rt /opt/route/local.rt
ENV RMR_SEED_RT /opt/route/local.rt

# --- POLLUTION & COMPATIBILITY FIX ---
# We force numpy < 2 to fix the 'Value Error' and install 'requests' for the exploit
RUN pip install --upgrade pip && \
    pip install "numpy<2" "pandas<2" requests==2.19.1 flask
# -------------------------------------

# Install xApp
COPY setup.py /tmp
COPY LICENSE.txt /tmp/
RUN pip install /tmp

COPY src/ /src

# Run
ENV PYTHONUNBUFFERED 1
# Ensure we point to the correct python site-packages for 3.11
CMD PYTHONPATH=/src:/usr/local/lib/python3.11/site-packages/:$PYTHONPATH run-qp.py