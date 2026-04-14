FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    xrdp \
    xfce4 \
    xfce4-terminal \
    dbus-x11 \
    sudo \
    wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create test user with sudo
RUN useradd -m -s /bin/bash admin && \
    echo "admin:admin" | chpasswd && \
    adduser admin sudo

# Configure XRDP to use XFCE
RUN echo "xfce4-session" > /home/admin/.xsession && \
    chown admin:admin /home/admin/.xsession

# XRDP configuration
RUN sed -i 's/^port=3389/port=3389/' /etc/xrdp/xrdp.ini && \
    sed -i 's/^#xserverbpp=24/xserverbpp=24/' /etc/xrdp/xrdp.ini && \
    adduser xrdp ssl-cert

EXPOSE 3389

COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]
