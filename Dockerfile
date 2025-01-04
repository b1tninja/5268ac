FROM dockcross/linux-mips

ENV DEFAULT_DOCKCROSS_IMAGE=5268ac
ENV FW_VER=11.14.1.533857
ENV PKGSTREAM_URL=http://gateway.c01.sbcglobal.net/firmware/00D09E/${FW_VER}-PROD/att-5268-${FW_VER}_prod_lightspeed-install.pkgstream

# Install binwalk
RUN apt-get install -y bzip2 squashfs-tools cpio python3-binwalk

#WORKDIR /firmware
#VOLUME /firmware

# Download firmware installation pkgstream
ADD ${PKGSTREAM_URL} install.pkgstream

# Extract firmware with binwalk
RUN python3 -m binwalk -eM install.pkgstream --run-as=root
