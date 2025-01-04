FROM dockcross/linux-mips

#ENV DEFAULT_DOCKCROSS_IMAGE=5268ac

# Install binwalk
RUN apt-get install -y bzip2 squashfs-tools cpio python3-binwalk

ADD http://gateway.c01.sbcglobal.net/firmware/00D09E/11.14.1.533857-PROD/att-5268-11.14.1.533857_prod_lightspeed-install.pkgstream install.pkgstream
