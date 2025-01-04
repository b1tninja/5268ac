FROM dockcross/linux-mips

#ENV DEFAULT_DOCKCROSS_IMAGE=5268ac

# Install binwalk
RUN apt-get install -y bzip2 squashfs-tools cpio python3-binwalk
