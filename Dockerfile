FROM ubuntu:20.04

ENV GHIDRA_DOWNLOAD_SHA ac96fbdde7f754e0eb9ed51db020e77208cdb12cf58c08657a2ab87cb2694940
ENV GHIDRA_DOWNLOAD_URL \
https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip
ENV GHIDRA_INSTALL_DIR /ghidra

#
# Install APT packages
# Setting a timezone is needed to avoid an interactive prompt from dpkg
#
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime \
    && apt-get update && apt-get install -y --no-install-recommends \
    fontconfig libxrender1 libxtst6 libxi6 wget unzip git openjdk-11-jdk gnupg cmake \
    protobuf-compiler libprotobuf-dev build-essential maven

#
# Download Ghidra and install it to /ghidra
#
RUN wget --progress=bar:force -O /tmp/ghidra.zip ${GHIDRA_DOWNLOAD_URL} \
    && echo "$GHIDRA_DOWNLOAD_SHA /tmp/ghidra.zip" | sha256sum -c - \
    && unzip /tmp/ghidra.zip \
    && rm /tmp/ghidra.zip \
    && mv ghidra_* ${GHIDRA_INSTALL_DIR} \
    && chmod +x ${GHIDRA_INSTALL_DIR}/ghidraRun

#
# Install ddisasm from the public APT repository
#
RUN wget -O - https://download.grammatech.com/gtirb/files/apt-repo/conf/apt.gpg.key | apt-key add - \
    && echo "deb https://download.grammatech.com/gtirb/files/apt-repo focal stable" > /etc/apt/sources.list.d/gtirb.list \
    && apt-get update \
    && apt-get install -y libgtirb gtirb-pprinter ddisasm

#
# Install Gradle. Ghidra 10.1.2 requires Gradle 6.8+
#
RUN wget --progress=bar:force -O /tmp/gradle.zip https://services.gradle.org/distributions/gradle-7.3.3-bin.zip \
    && unzip -d /opt /tmp/gradle.zip \
    && rm /tmp/gradle.zip \
    && ln -s /opt/gradle-7.3.3/bin/gradle /usr/local/bin/

RUN mkdir /workspace

#
# Clone Gtirb and build Java API
#
RUN git clone https://github.com/GrammaTech/gtirb.git /workspace/gtirb \
    && cd /workspace/gtirb \
    && protoc --java_out=java --proto_path=proto ./proto/*.proto \
    && mkdir build && cd build \
    && cmake -DGTIRB_CXX_API=OFF -DGTIRB_PY_API=OFF -DGTIRB_CL_API=OFF .. \
    && cd java \
    && make

#
# Build and install gtirb_ghidra_plugin
#
ADD . /workspace/gtirb-ghidra-plugin
RUN cd /workspace/gtirb-ghidra-plugin/Gtirb \
    && rm -f lib/*.jar dist/*.zip \
    && cp /workspace/gtirb/build/java/target/*.jar lib/ \
    && gradle \
    && unzip -d ${GHIDRA_INSTALL_DIR}/Ghidra/Extensions/ dist/*.zip

#
# Clean up
#
RUN  echo "===> Clean up unnecessary files..." \
    && apt-get purge -y --auto-remove wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives /tmp/* /var/tmp/* /ghidra/docs /ghidra/Extensions/Eclipse /ghidra/licenses

#
# Try importing gtirb file - headless
# Use headless script to verify imported file is there
#
RUN cd /workspace/gtirb-ghidra-plugin/tests \
    && ./test-import
