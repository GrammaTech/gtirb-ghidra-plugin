FROM openjdk:11-jdk-slim

ENV GHIDRA_DOWNLOAD_FILE ghidra_9.1.2_PUBLIC_20200212.zip
ENV GHIDRA_DOWNLOAD_SHA ebe3fa4e1afd7d97650990b27777bb78bd0427e8e70c1d0ee042aeb52decac61
ENV GHIDRA_DOWNLOAD_VERSION 9.1.2_PUBLIC
ENV PROTOBUF_VERSION 3.11.4
ENV GHIDRA_INSTALL_DIR /ghidra

#
# Download Ghidra and install it to /ghidra
#
RUN apt-get update && apt-get install -y fontconfig libxrender1 libxtst6 libxi6 wget unzip git --no-install-recommends \
    && wget --progress=bar:force -O /tmp/ghidra.zip https://www.ghidra-sre.org/${GHIDRA_DOWNLOAD_FILE} \
    && echo "$GHIDRA_DOWNLOAD_SHA /tmp/ghidra.zip" | sha256sum -c - \
    && unzip /tmp/ghidra.zip \
    && mv ghidra_${GHIDRA_DOWNLOAD_VERSION} ${GHIDRA_INSTALL_DIR} \
    && chmod +x ${GHIDRA_INSTALL_DIR}/ghidraRun

#
# Install protobuf compiler, will need it for Java API
#
RUN mkdir /workspace \
    && wget --progress=bar:force -O /workspace/protoc \
      https://repo1.maven.org/maven2/com/google/protobuf/protoc/${PROTOBUF_VERSION}/protoc-${PROTOBUF_VERSION}-linux-x86_64.exe \
    && chmod u+x /workspace/protoc \
    && cd /bin \
    && ln -s /workspace/protoc

#
# Clone gtirb and generate protobuf java files
#
RUN cd /workspace \
    && git clone https://git.grammatech.com/rewriting/gtirb.git \
    && cd /workspace/gtirb \
    && protoc --java_out=java --proto_path=proto ./proto/*.proto

#
# Clone gtirb_ghidra_plugin and copy gtirb and protobuf files in
# 
RUN cd /workspace \
    && git clone https://git.grammatech.com/rewriting/gtirb-ghidra-plugin.git \
    && cp -r /workspace/gtirb/java/com/grammatech/gtirb /workspace/gtirb-ghidra-plugin/Gtirb/src/main/java/com/grammatech

#
# Get java protobuf jar file, a dependency for the plugin
#
RUN wget --progress=bar:force -O /workspace/protobuf-java-${PROTOBUF_VERSION}.jar \
    https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/${PROTOBUF_VERSION}/protobuf-java-${PROTOBUF_VERSION}.jar \
    && mv /workspace/protobuf-java-${PROTOBUF_VERSION}.jar /workspace/gtirb-ghidra-plugin/Gtirb/lib/

#
# Get gradle and use it to build plugin
#  (Ghdira has a specific requirement that Gradle 5 be used)
#
RUN wget --progress=bar:force -O /workspace/gradle.zip https://services.gradle.org/distributions/gradle-5.0-bin.zip \
    && cd /workspace \
    && unzip gradle.zip \
    && rm gradle.zip \
    && cd /bin && ln -s /workspace/gradle-5.0/bin/gradle \
    && cd /workspace/gtirb-ghidra-plugin/Gtirb \
    && gradle

#
# Install plugin into ghidra
#  (Putting the zip in Extensions/Ghidra and unzipping it to Ghidra/Extensions installs the plugin)
#
RUN cd /workspace/gtirb-ghidra-plugin/Gtirb/dist/ \
    && mv *.zip ${GHIDRA_INSTALL_DIR}/Extensions/Ghidra/${GHIDRA_DOWNLOAD_VERSION}_Gtirb.zip \ 
    && cd ${GHIDRA_INSTALL_DIR}/Ghidra/Extensions \
    && unzip ../../Extensions/Ghidra/${GHIDRA_DOWNLOAD_VERSION}_Gtirb.zip
    
#
# Clean up
# 
RUN  echo "===> Clean up unnecessary files..." \
    && apt-get purge -y --auto-remove wget unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives /tmp/* /var/tmp/* /ghidra/docs /ghidra/Extensions/Eclipse /ghidra/licenses

#
# Try importing gtirb file - headless
# Use headless script to verify imported file is there
#
RUN cd /workspace/gtirb-ghidra-plugin/test \
    && ./test-import
