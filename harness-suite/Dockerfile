FROM ubuntu:24.04 AS builder

RUN apt-get update && \
    apt-get install -y make build-essential git wget curl tar vim rename python3-tomlkit

# install commonly-used building packages
RUN apt-get install -y autoconf automake autopoint libtool \
    make cmake pkg-config meson ninja-build \
    g++ libz-dev libreadline-dev

COPY scripts/ /usr/bin/
RUN prepare-toolchain.sh && mkdir /out/

ARG project_name
ARG project_path
ENV PROJECT=/projects/${project_name}

WORKDIR ${PROJECT}
# COPY ${project_name}/prepare.sh ${PROJECT}/prepare.sh
COPY ${project_path} ${PROJECT}/
RUN ${PROJECT}/prepare.sh
# remove the build artifacts to keep cached layers small
RUN ${PROJECT}/build.sh && rm -rf ${PROJECT}

RUN postprocess-outputs.sh

FROM scratch
COPY --from=builder /out /out
