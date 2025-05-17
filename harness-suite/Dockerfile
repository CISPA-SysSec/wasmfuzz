FROM ubuntu:24.04 AS builder

RUN apt-get update && \
    apt-get install -y make build-essential git wget curl tar vim rename python3-tomlkit

# install commonly-used building packages
RUN apt-get install -y autoconf automake autopoint libtool \
    make cmake pkg-config meson ninja-build \
    clang libz-dev libreadline-dev

COPY scripts/ /usr/bin/
RUN prepare-toolchain.sh && mkdir /out/

ARG project_name
ARG project_path
ARG build_type="wasi-lime1"
ARG build_flags="foo;bar"
ENV PROJECT=/projects/${project_name}
ENV BUILD_TYPE=${build_type}
ENV BUILD_FLAGS=${build_flags}

WORKDIR ${PROJECT}
# COPY ${project_name}/prepare.sh ${PROJECT}/prepare.sh
COPY ${project_path} ${PROJECT}/
RUN ${PROJECT}/prepare.sh
# remove the build artifacts to keep cached layers small
RUN ${PROJECT}/build.sh && rm -rf ${PROJECT}

RUN postprocess-outputs.sh

FROM scratch
COPY --from=builder /out /out
