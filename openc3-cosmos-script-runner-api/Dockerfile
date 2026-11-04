ARG OPENC3_REGISTRY=docker.io
ARG OPENC3_NAMESPACE=openc3inc
# No default on purpose: openc3.sh build (compose-build.yaml), openc3_build_ubi.sh and
# build_multi_arch.sh always pass OPENC3_TAG, and a bare `docker build` must fail
# instead of silently pulling a mutable :latest base image.
ARG OPENC3_TAG
ARG OPENC3_IMAGE=openc3-base
# Optional "@sha256:<digest>" pin for builds against a published base image. Left empty
# for the in-repo build chain, where the base is built locally from the digest-pinned
# alpine/UBI root in openc3-ruby/.
ARG OPENC3_BASE_DIGEST=

FROM ${OPENC3_REGISTRY}/${OPENC3_NAMESPACE}/${OPENC3_IMAGE}:${OPENC3_TAG}${OPENC3_BASE_DIGEST}

WORKDIR /src/
COPY Gemfile ./

USER root

ENV SKIP_DEV_GEMS=1
RUN bundle config set --local without 'development test' && \
    bundle install --quiet && \
    rm -rf /usr/lib/ruby/gems/*/cache/* /var/cache/apk/* /tmp/* /var/tmp/*

RUN ["chown", "-R", "openc3:openc3", "/src/"]
COPY --chown=${IMAGE_USER}:${IMAGE_GROUP} ./ ./
# Create a /tmp directory with global write permissions including the sticky bit (chmod -R 1777)
# This is required for Ruby to be able to call Dir.mktmpdir and create temporary directories.
# The sticky bit ensures that only the owner of a file can delete it,
# even if other users have write permissions to the directory.
RUN mkdir -p /tmp && \
    rm -rf /src/tmp && \
    ln -s /tmp /src/tmp && \
    chmod -R 1777 /src/tmp && \
    chmod -R 555 /src/scripts

EXPOSE 2902

USER ${USER_ID}:${GROUP_ID}

ENV HOME=/tmp
ENV TMPDIR=/tmp
CMD [ "shoreman" ]
