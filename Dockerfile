# The tenbri CLI (tenbri proxy is the MCP proxy) and the tenbrid daemon, from the static musl binaries the release ships:
# release.yml puts them in dist/<arch>/ before building, so the image runs the same bytes as
# the archive on the GitHub release. distroless/static has CA certificates and a nonroot user.
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETARCH
COPY dist/${TARGETARCH}/tenbri dist/${TARGETARCH}/tenbrid /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/tenbri"]
