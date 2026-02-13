# Extend edoburu/pgbouncer and ensure the Unix user matching POSTGRES_USER
# exists so pgbouncer can setuid to it while using that user for DB connections.
# Pin version to avoid unexpected changes from :latest; update intentionally when upgrading.
FROM edoburu/pgbouncer:v1.25.1-p0

COPY --chmod=755 entrypoint.sh /usr/local/bin/rengine-pgbouncer-entrypoint.sh

# Run entrypoint as root so adduser can create POSTGRES_USER (base image may set USER).
USER root

ENTRYPOINT ["/usr/local/bin/rengine-pgbouncer-entrypoint.sh"]
