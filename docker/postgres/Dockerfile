# Multi-stage build to get PostgreSQL 12 binaries
FROM postgres:12-alpine as pg12
FROM postgres:17.6-alpine

# Install ICU libraries compatible with PostgreSQL 12
RUN apk add --no-cache icu-libs

# Copy PostgreSQL 12 binaries from the pg12 stage
COPY --from=pg12 /usr/local/bin/pg_* /usr/local/pgsql-12/bin/
COPY --from=pg12 /usr/local/bin/postgres /usr/local/pgsql-12/bin/
COPY --from=pg12 /usr/local/bin/postmaster /usr/local/pgsql-12/bin/

# Copy libraries to the correct location that PostgreSQL 12 expects
COPY --from=pg12 /usr/local/lib/postgresql /usr/local/pgsql-12/lib/postgresql/
COPY --from=pg12 /usr/local/share/postgresql /usr/local/pgsql-12/share/postgresql/

# Also copy the main library directory
COPY --from=pg12 /usr/local/lib/libpq* /usr/local/pgsql-12/lib/
COPY --from=pg12 /usr/local/lib/libecpg* /usr/local/pgsql-12/lib/

# Copy the exact ICU libraries from PostgreSQL 12 image
COPY --from=pg12 /usr/lib/libicu*.so.* /usr/lib/

# Set environment variables
ENV PGBINOLD=/usr/local/pgsql-12/bin
ENV LD_LIBRARY_PATH=/usr/local/pgsql-12/lib:$LD_LIBRARY_PATH

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]