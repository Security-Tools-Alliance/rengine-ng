# Multi-stage build to get PostgreSQL 12 binaries
FROM postgres:12-bookworm as pg12
FROM postgres:17-bookworm

# Install ICU and LDAP libraries for Bookworm
RUN apt update && apt install -y libicu72 libldap-2.5-0 libldap-common libldap-dev

# Copy PostgreSQL 12 binaries from the pg12 stage
COPY --from=pg12 /usr/lib/postgresql/12/bin/pg_* /usr/local/pgsql-12/bin/
COPY --from=pg12 /usr/lib/postgresql/12/bin/postgres /usr/local/pgsql-12/bin/
COPY --from=pg12 /usr/lib/postgresql/12/bin/postmaster /usr/local/pgsql-12/bin/

# Copy libraries to the correct location that PostgreSQL 12 expects
COPY --from=pg12 /usr/lib/postgresql /usr/local/pgsql-12/lib/postgresql/
COPY --from=pg12 /usr/share/postgresql /usr/local/pgsql-12/share/postgresql/

# Also copy the main library directory
COPY --from=pg12 /usr/lib/libpq* /usr/local/pgsql-12/lib/
COPY --from=pg12 /usr/lib/libecpg* /usr/local/pgsql-12/lib/

# Copy the exact ICU libraries from PostgreSQL 12 image
COPY --from=pg12 /usr/lib/libicu*.so.* /usr/lib/

# Set environment variables
ENV PGBINOLD=/usr/local/pgsql-12/bin
ENV PGBINNEW=/usr/bin
ENV LD_LIBRARY_PATH=/usr/local/pgsql-12/lib:$LD_LIBRARY_PATH

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]