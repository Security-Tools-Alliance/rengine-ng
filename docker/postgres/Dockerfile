# Multi-stage build to get PostgreSQL 12 binaries
FROM postgres:12-bookworm as pg12
FROM postgres:17-bookworm

# Install ICU and LDAP libraries for Bookworm, plus iproute2 for network detection
RUN apt update && apt install -y libicu72 libldap-2.5-0 libldap-common libldap-dev procps iproute2

# Copy PostgreSQL 12 binaries from the pg12 stage
COPY --from=pg12 /usr/lib/postgresql/12/bin/pg_* /usr/local/pgsql-12/bin/
COPY --from=pg12 /usr/lib/postgresql/12/bin/postgres /usr/local/pgsql-12/bin/
COPY --from=pg12 /usr/lib/postgresql/12/bin/postmaster /usr/local/pgsql-12/bin/
COPY --from=pg12 /usr/lib/postgresql/12/bin/pg_ctl /usr/local/pgsql-12/bin/

# Copy libraries to the correct location that PostgreSQL 12 expects
COPY --from=pg12 /usr/lib/postgresql /usr/local/pgsql-12/lib/postgresql/
COPY --from=pg12 /usr/share/postgresql /usr/local/pgsql-12/share/postgresql/

# Copy PostgreSQL 12 share files to the system location
COPY --from=pg12 /usr/share/postgresql/12 /usr/share/postgresql/12

# Also copy the main library directory
COPY --from=pg12 /usr/lib/libpq* /usr/local/pgsql-12/lib/
COPY --from=pg12 /usr/lib/libecpg* /usr/local/pgsql-12/lib/

# Copy additional PostgreSQL 12 libraries that might be needed
COPY --from=pg12 /usr/lib/libpgcommon.so* /usr/local/pgsql-12/lib/
COPY --from=pg12 /usr/lib/libpgport.so* /usr/local/pgsql-12/lib/

# Copy the exact ICU libraries from PostgreSQL 12 image
COPY --from=pg12 /usr/lib/libicu*.so.* /usr/lib/

# Set environment variables
ENV PGBINOLD=/usr/local/pgsql-12/bin
ENV PGBINNEW=/usr/lib/postgresql/17/bin
ENV LD_LIBRARY_PATH=/usr/local/pgsql-12/lib:$LD_LIBRARY_PATH

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]