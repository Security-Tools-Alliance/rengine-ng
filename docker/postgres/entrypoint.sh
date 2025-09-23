#!/bin/bash

set -e

# Use PostgreSQL default environment variables
PGDATA=${PGDATA:-/var/lib/postgresql/data}
PGDATAOLD=/tmp/postgresql-data-old
PGDATANEW=/tmp/postgresql-data-new
PGBINOLD=${PGBINOLD:-/usr/local/pgsql-12/bin}
PGBINNEW=${PGBINNEW:-/usr/lib/postgresql/17/bin}

# Get the database user from environment (default to postgres if not set)
DB_USER=${POSTGRES_USER:-rengine}

# Function to configure pg_hba.conf for Docker network access
configure_pg_hba() {
    echo "Configuring pg_hba.conf for Docker network access..."
    
    # Get the Docker network subnet dynamically
    local docker_network=$(ip route | grep -E '^172\.|^192\.168\.|^10\.' | head -1 | awk '{print $1}')
    
    if [ -n "$docker_network" ]; then
        echo "Detected Docker network: $docker_network"
        # Use trust authentication for the specific Docker network (port not exposed in production)
        if ! grep -q "$docker_network" "$PGDATA/pg_hba.conf"; then
            echo "host    all             all             $docker_network          trust" >> "$PGDATA/pg_hba.conf"
        fi
    else
        # Fallback: allow connections from Docker's default bridge network
        echo "Using fallback Docker network configuration..."
        if ! grep -q "172.17.0.0/16" "$PGDATA/pg_hba.conf"; then
            echo "host    all             all             172.17.0.0/16          trust" >> "$PGDATA/pg_hba.conf"
        fi
    fi
    
    # Allow local connections with trust authentication
    if ! grep -q "host.*all.*all.*127.0.0.1/32.*trust" "$PGDATA/pg_hba.conf"; then
        echo "host    all             all             127.0.0.1/32            trust" >> "$PGDATA/pg_hba.conf"
    fi
    
    echo "Docker network access configured with trust authentication"
}

echo "PGDATA: $PGDATA"
echo "PGDATAOLD: $PGDATAOLD"
echo "PGDATANEW: $PGDATANEW"
echo "PGBINOLD: $PGBINOLD"
echo "PGBINNEW: $PGBINNEW"
echo "DB_USER: $DB_USER"

# Function to check if data directory contains PostgreSQL 12 data
check_old_data() {
    if [ -f "$PGDATA/PG_VERSION" ]; then
        local version=$(cat "$PGDATA/PG_VERSION")
        echo "Found PostgreSQL version: $version"
        if [ "$version" = "12" ]; then
            return 0  # Old data found
        fi
    fi
    return 1  # No old data or already migrated
}

# Function to perform migration
perform_migration() {
    echo "========================================="
    echo "Old PostgreSQL data detected - Starting migration to current PostgreSQL version"
    echo "========================================="
    
    # Clean up any existing temporary directories
    echo "Cleaning up temporary directories..."
    rm -rf "$PGDATAOLD" "$PGDATANEW"
    
    # Ensure postgres user owns the directories
    chown -R postgres:postgres /var/lib/postgresql/
    
    # Copy old data to temporary location (can't move mounted volume)
    echo "Copying old data from $PGDATA to $PGDATAOLD"
    mkdir -p "$PGDATAOLD"
    cp -a "$PGDATA/." "$PGDATAOLD/"
    chown -R postgres:postgres "$PGDATAOLD"
    
    # Create temporary directory for new data
    mkdir -p "$PGDATANEW"
    chown -R postgres:postgres "$PGDATANEW"
    
    # Initialize new cluster with the rengine user as the superuser
    echo "Initializing new PostgreSQL cluster with user $DB_USER..."
    su - postgres -c "$PGBINNEW/initdb -D $PGDATANEW -U $DB_USER"
    
    # Stop any running PostgreSQL processes
    echo "Stopping any running PostgreSQL processes..."
    pkill postgres || true

    # Also try to stop PostgreSQL 17 specifically
    if [ -f "/usr/lib/postgresql/17/bin/pg_ctl" ]; then
        /usr/lib/postgresql/17/bin/pg_ctl stop -D "$PGDATA" -m fast || true
    fi

    # Wait for all PostgreSQL processes to stop, with a timeout
    TIMEOUT=15
    INTERVAL=1
    ELAPSED=0
    while pgrep postgres >/dev/null; do
        if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
            echo "Timeout waiting for PostgreSQL processes to stop."
            break
        fi
        sleep "$INTERVAL"
        ELAPSED=$((ELAPSED + INTERVAL))
    done
    
    # Create socket directory
    mkdir -p /var/run/postgresql
    chown postgres:postgres /var/run/postgresql
    chmod 2775 /var/run/postgresql
    
    # The PostgreSQL 17 cluster is now initialized with rengine as the superuser
    
    echo "Running pg_upgrade with user $DB_USER..."
    su - postgres -c "cd /tmp && PGUSER=$DB_USER $PGBINNEW/pg_upgrade \
        -b $PGBINOLD \
        -B $PGBINNEW \
        -d $PGDATAOLD \
        -D $PGDATANEW \
        -s /var/run/postgresql \
        --verbose" || {
        
        echo "pg_upgrade failed! Displaying log files:"
        find /tmp -name "*.log" -type f -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null || true
        
        echo "Migration failed! Keeping original data..."
        rm -rf "$PGDATAOLD" "$PGDATANEW"
        exit 1
    }
    
    if [ $? -eq 0 ]; then
        echo "========================================="
        echo "Migration completed successfully!"
        echo "========================================="
        
        # Clear the original data directory and copy new data
        echo "Replacing old data with migrated data..."
        rm -rf "$PGDATA"/*
        rm -rf "$PGDATA"/.[!.]* 2>/dev/null || true  # Remove hidden files too
        cp -a "$PGDATANEW/." "$PGDATA/"
        chown -R postgres:postgres "$PGDATA"
        
        # Cleanup temporary directories
        rm -rf "$PGDATAOLD" "$PGDATANEW"
        
        # Configure pg_hba.conf for Docker network access after migration
        configure_pg_hba
        
        echo "Migration completed and data updated in $PGDATA"
    fi
}

# Main logic
if check_old_data; then
    perform_migration
else
    echo "No PostgreSQL 12 data found or already migrated. Starting normally..."
fi

# Create a custom docker-entrypoint.sh that configures pg_hba.conf after initdb
cat > /usr/local/bin/custom-entrypoint.sh << 'EOF'
#!/bin/bash
set -e

# Configure pg_hba.conf for Docker network access
if [ -f /docker-entrypoint-initdb.d/configure-docker-access.sh ]; then
    bash /docker-entrypoint-initdb.d/configure-docker-access.sh
fi

# Call the original docker-entrypoint.sh
exec /usr/local/bin/docker-entrypoint.sh "$@"
EOF

chmod +x /usr/local/bin/custom-entrypoint.sh

# Add post-init hook to configure pg_hba.conf
cat > /docker-entrypoint-initdb.d/configure-docker-access.sh << 'EOF'
#!/bin/bash
echo "Configuring pg_hba.conf for Docker network access..."

# Get the Docker network subnet dynamically
docker_network=$(ip route | grep -E '^172\.|^192\.168\.|^10\.' | head -1 | awk '{print $1}')

if [ -n "$docker_network" ]; then
    echo "Detected Docker network: $docker_network"
    # Use trust authentication for the specific Docker network (port not exposed in production)
    if ! grep -q "$docker_network" "$PGDATA/pg_hba.conf"; then
        echo "host    all             all             $docker_network          trust" >> "$PGDATA/pg_hba.conf"
    fi
else
    # Fallback: allow connections from Docker's default bridge network
    echo "Using fallback Docker network configuration..."
    if ! grep -q "172.17.0.0/16" "$PGDATA/pg_hba.conf"; then
        echo "host    all             all             172.17.0.0/16          trust" >> "$PGDATA/pg_hba.conf"
    fi
fi

# Allow local connections with trust authentication
if ! grep -q "host.*all.*all.*127.0.0.1/32.*trust" "$PGDATA/pg_hba.conf"; then
    echo "host    all             all             127.0.0.1/32            trust" >> "$PGDATA/pg_hba.conf"
fi

echo "Docker network access configured with trust authentication"
EOF

chmod +x /docker-entrypoint-initdb.d/configure-docker-access.sh

# Start PostgreSQL normally after migration or if no migration needed
echo "Starting PostgreSQL..."
exec docker-entrypoint.sh postgres