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

    # Configurable wait for postgres processes to stop
    POSTGRES_STOP_TIMEOUT="${POSTGRES_STOP_TIMEOUT:-15}"   # seconds
    POSTGRES_STOP_INTERVAL="${POSTGRES_STOP_INTERVAL:-1}"  # seconds

    ELAPSED=0
    while pgrep postgres >/dev/null; do
        if [ "$ELAPSED" -ge "$POSTGRES_STOP_TIMEOUT" ]; then
            echo "Timeout waiting for PostgreSQL processes to stop."
            echo "Error: PostgreSQL did not stop within $POSTGRES_STOP_TIMEOUT seconds. Exiting."
            exit 1
        fi
        sleep "$POSTGRES_STOP_INTERVAL"
        ELAPSED=$((ELAPSED + POSTGRES_STOP_INTERVAL))
    done

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
            echo "Error: PostgreSQL did not stop within $TIMEOUT seconds. Exiting."
            exit 1
        fi
        sleep "$INTERVAL"
        ELAPSED=$((ELAPSED + INTERVAL))
    done
    
    # Create socket directory
    mkdir -p /var/run/postgresql
    chown postgres:postgres /var/run/postgresql
    chmod 2775 /var/run/postgresql
    
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
        
        
        echo "Migration completed and data updated in $PGDATA"
    fi
}

# Main logic
if check_old_data; then
    perform_migration
else
    echo "No PostgreSQL 12 data found or already migrated. Starting normally..."
fi


# Create a script that configures pg_hba.conf after PostgreSQL starts
cat > /usr/local/bin/configure-pg-hba.sh << 'EOF'
#!/bin/bash
set -e

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
until pg_isready -h localhost -p 5432 -U rengine; do
    echo "PostgreSQL is not ready yet, waiting..."
    sleep 2
done

echo "PostgreSQL is ready, configuring pg_hba.conf..."

# Configure pg_hba.conf
PGDATA=${PGDATA:-/var/lib/postgresql/data}

if [ -f "$PGDATA/pg_hba.conf" ]; then
    echo "Configuring pg_hba.conf for Docker network access..."
    
    # Add Docker network rules if they don't exist
    docker_networks=("192.168.0.0/16" "172.16.0.0/12" "10.0.0.0/8")
    
    for network in "${docker_networks[@]}"; do
        if ! grep -q "$network" "$PGDATA/pg_hba.conf"; then
            echo "host    all             all             $network          trust" >> "$PGDATA/pg_hba.conf"
            echo "✓ Added rule: $network"
        else
            echo "✓ Rule already exists: $network"
        fi
    done
    
    echo "pg_hba.conf configuration completed"
    
    # Reload PostgreSQL configuration
    echo "Reloading PostgreSQL configuration..."
    psql -h localhost -p 5432 -U rengine -c "SELECT pg_reload_conf();" || echo "Warning: Could not reload configuration"
else
    echo "Warning: pg_hba.conf not found at $PGDATA/pg_hba.conf"
fi
EOF

chmod +x /usr/local/bin/configure-pg-hba.sh

# Start the configuration script in the background
/usr/local/bin/configure-pg-hba.sh &

# Start PostgreSQL normally after migration or if no migration needed
echo "Starting PostgreSQL..."
exec docker-entrypoint.sh postgres