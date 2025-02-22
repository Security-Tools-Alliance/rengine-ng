#!/bin/bash

print_msg() {
  printf "\r\n"
  printf "========================================\r\n"
  printf "$1\r\n"
  printf "========================================\r\n\r\n"
}

RENGINE_FOLDER="/home/$USERNAME/rengine"
MAX_CONCURRENCY=${MAX_CONCURRENCY:-20}
MIN_CONCURRENCY=${MIN_CONCURRENCY:-5}
CELERY_LOGLEVEL=${CELERY_LOGLEVEL:-info}

print_msg "Generate Django migrations files"
poetry run -C $RENGINE_FOLDER python3 manage.py makemigrations
print_msg "Migrate database"
poetry run -C $RENGINE_FOLDER python3 manage.py migrate
print_msg "Collect static files"
poetry run -C $RENGINE_FOLDER python3 manage.py collectstatic --no-input --clear

# Load default engines, keywords, and external tools
print_msg "Load default engines"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata fixtures/default_scan_engines.yaml --app scanEngine.EngineType
print_msg "Load default keywords"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
print_msg "Load default external tools"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool

worker_command() {
    local queue=$1
    local worker_name=$2
    
    if [ "$CELERY_DEBUG" = "1" ]; then
        echo "watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"$RENGINE_FOLDER\" -- \
            poetry run -C $RENGINE_FOLDER celery -A reNgine.tasks worker \
            --pool=prefork \
            --loglevel=$CELERY_LOGLEVEL \
            --concurrency=1 \
            -Q $queue -n $worker_name"
    else
        echo "poetry run -C $RENGINE_FOLDER celery -A reNgine.tasks worker \
            --pool=gevent \
            --loglevel=$CELERY_LOGLEVEL \
            --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY \
            -Q $queue -n $worker_name"
    fi
}

queues=(
    "main_scan_queue:main_scan_worker"
    "subscan_queue:subscan_worker"
    "subdomain_discovery_queue:subdomain_discovery_worker"
    "osint_discovery_queue:osint_discovery_worker"
    "port_scan_queue:port_scan_worker"
    "vulnerability_scan_queue:vulnerability_scan_worker"
    "nuclei_queue:nuclei_worker"
    "dalfox_queue:dalfox_worker"
    "dir_fuzzing_queue:dir_fuzzing_worker"
    "screenshot_queue:screenshot_worker"
    "waf_detection_queue:waf_detection_worker"
    "http_crawl_queue:http_crawl_worker"
    "crlfuzz_queue:crlfuzz_worker"
    "s3scanner_queue:s3scanner_worker"
    "report_queue:report_worker"
    "send_notif_queue:send_notif_worker"
    "send_scan_notif_queue:send_scan_notif_worker"
    "send_task_notif_queue:send_task_notif_worker"
    "parse_nmap_results_queue:parse_nmap_results_worker"
    "geo_localize_queue:geo_localize_worker"
    "query_whois_queue:query_whois_worker"
    "query_reverse_whois_queue:query_reverse_whois_worker"
    "gpt_queue:gpt_worker"
    "dorking_queue:dorking_worker"
    "h8mail_queue:h8mail_worker"
    "theHarvester_queue:theHarvester_worker"
)

commands=""
for queue in "${queues[@]}"; do
    IFS=':' read -r queue worker_name <<< "$queue"
    commands+="$(worker_command "$queue" "$worker_name") &"$'\n'
done

eval "$commands"

wait

exec "$@"