#!/bin/bash

print_msg() {
  printf "\r\n"
  printf "========================================\r\n"
  printf "$1\r\n"
  printf "========================================\r\n\r\n"
}

print_msg "Generate Django migrations files"
poetry run -C $HOME/ python3 manage.py makemigrations
print_msg "Migrate database"
poetry run -C $HOME/ python3 manage.py migrate
print_msg "Collect static files"
poetry run -C $HOME/ python3 manage.py collectstatic --no-input --clear

# Load default engines, keywords, and external tools
print_msg "Load default engines"
poetry run -C $HOME/ python3 manage.py loaddata fixtures/default_scan_engines.yaml --app scanEngine.EngineType
print_msg "Load default keywords"
poetry run -C $HOME/ python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
print_msg "Load default external tools"
poetry run -C $HOME/ python3 manage.py loaddata fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool

if [ ! "$CELERY_LOGLEVEL" ]; then
  export CELERY_LOGLEVEL='info'
fi

print_msg "Start celery workers"
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --loglevel=$CELERY_LOGLEVEL --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY -Q main_scan_queue &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=30 --loglevel=$CELERY_LOGLEVEL -Q initiate_scan_queue -n initiate_scan_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=30 --loglevel=$CELERY_LOGLEVEL -Q subscan_queue -n subscan_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=20 --loglevel=$CELERY_LOGLEVEL -Q report_queue -n report_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=10 --loglevel=$CELERY_LOGLEVEL -Q send_notif_queue -n send_notif_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=10 --loglevel=$CELERY_LOGLEVEL -Q send_scan_notif_queue -n send_scan_notif_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=10 --loglevel=$CELERY_LOGLEVEL -Q send_task_notif_queue -n send_task_notif_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=5 --loglevel=$CELERY_LOGLEVEL -Q send_file_to_discord_queue -n send_file_to_discord_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=5 --loglevel=$CELERY_LOGLEVEL -Q send_hackerone_report_queue -n send_hackerone_report_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=10 --loglevel=$CELERY_LOGLEVEL -Q parse_nmap_results_queue -n parse_nmap_results_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=20 --loglevel=$CELERY_LOGLEVEL -Q geo_localize_queue -n geo_localize_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=10 --loglevel=$CELERY_LOGLEVEL -Q query_whois_queue -n query_whois_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=30 --loglevel=$CELERY_LOGLEVEL -Q remove_duplicate_endpoints_queue -n remove_duplicate_endpoints_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=50 --loglevel=$CELERY_LOGLEVEL -Q run_command_queue -n run_command_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=10 --loglevel=$CELERY_LOGLEVEL -Q query_reverse_whois_queue -n query_reverse_whois_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=10 --loglevel=$CELERY_LOGLEVEL -Q query_ip_history_queue -n query_ip_history_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=30 --loglevel=$CELERY_LOGLEVEL -Q llm_queue -n llm_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=10 --loglevel=$CELERY_LOGLEVEL -Q dorking_queue -n dorking_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=10 --loglevel=$CELERY_LOGLEVEL -Q osint_discovery_queue -n osint_discovery_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=10 --loglevel=$CELERY_LOGLEVEL -Q h8mail_queue -n h8mail_worker &
watchmedo auto-restart --recursive --pattern="*.py" --directory="/home/rengine/rengine/" -- poetry run -C $HOME/ celery -A reNgine.tasks worker --pool=gevent --concurrency=10 --loglevel=$CELERY_LOGLEVEL -Q theHarvester_queue -n theHarvester_worker

exec "$@"