/**
 * Get scan name from scan object
 * @param {Object} scan_object - Scan object from API
 * @returns {string} Scan name for display
 */
function getScanName(scan_object) {
  return scan_object.display_runner_type + ': ' + scan_object.display_scan_name;
}

function getScanStatusSidebar(endpoint_url, endpoint_stop_scan_url, endpoint_stop_activity_url, endpoint_scan_status_url, project, reload) {
  // Handle calls without parameters by using defaults or extracting from DOM
  // Note: endpoint_scan_status_url is kept for compatibility but not currently used in this function
  const finalEndpointUrl = endpoint_url || '/api/scan_status/';
  const finalStopScanUrl = endpoint_stop_scan_url || '/api/stop_scan/';
  const finalStopActivityUrl = endpoint_stop_activity_url || '/api/stop_activity/';
  
  let finalProject = project;
  if (!finalProject) {
    // Try to extract project from URL or DOM
    const urlMatch = window.location.pathname.match(/\/scan\/([^\/]+)\//);
    if (urlMatch) {
      finalProject = urlMatch[1];
    } else {
      const projectElement = document.querySelector('[data-project-slug]');
      if (projectElement) {
        finalProject = projectElement.getAttribute('data-project-slug');
      }
    }
  }
  
  // Ensure we have a valid project before making the request
  if (!finalProject) {
    console.error('getScanStatusSidebar: Unable to determine project slug. Cannot load scan status.');
    return;
  }
  
  const finalReload = reload !== undefined ? reload : false;
  
  $.getJSON(finalEndpointUrl + '?project=' + finalProject, function(data) {
    // main scans
    $('#currently_scanning').empty();
    $('#completed').empty();
    $('#upcoming_scans').empty();

    // subtasks
    $('#currently_running_tasks').empty();
    $('#completed_tasks').empty();
    $('#upcoming_tasks').empty();
    $('#current_task_count').empty();

    scans = data['scans'];
    tasks = data['tasks'];

    if (scans['pending'].length > 0){
      for (var scan in scans['pending']) {
        scan_object = scans['pending'][scan];
        const scan_name = getScanName(scan_object);
        $('#upcoming_scans').append(`
          <div class="alert alert-warning" role="alert">${htmlEncode(scan_name)} on ${scan_object.domain.name}</div>
          `);
      }
    }
    else{
      $('#upcoming_scans').html(`<div class="alert alert-info" role="alert">No upcoming Scans.</div>`);
    }

    if (scans['scanning'].length > 0){
      $('#current_scan_counter').html(scans['scanning'].length);
      $('#current_scan_count').html(`${scans['scanning'].length} Scans Currently Running`)
      for (var scan in scans['scanning']) {
        scan_object = scans['scanning'][scan];
        
        // Format current task display
        let currentTaskDisplay = '';
        if (scan_object.current_task) {
          currentTaskDisplay = `<br><small class="text-muted font-weight-bold">${scan_object.current_task}</small>`;
        }
        
        // Get scan name (legacy or Secator)
        const scan_name = getScanName(scan_object);
        
        $('#currently_scanning').append(`
          <div class="card border-primary border mini-card" id="scan-card-${scan_object.id}">
          <a href="/scan/${project}/${scan_object.id}" class="text-reset item-hovered">
          <div class="card-header bg-soft-primary text-primary mini-card-header">
          ${htmlEncode(scan_name)} on ${scan_object.domain.name}
          <span class="badge badge-soft-primary float-end">
          ${scan_object.current_progress}%
          </span>
          ${currentTaskDisplay}
          </div>
          <div class="card-body mini-card-body">
          <p class="card-text">
          <span class="badge badge-soft-primary float-end scan_status">
          Scanning
          </span>
          <span class="">
          Started ${scan_object.elapsed_time} ago.
          </span>
          </p>
          <div>
          <span class="badge-subdomain-count badge badge-pills bg-info mt-1" data-toggle="tooltip" data-placement="top" title="Subdomains">&nbsp;&nbsp;${scan_object.subdomain_count}&nbsp;&nbsp;</span>
          <span class="badge-endpoint-count badge badge-pills bg-warning mt-1" data-toggle="tooltip" data-placement="top" title="Endpoints">&nbsp;&nbsp;${scan_object.endpoint_count}&nbsp;&nbsp;</span>
          <span class="badge-vuln-count badge badge-pills bg-danger mt-1" data-toggle="tooltip" data-placement="top" title="Vulnerabilities">&nbsp;&nbsp;${scan_object.vulnerability_count}&nbsp;&nbsp;</span>
          </div>
          <div class="progress mt-2 progress-4px">
          <div class="progress-bar progress-bar-striped progress-bar-animated bg-primary scan-progress-bar" role="progressbar" aria-valuenow="${scan_object.current_progress}" aria-valuemin="0" aria-valuemax="100" style="width: ${scan_object.current_progress}%"></div>
          </div>
          <a href="#" onclick="stop_scan('${finalStopScanUrl}', scan_id=${scan_object.id}, subscan_id=null, reload_scan_bar=true, reload_location=false)" class="btn btn-xs btn-soft-danger waves-effect waves-light mt-1 float-end"><i class="fe-alert-triangle"></i> Stop</a>
          </div>
          </a>
          </div>
          `);
        }
      }
      else{
        $('#currently_scanning').html(`<div class="alert alert-info" role="alert">No Scans are currently running.</div>`);
      }

      if (scans['completed'].length > 0){
        for (var scan in scans['completed']) {
          scan_object = scans['completed'][scan];
          if (scan_object.scan_status == 0 ) {
            bg_color = 'bg-soft-danger';
            color = 'danger';
            status_badge = '<span class="float-end badge bg-danger">Failed</span>';
          }
          else if (scan_object.scan_status == 3) {
            bg_color = 'bg-soft-danger';
            color = 'danger';
            status_badge = '<span class="float-end badge bg-danger">Aborted</span>';
          }
          else if (scan_object.scan_status == 2){
            bg_color = 'bg-soft-success';
            color = 'success';
            status_badge = '<span class="float-end badge bg-success">Scan Completed</span>';
          }

          // Get scan name (legacy or Secator)
          const completed_scan_name = getScanName(scan_object);
          
          $('#completed').append(`
            <div class="card border-${color} border mini-card" id="scan-card-${scan_object.id}">
            <a href="/scan/${project}/${scan_object.id}" class="text-reset item-hovered float-end">
            <div class="card-header ${bg_color} text-${color} mini-card-header">
            ${htmlEncode(completed_scan_name)} on ${scan_object.domain.name}
            </div>
            <div class="card-body mini-card-body">
            <p class="card-text">
            ${status_badge}
            <span class="">
            Scan Completed ${scan_object.completed_ago} ago
            </span>
            <div>
            <span class="badge-subdomain-count badge badge-pills bg-info mt-1" data-toggle="tooltip" data-placement="top" title="Subdomains">&nbsp;&nbsp;${scan_object.subdomain_count}&nbsp;&nbsp;</span>
            <span class="badge-endpoint-count badge badge-pills bg-warning mt-1" data-toggle="tooltip" data-placement="top" title="Endpoints">&nbsp;&nbsp;${scan_object.endpoint_count}&nbsp;&nbsp;</span>
            <span class="badge-vuln-count badge badge-pills bg-danger mt-1" data-toggle="tooltip" data-placement="top" title="Vulnerabilities">&nbsp;&nbsp;${scan_object.vulnerability_count}&nbsp;&nbsp;</span>
            </div>
            </p>
            </div>
            </a>
            </div>
            `);
        }
      }
      else{
        $('#completed').html(`<div class="alert alert-info" role="alert">No scans have been recently completed.</div>`);
      }


      // tasks

      if (tasks['running'].length > 0){
        $('#current_task_count').html(`${tasks['running'].length} Tasks are currently running`)
        for (let task in tasks['running']) {
          const task_object = tasks['running'][task];
          const task_name = task_object.formatted_task_name || 'Unknown Task';
          const domain_name = task_object.domain_name || 'Unknown';
          const engine_name = task_object.engine_name || 'Unknown';

          $('#currently_running_tasks').append(`
            <div class="card border-primary border mini-card">
            <a href="/scan/${project}/${task_object.scan_id}" class="text-reset item-hovered">
            <div class="card-header bg-soft-primary text-primary mini-card-header">
            ${task_name} on <b>${domain_name}</b> using engine <b>${htmlEncode(engine_name)}</b>
            </div>
            <div class="card-body mini-card-body">
            <p class="card-text">
            <span class="badge badge-soft-primary float-end scan_status">
            In Progress
            </span>
            <span class="">
            Running Since ${task_object.elapsed_time} ago.
            </span>
            </p>
            <div>
            </div>
            </div>
            </a>
            <a href="#" onclick="stop_activity('${finalStopActivityUrl}', activity_id=${task_object.id}, reload_scan_bar=true, reload_location=false); return false;" class="btn btn-xs btn-soft-danger waves-effect waves-light mt-1 float-end"><i class="fe-alert-triangle"></i> Stop</a>
            </div>
          `);
        }
      }
      else{
        $('#currently_running_tasks').html(`<div class="alert alert-info" role="alert">No tasks are currently running.</div>`);
      }

      if (tasks['completed'].length > 0){
        for (let task in tasks['completed']) {
          const task_object = tasks['completed'][task];
          const task_name = task_object.formatted_task_name || 'Unknown Task';
          const domain_name = task_object.domain_name || 'Unknown';
          let error_message = '';

          let bg_color;
          let color;
          let status_badge;
          if (task_object.status == 0) {
            bg_color = 'bg-soft-danger';
            color = 'danger';
            status_badge = '<span class="float-end badge bg-danger">Failed</span>';
            if (task_object.error_message) {
              error_message = `<small class="text-danger">${task_object.error_message}</small><br>`;
            }
          }
          else if (task_object.status == 2) {
            bg_color = 'bg-soft-success';
            color = 'success';
            status_badge = '<span class="float-end badge bg-success">Completed</span>';
          }

          $('#completed_tasks').append(`
            <div class="card border-${color} border mini-card">
            <a href="/scan/${project}/${task_object.scan_id}" class="text-reset item-hovered">
            <div class="card-header ${bg_color} text-${color} mini-card-header">
            ${task_name} on <b>${domain_name}</b>
            </div>
            <div class="card-body mini-card-body">
            <p class="card-text">
            ${status_badge}
            ${error_message}
            <span class="">
            Completed ${task_object.elapsed_time} ago
            </span>
            </p>
            </div>
            </a>
            </div>
          `);
        }
      }
      else{
        $('#completed_tasks').html(`<div class="alert alert-info" role="alert">No tasks have been recently completed.</div>`);
      }

      if (tasks['pending'].length > 0){
        for (var task in tasks['pending']) {
          task_object = tasks['pending'][task];
          task_name = task_object.formatted_task_name || 'Unknown Task';

          status_badge = '<span class="float-end badge bg-warning">Upcoming</span>';

          $('#upcoming_tasks').append(`<div class="alert alert-warning" role="alert">${task_name} on ${task_object.subdomain_name}</div>`);
        }
      }
      else{
        $('#upcoming_tasks').html(`<div class="alert alert-info" role="alert">No upcoming tasks.</div>`);
      }

    }).done(function() {
      tippy('.scan_status', {
        content: 'Scan Status',
      });
      tippy('.badge-subdomain-count', {
        content: 'Subdomains',
      });
      tippy('.badge-endpoint-count', {
        content: 'Endpoints',
      });
      tippy('.badge-vuln-count', {
        content: 'Vulnerabilities',
      });
      tippy('.badge-scan_engine-type', {
        content: 'Scan Engine',
      });
      if(finalReload){
        Snackbar.show({
          text: 'Scan Status Reloaded.',
          pos: 'top-right',
          actionTextColor: '#42A5F5',
          duration: 1500
        });
      }
      
      // Connect to WebSocket for real-time updates if available
      if (typeof connectScanStatusWebSocket === 'function') {
        connectScanStatusWebSocket(null, finalProject, {
          updateSidebar: function(data) {
            updateRightSidebar(data);
          }
        });
      }
    });

  }

// Compatibility function for other parts of the codebase
function get_task_name(data){
  // Use formatted_task_name if available (from ScanActivitySerializer)
  if (data.formatted_task_name) {
    return data.formatted_task_name;
  }
  
  // Fallback to old type-based mapping for SubScan objects
  if (data['type'] == 'dir_file_fuzz') {
    return 'Directory Fuzzing';
  }
  else if (data['type'] == 'port_scan') {
    return 'Port Scan';
  }
  else if (data['type'] == 'fetch_url') {
    return 'Endpoint Gathering';
  }
  else if (data['type'] == 'vulnerability_scan') {
    return 'Vulnerability Scan';
  }
  else if (data['type'] == 'osint') {
    return 'OSINT';
  }
  else{
    return 'Unknown';
  }
}
