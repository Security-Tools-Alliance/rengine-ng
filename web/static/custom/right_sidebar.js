function getScanStatusSidebar(endpoint_url, endpoint_stop_scan_url, endpoint_scan_status_url, project, reload) {
  $.getJSON(endpoint_url + '?project=' + project, function(data) {
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
        $('#upcoming_scans').append(`
          <div class="alert alert-warning" role="alert">${htmlEncode(scan_object.scan_type.engine_name)} on ${scan_object.domain.name}</div>
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
        
        $('#currently_scanning').append(`
          <div class="card border-primary border mini-card">
          <a href="/scan/${project}/${scan_object.id}" class="text-reset item-hovered">
          <div class="card-header bg-soft-primary text-primary mini-card-header">
          ${htmlEncode(scan_object.scan_type.engine_name)} on ${scan_object.domain.name}
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
          <span class="badge-subdomain-count badge badge-soft-info waves-effect waves-light">&nbsp;&nbsp;${scan_object.subdomain_count}&nbsp;&nbsp;</span>
          <span class="badge-endpoint-count badge badge-soft-primary waves-effect waves-light">&nbsp;&nbsp;${scan_object.endpoint_count}&nbsp;&nbsp;</span>
          <span class="badge-vuln-count badge badge-soft-danger waves-effect waves-light">&nbsp;&nbsp;${scan_object.vulnerability_count}&nbsp;&nbsp;</span>
          </div>
          <div class="progress mt-2 progress-4px">
          <div class="progress-bar progress-bar-striped progress-bar-animated bg-primary" role="progressbar" aria-valuenow="${scan_object.current_progress}" aria-valuemin="0" aria-valuemax="100" style="width: ${scan_object.current_progress}%"></div>
          </div>
          <a href="#" onclick="stop_scan('${endpoint_stop_scan_url}', scan_id=${scan_object.id}, subscan_id=null, reload_scan_bar=true, reload_location=false)" class="btn btn-xs btn-soft-danger waves-effect waves-light mt-1 float-end"><i class="fe-alert-triangle"></i> Stop</a>
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

          $('#completed').append(`
            <div class="card border-${color} border mini-card">
            <a href="/scan/${project}/${scan_object.id}" class="text-reset item-hovered float-end">
            <div class="card-header ${bg_color} text-${color} mini-card-header">
            ${htmlEncode(scan_object.scan_type.engine_name)} on ${scan_object.domain.name}
            </div>
            <div class="card-body mini-card-body">
            <p class="card-text">
            ${status_badge}
            <span class="">
            Scan Completed ${scan_object.completed_ago} ago
            </span>
            <div>
            <span class="badge-subdomain-count badge badge-soft-info waves-effect waves-light">&nbsp;&nbsp;${scan_object.subdomain_count}&nbsp;&nbsp;</span>
            <span class="badge-endpoint-count badge badge-soft-primary waves-effect waves-light">&nbsp;&nbsp;${scan_object.endpoint_count}&nbsp;&nbsp;</span>
            <span class="badge-vuln-count badge badge-soft-danger waves-effect waves-light">&nbsp;&nbsp;${scan_object.vulnerability_count}&nbsp;&nbsp;</span>
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
        for (var task in tasks['running']) {
          var task_object = tasks['running'][task];
          var task_name = task_object.formatted_task_name || 'Unknown Task';
          var domain_name = task_object.domain_name || 'Unknown';
          var engine_name = task_object.engine_name || 'Unknown';
          var bg_color = 'bg-soft-info';
          var status_badge = '<span class="float-end badge bg-info">Running</span>';

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
            </div>
          `);
        }
      }
      else{
        $('#currently_running_tasks').html(`<div class="alert alert-info" role="alert">No tasks are currently running.</div>`);
      }

      if (tasks['completed'].length > 0){
        for (var task in tasks['completed']) {
          var task_object = tasks['completed'][task];
          var task_name = task_object.formatted_task_name || 'Unknown Task';
          var domain_name = task_object.domain_name || 'Unknown';
          var engine_name = task_object.engine_name || 'Unknown';
          var error_message = '';

          if (task_object.status == 0) {
            var bg_color = 'bg-soft-danger';
            var color = 'danger';
            var status_badge = '<span class="float-end badge bg-danger">Failed</span>';
            if (task_object.error_message) {
              error_message = `<small class="text-danger">${task_object.error_message}</small><br>`;
            }
          }
          else if (task_object.status == 2) {
            var bg_color = 'bg-soft-success';
            var color = 'success';
            var status_badge = '<span class="float-end badge bg-success">Completed</span>';
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
      if(reload){
        Snackbar.show({
          text: 'Scan Status Reloaded.',
          pos: 'top-right',
          actionTextColor: '#42A5F5',
          duration: 1500
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
