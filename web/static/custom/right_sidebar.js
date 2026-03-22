/**
 * Get scan name from scan object
 * @param {Object} scan_object - Scan object from API
 * @returns {string} Scan name for display
 */
function getScanName(scan_object) {
  return scan_object.display_runner_type + ': ' + scan_object.display_scan_name;
}

/**
 * Get target/domain display name from scan object (API may send domain.name or target.value).
 * @param {Object} scan_object - Scan object from API
 * @returns {string} Display name for the scan target
 */
function getScanTargetDisplayName(scan_object) {
  if (!scan_object) return '';
  const { domain, target } = scan_object;
  const fromDomain = domain && typeof domain.name !== 'undefined' ? domain.name : null;
  const fromTarget = target && typeof target.value !== 'undefined' ? target.value : null;
  return fromDomain || fromTarget || '';
}

function getScanStatusSidebar(endpoint_url, endpoint_stop_scan_url, endpoint_stop_activity_url, endpoint_scan_status_url, options) {
  // options: { project, reload, openBar }. Legacy: 5th arg can be project (string), 6th reload, 7th openBar.
  const opts = (options && typeof options === 'object' && !Array.isArray(options))
    ? options
    : { project: arguments[4], reload: arguments[5], openBar: arguments[6] };
  const finalEndpointUrl = endpoint_url || window.scanStatusApiUrls?.scanStatusUrl;
  const finalStopScanUrl = endpoint_stop_scan_url || window.scanStatusApiUrls?.stopScanUrl;
  const finalStopActivityUrl = endpoint_stop_activity_url || window.scanStatusApiUrls?.stopActivityUrl;

  if (!finalEndpointUrl || !finalStopScanUrl || !finalStopActivityUrl) {
    console.error('getScanStatusSidebar: API URLs are required. Please ensure URLs are passed from template.');
    return;
  }

  let finalProject = opts.project;
  if (!finalProject) {
    const projectElement = document.querySelector('[data-project-slug]');
    const slugFromDom = projectElement && projectElement.getAttribute('data-project-slug');
    if (slugFromDom) {
      finalProject = slugFromDom;
    } else {
      const {pathname} = window.location;
      const scanMatch = pathname.match(/\/scan\/([^\/]+)(?:\/|$)/);
      const targetMatch = pathname.match(/\/target\/([^\/]+)(?:\/|$)/);
      finalProject = (scanMatch && scanMatch[1]) || (targetMatch && targetMatch[1]) || null;
    }
  }

  if (!finalProject) {
    console.error('getScanStatusSidebar: Unable to determine project slug. Cannot load scan status.');
    return;
  }

  const finalReload = opts.reload !== undefined ? opts.reload : false;
  const shouldOpenBar = opts.openBar === true;

  // Only open the bar when explicitly requested (user clicked the scan activity link); not on initial page load.
  if (shouldOpenBar && document.body && !document.body.classList.contains('right-bar-enabled')) {
    document.body.classList.add('right-bar-enabled');
  }

  $.getJSON(finalEndpointUrl + '?project=' + finalProject, function(data) {
    const $bar = $('.right-bar[data-scan-sidebar="true"]');
    if (!$bar.length) {
      return;
    }
    if (!data || !data.scans || !data.tasks) {
      $bar.find('#currently_scanning').html('<div class="alert alert-warning" role="alert">Unable to load scan status.</div>');
      return;
    }
    const {scans, tasks} = data;

    // main scans
    $bar.find('#currently_scanning').empty();
    $bar.find('#completed').empty();
    $bar.find('#upcoming_scans').empty();

    // subtasks
    $bar.find('#currently_running_tasks').empty();
    $bar.find('#completed_tasks').empty();
    $bar.find('#upcoming_tasks').empty();
    $bar.find('#current_task_count').empty();

    try {
    if (scans.pending.length > 0){
      for (const scan_object of scans.pending) {
        const scan_name = getScanName(scan_object);
        $bar.find('#upcoming_scans').append(`
          <div class="alert alert-warning" role="alert">${htmlEncode(scan_name)} on ${htmlEncode(getScanTargetDisplayName(scan_object))}</div>
          `);
      }
    }
    else{
      $bar.find('#upcoming_scans').html('<div class="alert alert-info" role="alert">No upcoming Scans.</div>');
    }

    const scanningCount = scans.scanning.length;
    const runningTasksCount = tasks.running.length;
    const $topCounter = $('#current_scan_counter');
    const $topTaskCounter = $('#current_task_counter');
    const $topCountLabel = $('#current_scan_count');
    if ($topCounter.length) {
      $topCounter.text(scanningCount);
    }
    if ($topTaskCounter.length) {
      $topTaskCounter.text(runningTasksCount);
    }
    const $scanActivityBadge = $('#scan-activity-badge');
    if ($scanActivityBadge.length) {
      if (scanningCount + runningTasksCount > 0) {
        $scanActivityBadge.show();
      } else {
        $scanActivityBadge.hide();
      }
    }
    if ($topCountLabel.length) {
      $topCountLabel.text(scanningCount > 0 ? scanningCount + ' Scans Currently Running' : '');
    }
    const $scansTabCount = $('#scans-tab-count');
    const $tasksTabCount = $('#tasks-tab-count');
    if ($scansTabCount.length) {
      if (scanningCount > 0) {
        $scansTabCount.text(scanningCount).show();
      } else {
        $scansTabCount.hide();
      }
    }
    if ($tasksTabCount.length) {
      if (runningTasksCount > 0) {
        $tasksTabCount.text(runningTasksCount).show();
      } else {
        $tasksTabCount.hide();
      }
    }

    if (scans.scanning.length > 0){
      $bar.find('#current_scan_count').html(scans.scanning.length + ' Scans Currently Running');
      for (const scan_object of scans.scanning) {
        
        // Format current task display
        let currentTaskDisplay = '';
        if (scan_object.current_task) {
          currentTaskDisplay = `<br><small class="text-muted font-weight-bold">${scan_object.current_task}</small>`;
        }
        
        // Get scan name (legacy or Secator)
        const scan_name = getScanName(scan_object);
        
        $bar.find('#currently_scanning').append(`
          <div class="card border-primary border mini-card" id="scan-card-${scan_object.id}">
          <a href="/scan/${finalProject}/${scan_object.id}" class="text-reset item-hovered">
          <div class="card-header bg-soft-primary text-primary mini-card-header">
          ${htmlEncode(scan_name)} on ${typeof htmlEncode === 'function' ? htmlEncode(getScanTargetDisplayName(scan_object)) : getScanTargetDisplayName(scan_object)}
          <span class="badge badge-soft-primary float-end">
          ${typeof htmlEncode === 'function' ? htmlEncode(String(scan_object.current_progress)) : scan_object.current_progress}%
          </span>
          ${currentTaskDisplay}
          </div>
          <div class="card-body mini-card-body">
          <p class="card-text">
          <span class="badge badge-soft-primary float-end scan_status">
          Scanning
          </span>
          <span class="">
          Started ${typeof htmlEncode === 'function' ? htmlEncode(scan_object.elapsed_time) : scan_object.elapsed_time} ago.
          </span>
          </p>
          <div>
          <span class="badge-subdomain-count badge badge-pills bg-info mt-1" data-toggle="tooltip" data-placement="top" title="Subdomains">&nbsp;&nbsp;${scan_object.subdomain_count}&nbsp;&nbsp;</span>
          <span class="badge-ip-address-count badge badge-pills bg-info mt-1" data-toggle="tooltip" data-placement="top" title="IP addresses">&nbsp;&nbsp;${scan_object.ip_address_count}&nbsp;&nbsp;</span>
          <span class="badge-endpoint-count badge badge-pills bg-warning mt-1" data-toggle="tooltip" data-placement="top" title="Endpoints">&nbsp;&nbsp;${scan_object.endpoint_count}&nbsp;&nbsp;</span>
          <span class="badge-vuln-count badge badge-pills bg-danger mt-1" data-toggle="tooltip" data-placement="top" title="Vulnerabilities">&nbsp;&nbsp;${scan_object.vulnerability_count}&nbsp;&nbsp;</span>
          </div>
          <div class="progress mt-2 progress-4px">
          <div class="progress-bar progress-bar-striped progress-bar-animated bg-primary scan-progress-bar" role="progressbar" aria-valuenow="${typeof htmlEncode === 'function' ? htmlEncode(String(scan_object.current_progress)) : scan_object.current_progress}" aria-valuemin="0" aria-valuemax="100" style="width: ${typeof htmlEncode === 'function' ? htmlEncode(String(scan_object.current_progress)) : scan_object.current_progress}%"></div>
          </div>
          <a href="#" onclick="stop_scan('${finalStopScanUrl}', scan_id=${scan_object.id}, subscan_id=null, reload_scan_bar=true, reload_location=false)" class="btn btn-xs btn-soft-danger waves-effect waves-light mt-1 float-end"><i class="fe-alert-triangle"></i> Stop</a>
          </div>
          </a>
          </div>
          `);
        }
      }
      else{
        $bar.find('#currently_scanning').html('<div class="alert alert-info" role="alert">No Scans are currently running.</div>');
      }

      if (scans.completed.length > 0){
        for (const scan_object of scans.completed) {
          let bg_color;
          let color;
          let status_badge;
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
          else if (scan_object.scan_status == 2) {
            bg_color = 'bg-soft-success';
            color = 'success';
            status_badge = '<span class="float-end badge bg-success">Scan Completed</span>';
          }
          else {
            bg_color = 'bg-soft-secondary';
            color = 'secondary';
            status_badge = '<span class="float-end badge bg-secondary">Completed</span>';
          }

          // Get scan name (legacy or Secator)
          const completed_scan_name = getScanName(scan_object);
          
          $bar.find('#completed').append(`
            <div class="card border-${color} border mini-card" id="scan-card-${scan_object.id}">
            <a href="/scan/${finalProject}/${scan_object.id}" class="text-reset item-hovered float-end">
            <div class="card-header ${bg_color} text-${color} mini-card-header">
            ${htmlEncode(completed_scan_name)} on ${htmlEncode(getScanTargetDisplayName(scan_object))}
            </div>
            <div class="card-body mini-card-body">
            <p class="card-text">
            ${status_badge}
            <span class="">
            Scan Completed ${typeof htmlEncode === 'function' ? htmlEncode(scan_object.completed_ago) : scan_object.completed_ago} ago
            </span>
            <div>
            <span class="badge-subdomain-count badge badge-pills bg-info mt-1" data-toggle="tooltip" data-placement="top" title="Subdomains">&nbsp;&nbsp;${scan_object.subdomain_count}&nbsp;&nbsp;</span>
            <span class="badge-ip-address-count badge badge-pills bg-info mt-1" data-toggle="tooltip" data-placement="top" title="IP addresses">&nbsp;&nbsp;${scan_object.ip_address_count}&nbsp;&nbsp;</span>
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
      else {
        $bar.find('#completed').html('<div class="alert alert-info" role="alert">No scans have been recently completed.</div>');
      }


      // tasks

      if (tasks.running.length > 0) {
        $bar.find('#current_task_count').html(tasks.running.length + ' Tasks are currently running');
        for (let task in tasks.running) {
          const task_object = tasks['running'][task];
          const task_name = task_object.formatted_task_name || 'Unknown Task';
          const domain_name = task_object.domain_name || 'Unknown';
          const engine_name = task_object.engine_name || 'Unknown';

          $bar.find('#currently_running_tasks').append(`
            <div class="card border-primary border mini-card" data-activity-id="${task_object.id}">
            <a href="/scan/${finalProject}/${task_object.scan_id}" class="text-reset item-hovered">
            <div class="card-header bg-soft-primary text-primary mini-card-header">
            ${htmlEncode(task_name)} on <b>${htmlEncode(domain_name)}</b> using engine <b>${htmlEncode(engine_name)}</b>
            </div>
            <div class="card-body mini-card-body">
            <p class="card-text">
            <span class="badge badge-soft-primary float-end scan_status">
            In Progress
            </span>
            <span class="">
            Running Since ${typeof htmlEncode === 'function' ? htmlEncode(task_object.elapsed_time) : task_object.elapsed_time} ago.
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
        $bar.find('#currently_running_tasks').html('<div class="alert alert-info" role="alert">No tasks are currently running.</div>');
      }

    const $stopAllScansBtn = $('#stop-all-scans-btn');
    const $stopAllTasksBtn = $('#stop-all-tasks-btn');
    if ($stopAllScansBtn.length) {
      $stopAllScansBtn.toggle(scanningCount > 0);
    }
    if ($stopAllTasksBtn.length) {
      $stopAllTasksBtn.toggle(runningTasksCount > 0);
    }

      if (tasks.completed.length > 0){
        for (let task in tasks.completed) {
          const task_object = tasks.completed[task];
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
              error_message = `<small class="text-danger">${htmlEncode(task_object.error_message)}</small><br>`;
            }
          }
          else if (task_object.status == 2) {
            bg_color = 'bg-soft-success';
            color = 'success';
            status_badge = '<span class="float-end badge bg-success">Completed</span>';
          }
          else {
            bg_color = 'bg-soft-secondary';
            color = 'secondary';
            status_badge = '<span class="float-end badge bg-secondary">Done</span>';
          }

          $bar.find('#completed_tasks').append(`
            <div class="card border-${color} border mini-card">
            <a href="/scan/${finalProject}/${task_object.scan_id}" class="text-reset item-hovered">
            <div class="card-header ${bg_color} text-${color} mini-card-header">
            ${htmlEncode(task_name)} on <b>${htmlEncode(domain_name)}</b>
            </div>
            <div class="card-body mini-card-body">
            <p class="card-text">
            ${status_badge}
            ${error_message}
            <span class="">
            Completed ${typeof htmlEncode === 'function' ? htmlEncode(task_object.elapsed_time) : task_object.elapsed_time} ago
            </span>
            </p>
            </div>
            </a>
            </div>
          `);
        }
      }
      else{
        $bar.find('#completed_tasks').html('<div class="alert alert-info" role="alert">No tasks have been recently completed.</div>');
      }

      if (tasks.pending.length > 0){
        for (const task_object of tasks.pending) {
          const task_name = task_object.formatted_task_name || 'Unknown Task';
          $bar.find('#upcoming_tasks').append('<div class="alert alert-warning" role="alert">' + htmlEncode(task_name) + ' on ' + htmlEncode(task_object.subdomain_name || '') + '</div>');
        }
      }
      else{
        $bar.find('#upcoming_tasks').html('<div class="alert alert-info" role="alert">No upcoming tasks.</div>');
      }

    } catch (e) {
      console.error('getScanStatusSidebar: Error rendering scan status', e);
      $bar.find('#currently_scanning').html('<div class="alert alert-warning" role="alert">Error loading scan status.</div>');
    }
    }).done(function() {
      const $sidebar = $('.right-bar[data-scan-sidebar="true"]');
      if ($sidebar.length && typeof tippy === 'function') {
        tippy($sidebar[0].querySelectorAll('.scan_status'), { content: 'Scan Status' });
        tippy($sidebar[0].querySelectorAll('.badge-subdomain-count'), { content: 'Subdomains' });
        tippy($sidebar[0].querySelectorAll('.badge-endpoint-count'), { content: 'Endpoints' });
        tippy($sidebar[0].querySelectorAll('.badge-vuln-count'), { content: 'Vulnerabilities' });
        tippy($sidebar[0].querySelectorAll('.badge-scan_engine-type'), { content: 'Scan Engine' });
      }
      if (finalReload) {
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

/**
 * Move scan sidebar and overlay to body so position:fixed is relative to viewport (not a transformed ancestor).
 */
function ensureRightBarInBody() {
  const overlay = document.querySelector('.rightbar-overlay');
  const bar = document.querySelector('.right-bar[data-scan-sidebar="true"]');
  if (overlay && overlay.parentNode !== document.body) {
    document.body.appendChild(overlay);
  }
  if (bar && bar.parentNode !== document.body) {
    document.body.appendChild(bar);
  }
}

/**
 * Ensure the scan activity bar opens on click on all pages (including those with heavy page_level_script).
 * Use capture phase so this runs before the theme's body click handler, which would remove right-bar-enabled.
 */
(function () {
  const handleScanActivityBarClick = function (e) {
    const target = e.target && (e.target.closest ? e.target.closest('.scan-activity-bar-toggle') : null);
    if (!target) return;
    e.preventDefault();
    e.stopPropagation();
    document.body.classList.add('right-bar-enabled');
    if (typeof getScanStatusSidebar === 'function') {
      getScanStatusSidebar(null, null, null, null, { openBar: true });
    }
  };
  document.addEventListener('click', handleScanActivityBarClick, true);
  const initRightBarPosition = function () {
    ensureRightBarInBody();
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initRightBarPosition);
  } else {
    initRightBarPosition();
  }
  window.addEventListener('load', initRightBarPosition);
})();
