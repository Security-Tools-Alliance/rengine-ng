const subdomain_datatable_columns = [
  {'data': 'id'},
  {'data': 'name'},
  {'data': 'endpoint_count'},
  {'data': 'vuln_count'},
  {'data': 'http_status'},
  {'data': 'page_title'},
  {'data': 'ip_addresses'},
  {'data': 'ip_addresses'},
  {'data': 'content_length', 'searchable': false},
  {'data': 'response_time'},
  {'data': 'technologies'},
  {'data': 'http_url'},
  {'data': 'cname'},
  {'data': 'is_interesting'},
  {'data': 'info_count'},
  {'data': 'low_count'},
  {'data': 'medium_count'},
  {'data': 'high_count'},
  {'data': 'critical_count'},
  {'data': 'todos_count'},
  {'data': 'is_important'},
  {'data': 'webserver'},
  {'data': 'content_type'},
  {'data': 'action', 'orderable': false, 'searchable': false, 'defaultContent': ''},
  {'data': 'directories_count'},
  {'data': 'subscan_count'},
  {'data': 'waf'},
  {'data': 'attack_surface'},
  {'data': 'verified'},
  {'data': 'sources'}
];

const subdomain_datatable_page_length = window.getRengineDatatablePageLength
  ? window.getRengineDatatablePageLength()
  : 30;
const subdomain_datatable_length_menu = window.getRengineDatatableLengthMenu
  ? window.getRengineDatatableLengthMenu()
  : [[30, 50, 100, 200, 500, 1000, -1], ["30", "50", "100", "200", "500", "1000", "All"]];

function subdomain_datatable_col_visibility(subdomain_datatables){
  
  // Centralized handler for column visibility toggling
  function setupColumnVisibilityToggle(checkboxSelector, columnName, storageKey) {
    // Set initial visibility based on checkbox state
    const isChecked = $(checkboxSelector).is(":checked");
    subdomain_datatables.column(get_datatable_col_index(columnName, subdomain_datatable_columns)).visible(isChecked);
    
    // Set up change handler
    $(checkboxSelector).change(function() {
      const visible = $(this).is(':checked');
      subdomain_datatables.column(get_datatable_col_index(columnName, subdomain_datatable_columns)).visible(visible);
      if (storageKey) {
        window.localStorage.setItem(storageKey, visible);
      }
    });
  }

  // Special handler for ports column (uses ip_addresses + 1)
  function setupPortsColumnToggle() {
    const isChecked = $('#sub_ports_filter_checkbox').is(":checked");
    subdomain_datatables.column(get_datatable_col_index('ip_addresses', subdomain_datatable_columns) + 1).visible(isChecked);
    
    $('input[name=sub_ports_filter_checkbox]').change(function() {
      const visible = $(this).is(':checked');
      subdomain_datatables.column(get_datatable_col_index('ip_addresses', subdomain_datatable_columns) + 1).visible(visible);
      window.localStorage.setItem('sub_ports_filter_checkbox', visible);
    });
  }

  // Set up all column visibility toggles
  setupColumnVisibilityToggle('input[name=sub_http_status_filter_checkbox]', 'http_status', 'sub_http_status_filter_checkbox');
  setupColumnVisibilityToggle('input[name=sub_page_title_filter_checkbox]', 'page_title', 'sub_page_title_filter_checkbox');
  setupColumnVisibilityToggle('input[name=sub_ip_filter_checkbox]', 'ip_addresses', 'sub_ip_filter_checkbox');
  setupColumnVisibilityToggle('input[name=sub_content_length_filter_checkbox]', 'content_length', 'sub_content_length_filter_checkbox');
  setupColumnVisibilityToggle('input[name=sub_response_time_filter_checkbox]', 'response_time', 'sub_response_time_filter_checkbox');
  
  // Handle ports column separately (special case)
  setupPortsColumnToggle();
}
