const vuln_datatable_columns = [
	{'data': 'id'},                    // Checkbox column
	{'data': 'source'},                // Source
	{'data': 'type'},                  // Type
	{'data': 'name'},                  // Title
	{'data': 'cvss_metrics'},          // CVSS Metrics
	{'data': 'tags'},                  // Tags
	{'data': 'hackerone_report_id'},   // Hackerone ID
	{'data': 'severity'},              // Severity
	{'data': 'cvss_score'},            // CVSS Score
	{'data': 'cve_ids'},               // CVE/CWE (first)
	{'data': 'cwe_ids'},               // CVE/CWE (second)
	{'data': 'http_url'},              // Vulnerable URL
	{'data': 'description'},           // Description
	{'data': 'references'},            // Reference
	{'data': 'discovered_date'},       // Discovered on
	{'data': 'open_status'},           // Status
	{'data': 'action', 'orderable': false, 'searchable': false}, // Action
	{'data': 'extracted_results'},     // Extracted Results
	{'data': 'curl_command'},          // CURL command
	{'data': 'matcher_name'}           // Matcher Name
];

const vuln_datatable_page_length = 50;
const vuln_datatable_length_menu = [[50, 100, 500, 1000, -1], [50, 100, 500, 1000, 'All']];


function vulnerability_datatable_col_visibility(table){
	if(!$('#vuln_source_checkbox').is(":checked")){
		table.column(get_datatable_col_index('source', vuln_datatable_columns)).visible(false);
	}
	if(!$('#vuln_severity_checkbox').is(":checked")){
		table.column(get_datatable_col_index('severity', vuln_datatable_columns)).visible(false);
	}
	if(!$('#vuln_vulnerable_url_checkbox').is(":checked")){
		table.column(get_datatable_col_index('http_url', vuln_datatable_columns)).visible(false);
	}
	if(!$('#vuln_status_checkbox').is(":checked")){
		table.column(get_datatable_col_index('open_status', vuln_datatable_columns)).visible(false);
	}
}
