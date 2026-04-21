function todoCheckboxListener(){
  $('.detail-scan-todo-item').click(function() {
    const note_id = parseInt(this.id.split('_')[1], 10);
    console.log(note_id);
    if ($(this).is(":checked")) {
      $("#todo_parent_"+note_id).addClass('text-strike');
    } else {
      $("#todo_parent_"+note_id).removeClass('text-strike');
    }
    fetch('../../recon_note/flip_todo_status', {
      method: 'post',
      headers: {
        "X-CSRFToken": getCookie("csrftoken")
      },
      body: JSON.stringify({
        'id': note_id,
      })
    }).then(res => res.json())
    .then(res => console.log(res));
  });
}

function delete_todo(todo_id){
  scan_id = parseInt(document.getElementById('summary_identifier_val').value);
  swal.queue([{
    title: 'Are you sure you want to delete this Recon To-do?',
    text: "You won't be able to revert this!",
    type: 'warning',
    showCancelButton: true,
    confirmButtonText: 'Delete',
    padding: '2em',
    showLoaderOnConfirm: true,
    preConfirm: function() {
      return fetch('../../recon_note/delete_note', {
        method: 'POST',
        credentials: "same-origin",
        headers: {
          "X-CSRFToken": getCookie("csrftoken")
        },
        body: JSON.stringify({
          'id': parseInt(todo_id),
        })
      })
      .then(function (response) {
        Snackbar.show({
          text: 'Recon To-do Deleted.',
          pos: 'top-right',
          duration: 1500,
        });
        get_recon_notes(null, scan_id);
      })
      .catch(function() {
        swal.insertQueueStep({
          type: 'error',
          title: 'Oops! Unable to delete todo!'
        })
      })
    }
  }]);
}

function change_todo_priority(todo_id, imp_type){
  if (imp_type == 0) {
    snackbar_text = 'To-do Marked as Unimportant';
  }
  else if (imp_type == 1) {
    snackbar_text = 'To-do Marked as Important';
  }
  scan_id = parseInt(document.getElementById('summary_identifier_val').value);
  fetch('../../recon_note/flip_important_status', {
    method: 'post',
    headers: {
      "X-CSRFToken": getCookie("csrftoken")
    },
    body: JSON.stringify({
      'id': todo_id,
    })
  }).then(function (response) {
    $(".tooltip").tooltip("hide");
    Snackbar.show({
      text: snackbar_text,
      pos: 'top-right',
      duration: 1500,
    });
    get_recon_notes(null, scan_id);
  });
}


function list_subdomain_todos(subdomain_id, subdomain_name){
  const safeName = typeof htmlEncode === 'function' ? htmlEncode(subdomain_name) : subdomain_name;
  const titleHtml = 'Todos for subdomain ' + safeName;
  const loaderHtml = '<div class="outer-div" id="modal-loader"><span class="inner-div spinner-border text-info align-self-center loader-sm"></span></div>';
  if (window.ModalManager) {
    ModalManager.showDialog({ title: titleHtml, bodyHtml: loaderHtml, footerHtml: '' });
  } else {
    $('#modal-dialog-title').html(titleHtml);
    $('#modal-dialog-body').html(loaderHtml);
    $('#modal-dialog-footer').empty();
    $('#modal-dialog').modal('show');
  }
  $.getJSON(`/api/listTodoNotes/?subdomain_id=${subdomain_id}&format=json`, function(data) {
    const importantBadgeSvg = '<span class="text-danger bs-tooltip" title="Important Task"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-alert-octagon"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12" y2="16"></line></svg></span>';
    const notes = data['notes'] || [];
    let listItems = '';
    for (let i = 0; i < notes.length; i++) {
      const todo_obj = notes[i];
      const important_badge = todo_obj['is_important'] ? importantBadgeSvg : '';
      const is_done = todo_obj['is_done'] ? 'text-strike' : '';
      listItems += '<li class="' + is_done + '">' + important_badge + '<b>&nbsp;' + htmlEncode(todo_obj['title']) + '</b><br />' + htmlEncode(todo_obj['description']) + '</li>';
    }
    $('#modal-dialog-body').html('<ul id="todo-modal-content-ul">' + listItems + '</ul>');
    $('.bs-tooltip').tooltip();
  }).fail(function(){
    $('#modal-dialog-body').html('');
  });
}

function get_task_details(todo_id) {
  const loaderHtml = '<div class="outer-div" id="modal-loader"><span class="inner-div spinner-border text-info align-self-center loader-sm"></span></div>';
  if (window.ModalManager) ModalManager.showDialog({ title: '', bodyHtml: loaderHtml, footerHtml: '' });
  const baseUrl = (window.RENGINE_API_URLS && window.RENGINE_API_URLS.listTodoNotes) || '/api/listTodoNotes/';
  const url = `${baseUrl}?todo_id=${todo_id}&format=json`;
  $.getJSON(url, function (data) {
    const notes = data.notes || [];
    const note = notes[0];
    if (!note) {
      if (window.ModalManager) ModalManager.setDialogLoading('<p class="text-muted">No note found.</p>');
      return;
    }
    const subdomain_name = note.subdomain_name ? `<small class="text-success"> Subdomain: ${htmlEncode(note.subdomain_name)}</small><br />` : '';
    const title = `<b>${htmlEncode(note.title)}</b>`;
    const bodyHtml = `<p>${subdomain_name}${htmlEncode(note.description)}</p>`;
    if (window.ModalManager) {
      ModalManager.setDialogTitle(title);
      ModalManager.setDialogLoading(bodyHtml);
    }
  }).fail(function () {
    if (window.ModalManager) ModalManager.setDialogLoading('<p class="text-danger">Error loading task details.</p>');
  });
}

function get_recon_notes(endpoint, target_id, scan_id){
  let url = `${endpoint}?`;

  if (target_id) {
    url += `target_id=${target_id}`;
  }
  else if (scan_id) {
    url += `scan_id=${scan_id}`;
  }

  url += `&format=json`;

  // <li class="list-group-item border-0 ps-0"><div class="form-check"><input type="checkbox" class="form-check-input todo-done" id="8"><label class="form-check-label" for="8">dd</label></div></li>
  $.getJSON(url, function(data) {
    $('#tasks-count').empty();
    $('#todo-list').empty();
    if (data['notes'].length > 0){
      $('#todo-list').append(`<li class="list-group-item border-0 ps-0" id="todo_list_${target_id}"></li>`);
      for (const val in data['notes']){
        const note = data['notes'][val];
        const div_id = 'todo_' + note['id'];
        let subdomain_name = '';
        if (note['subdomain_name']) {
          subdomain_name = '<small class="text-success"> Subdomain: ' + note['subdomain_name'] + '</small></br>';
        }
        let strike_tag = 'span';
        let checked = '';
        if (note['is_done']) {
          strike_tag = 'del';
          checked = 'checked';
        }
        let important_badge = '';
        let mark_important = '';
        if (note['is_important']) {
          important_badge = `<i class="fe-alert-triangle text-danger me-1"></i>&nbsp;`;
          mark_important = `<a class="dropdown-item" onclick="change_todo_priority(${note['id']}, 0)">Mark UnImportant</a>`;
        }
        else{
          mark_important = `<a class="dropdown-item" onclick="change_todo_priority(${note['id']}, 1)">Mark Important</a>`;
        }
        $(`#todo_list_${target_id}`).append(`<div id="todo_parent_${note['id']}">
        <div class="d-flex align-items-start">
        <div class="w-100" onclick="get_task_details(${note['id']})">
        <input type="checkbox" class="me-1 form-check-input todo-done todo-item detail-scan-todo-item" ${checked} name="${div_id}" id="${div_id}">
        <label for="${div_id}" class="form-check-label">${important_badge}<${strike_tag}>${htmlEncode(note['title'])}</${strike_tag}></label>
        <${strike_tag}><p>${subdomain_name} <small>${truncate(htmlEncode(note['description']), 150)}</small></p></${strike_tag}>
        </div>
        <div class="btn-group dropstart float-end">
        <a href="#" class="text-dark dropdown-toggle float-start" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
        <i class="fe-more-vertical"></i>
        </a>
        <div class="dropdown-menu" style="">
        ${mark_important}
        <a class="dropdown-item" onclick="delete_todo(${note['id']})">Delete to-do</a>
        </div>
        </div>
        </div>
        <hr/>
        `);
      }
      const displayCount = data['total_count'] !== undefined ? data['total_count'] : data['notes'].length;
      $('#tasks-count').html(`<span class="badge badge-soft-primary">${displayCount}</span>`);
    }
    else{
      const displayCount = data['total_count'] !== undefined ? data['total_count'] : 0;
      $('#tasks-count').html(`<span class="badge badge-soft-primary me-1">${displayCount}</span>`);
      $('#todo-list').append(`<p>No todos or notes...</br>You can add todo for individual subdomains or you can also add using + symbol above.</p>`);
    }
    $('.bs-tooltip').tooltip();
    todoCheckboxListener();
  });
}
