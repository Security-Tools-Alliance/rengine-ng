
function populateTodofunction(project=null){
  $('.input-search').on('keyup', function() {
    var rex = new RegExp($(this).val(), 'i');
    $('.todo-box .todo-item').hide();
    $('.todo-box .todo-item').filter(function() {
      return rex.test($(this).text());
    }).show();
  });

  const taskViewScroll = new PerfectScrollbar('.task-text', {
    wheelSpeed:.5,
    swipeEasing:!0,
    minScrollbarLength:40,
    maxScrollbarLength:300,
    suppressScrollX : true
  });

  new dynamicBadgeNotification('allList');
  new dynamicBadgeNotification('completedList');
  new dynamicBadgeNotification('importantList');

  $('.mail-menu').on('click', function(event) {
    $('.tab-title').addClass('mail-menu-show');
    $('.mail-overlay').addClass('mail-overlay-show');
  })
  $('.mail-overlay').on('click', function(event) {
    $('.tab-title').removeClass('mail-menu-show');
    $('.mail-overlay').removeClass('mail-overlay-show');
  })
  $('#addTask').on('click', function(event) {
    event.preventDefault();

    $('#task').val('');
    $('#taskdescription').val('');

    $('.add-tsk').show();
    $('.edit-tsk').hide();
    $('#addTaskModal').modal('show');
    const ps = new PerfectScrollbar('.todo-box-scroll', {
      suppressScrollX : true
    });

    populateScanHistory(project=project);

  });
  const ps = new PerfectScrollbar('.todo-box-scroll', {
    suppressScrollX : true
  });

  const todoListScroll = new PerfectScrollbar('.todoList-sidebar-scroll', {
    suppressScrollX : true
  });

  var $btns = $('.list-actions').click(function() {
    if (this.id == 'all-list') {
      var $el = $('.' + this.id).fadeIn();
      $('#ct > div').not($el).hide();
    } else {
      var $el = $('.' + this.id).fadeIn();
      $('#ct > div').not($el).hide();
    }
    $btns.removeClass('active');
    $(this).addClass('active');
  })

  checkCheckbox();
  importantDropdown();
  todoItem();
  deleteDropdown();

  $(".add-tsk").click(function(){

    var $_task = document.getElementById('task').value;

    var $_taskDescriptionText = document.getElementById('taskdescription').value;

    var $_taskScanHistory = $("#scanHistoryIDropdown option:selected").text();

    var $_taskSubdomain = $("#subdomainDropdown option:selected").text();

    var $_targetText = '';

    if ($_taskScanHistory != 'Choose Scan History...') {
      $_targetText = $_taskScanHistory;
    }

    if ($_taskSubdomain != 'Choose Subdomain...') {
      $_targetText += ' Subdomain : ' + $_taskSubdomain;
    }

    data = {
      'title': $_task,
      'description': $_taskDescriptionText
    }

    if ($("#scanHistoryIDropdown").val() && $("#scanHistoryIDropdown").val() != 'Choose Scan History...') {
      data['scan_history'] = parseInt($("#scanHistoryIDropdown").val());
    }

    if ($("#subdomainDropdown").val() != 'Choose Subdomain...') {
      data['subdomain'] = parseInt($("#subdomainDropdown").val());
    }

    if (project) {
      data['project'] = project;
    }

    fetch('/api/add/recon_note/', {
      method: 'post',
      headers: {
        "X-CSRFToken": getCookie("csrftoken"),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    }).then(function (response) {
      return response.json().then(function(data) {
        swal.queue([{
          title: response.status === 200 ? 'Note added successfully!' : 
                response.status === 400 ? 'Oops! Unable to add todo!\r\n' + data.error : 
                response.status === 404 ? 'Oops! Note not found!\r\n' + data.error : 
                'Oops! An error occurred!\r\n' + data.error,
          icon: response.status === 200 ? 'success' : 'error'
        }]);

        if (response.status === 200) {
          const newNote = {
            id: data.id,
            title: $_task,
            description: $_taskDescriptionText,
            domain_name: $_targetText,
            subdomain_name: $_taskSubdomain,
            is_done: false
          };
        
          let todoHTML = $('#todo-template').html();
        
          todoHTML = todoHTML
            .replace(/{task_id}/g, newNote.id)
            .replace(/{title}/g, htmlEncode(newNote.title))
            .replace(/{target_text}/g, newNote.domain_name ? `Domain: ${newNote.domain_name}` : '')
            .replace(/{description}/g, htmlEncode(newNote.description))
            .replace(/{is_done}/g, newNote.is_done ? 'todo-task-done' : '')
            .replace(/{checked}/g, newNote.is_done ? 'checked' : '');
        
          // Créer un nouvel élément avec la classe todo-item
          const $newTodo = $('<div class="todo-item all-list"></div>').append(todoHTML);
        
          $("#ct").prepend($newTodo);
          $('#addTaskModal').modal('hide');
          checkCheckbox();
          todoItem();
          importantDropdown();
          deleteDropdown();
          new dynamicBadgeNotification('allList');
          $(".list-actions#all-list").trigger('click');
        }
      });
    });
  });
  $('.tab-title .nav-pills a.nav-link').on('click', function(event) {
    $(this).parents('.mail-box-container').find('.tab-title').removeClass('mail-menu-show')
    $(this).parents('.mail-box-container').find('.mail-overlay').removeClass('mail-overlay-show')
  })
}

function dynamicBadgeNotification(setTodoCategoryCount) {
  var todoCategoryCount = setTodoCategoryCount;

  // Get Parents Div(s)
  var get_TodoAllListParentsDiv = $('.todo-item.all-list').not('.todo-item-template'); // Ignorer le modèle
  var get_TodoCompletedListParentsDiv = $('.todo-item.todo-task-done').not('.todo-item-template'); // Ignorer le modèle
  var get_TodoImportantListParentsDiv = $('.todo-item.todo-task-important').not('.todo-item-template'); // Ignorer le modèle

  // Get Parents Div(s) Counts
  var get_TodoListElementsCount = get_TodoAllListParentsDiv.length;
  var get_CompletedTaskElementsCount = get_TodoCompletedListParentsDiv.length;
  var get_ImportantTaskElementsCount = get_TodoImportantListParentsDiv.length;

  // Get Badge Div(s)
  var getBadgeTodoAllListDiv = $('#all-list .todo-badge');
  var getBadgeCompletedTaskListDiv = $('#todo-task-done .todo-badge');
  var getBadgeImportantTaskListDiv = $('#todo-task-important .todo-badge');

  if (todoCategoryCount === 'allList') {
    if (get_TodoListElementsCount === 0) {
      getBadgeTodoAllListDiv.text('');
      return;
    }
    if (get_TodoListElementsCount > 9) {
      getBadgeTodoAllListDiv.css({
        padding: '2px 0px',
        height: '25px',
        width: '25px'
      });
    } else if (get_TodoListElementsCount <= 9) {
      getBadgeTodoAllListDiv.removeAttr('style');
    }
    getBadgeTodoAllListDiv.text(get_TodoListElementsCount);
  }
  else if (todoCategoryCount === 'completedList') {
    if (get_CompletedTaskElementsCount === 0) {
      getBadgeCompletedTaskListDiv.text('');
      return;
    }
    if (get_CompletedTaskElementsCount > 9) {
      getBadgeCompletedTaskListDiv.css({
        padding: '2px 0px',
        height: '25px',
        width: '25px'
      });
    } else if (get_CompletedTaskElementsCount <= 9) {
      getBadgeCompletedTaskListDiv.removeAttr('style');
    }
    getBadgeCompletedTaskListDiv.text(get_CompletedTaskElementsCount);
  }
  else if (todoCategoryCount === 'importantList') {
    if (get_ImportantTaskElementsCount === 0) {
      getBadgeImportantTaskListDiv.text('');
      return;
    }
    if (get_ImportantTaskElementsCount > 9) {
      getBadgeImportantTaskListDiv.css({
        padding: '2px 0px',
        height: '25px',
        width: '25px'
      });
    } else if (get_ImportantTaskElementsCount <= 9) {
      getBadgeImportantTaskListDiv.removeAttr('style');
    }
    getBadgeImportantTaskListDiv.text(get_ImportantTaskElementsCount);
  }
}

function deleteDropdown() {
  $('.action-dropdown .dropdown-menu .delete.dropdown-item').click(function() {
    var id = this.id.split('_')[1];
    var main_this = this;
    swal.queue([{
      title: 'Are you sure you want to delete this Recon Note?',
      text: "You won't be able to revert this!",
      icon: 'warning',
      showCancelButton: true,
      confirmButtonText: 'Delete',
      padding: '2em',
      showLoaderOnConfirm: true,
      preConfirm: function() {
        return fetch('/recon_note/delete_note', {
          method: 'POST',
          credentials: "same-origin",
          headers: {
            "X-CSRFToken": getCookie("csrftoken")
          },
          body: JSON.stringify({ 'id': parseInt(id) })
        })
        .then(function (response) {
          const errorMessages = {
            400: 'Oops! Unable to delete todo!',
            404: 'Oops! Note not found!',
            200: 'Note deleted successfully!'
          };

          if (response.status in errorMessages) {
            swal.insertQueueStep({
              icon: response.status === 200 ? 'success' : 'error',
              title: errorMessages[response.status]
            });

            if (response.status === 200) {
              const getTodoParent = $(main_this).parents('.todo-item');
              getTodoParent.remove();
              new dynamicBadgeNotification('allList');
              new dynamicBadgeNotification('completedList');
              new dynamicBadgeNotification('importantList');
            }
          }
        })
        .catch(function() {
          swal.insertQueueStep({
            type: 'error',
            title: 'Oops! Unable to delete todo!'
          });
        });
      }
    }]);
  });
}
function checkCheckbox() {
  $('.inbox-chkbox').click(function() {
    if ($(this).is(":checked")) {
      $(this).parents('.todo-item').addClass('todo-task-done');
    }
    else if ($(this).is(":not(:checked)")) {
      $(this).parents('.todo-item').removeClass('todo-task-done');
    }
    new dynamicBadgeNotification('completedList');
    fetch('/recon_note/flip_todo_status', {
      method: 'post',
      headers: {
        "X-CSRFToken": getCookie("csrftoken")
      },
      body: JSON.stringify({
        'id': parseInt(this.id.split('_')[1]),
      })
    }).then(res => res.json());
  });
}

function importantDropdown() {
  $('.important').click(function() {
    badge_id = this.id.split('_')[1];
    if(!$(this).parents('.todo-item').hasClass('todo-task-important')){
      $(this).parents('.todo-item').addClass('todo-task-important');

      var is_important_badge = document.createElement("div");
      is_important_badge.classList.add("priority-dropdown");
      is_important_badge.classList.add("custom-dropdown-icon");
      is_important_badge.id = 'important-badge-' + this.id.split('_')[1];

      badge = `
      <div class="dropdown p-dropdown">
      <span class="text-danger bs-tooltip" title="Important Task">
      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-alert-octagon"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12" y2="16"></line></svg>
      </span>
      </div>`

      is_important_badge.innerHTML = badge;

      $(this).parents('.todo-item').find('.todo-content').after(is_important_badge);
    }
    else if($(this).parents('.todo-item').hasClass('todo-task-important')){
      $(this).parents('.todo-item').removeClass('todo-task-important');
      $(".list-actions#all-list").trigger('click');
      $("#important-badge-"+badge_id).empty();
    }
    new dynamicBadgeNotification('importantList');
    fetch('/recon_note/flip_important_status', {
      method: 'post',
      headers: {
        "X-CSRFToken": getCookie("csrftoken")
      },
      body: JSON.stringify({
        'id': parseInt(this.id.split('_')[1]),
      })
    }).then(res => res.json());
  });
}

function todoItem() {
  $('.todo-item .todo-content').on('click', function(event) {
    event.preventDefault();

    var $_taskTitle = $(this).find('.todo-heading').text();

    var $_taskTarget = $(this).find('.target').text();

    var $todoDescription = $(this).find('.todo-text').text();

    $('.task-heading').text($_taskTitle);
    $('.task-text').html(`<span class="text-success">${$_taskTarget}</span><br>` + htmlEncode($todoDescription));

    $('#todoShowListItem').modal('show');
  });
}

function populateScanHistory(project) {
  scan_history_select = document.getElementById('scanHistoryIDropdown');
  $.getJSON(`/api/listScanHistory/?format=json&project=${project}`, function(data) {
    for (var history in data){
      history_object = data[history];
      var option = document.createElement('option');
      option.value = history_object['id'];
      option.innerHTML = history_object['domain']['name'] + ' - Scanned ' + moment.utc(history_object['start_scan_date']).fromNow();
      scan_history_select.appendChild(option);
    }
  });
}
