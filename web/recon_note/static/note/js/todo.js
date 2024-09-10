function populateTodofunction(project=null){
  $('.input-search').on('keyup', function() {
    const rex = new RegExp($(this).val(), 'i');
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

    populateScanHistory(project);

  });
  const ps = new PerfectScrollbar('.todo-box-scroll', {
    suppressScrollX : true
  });

  const todoListScroll = new PerfectScrollbar('.todoList-sidebar-scroll', {
    suppressScrollX : true
  });

  const $btns = $('.list-actions').click((event) => {
    if (this.id === 'all-list') {
      const $el = $('.' + this.id).fadeIn();
      $('#ct > div').not($el).hide();
    } else {
      const $el = $('.' + this.id).fadeIn();
      $('#ct > div').not($el).hide();
    }
    $btns.removeClass('active');
    $(event.currentTarget).addClass('active');
  })

  checkCheckbox();
  importantDropdown();
  todoItem();
  deleteDropdown();

  $(".add-tsk").click(async function(){
    try {
      const $_task = document.getElementById('task').value;
      const $_taskDescriptionText = document.getElementById('taskdescription').value;
      const $_taskScanHistory = $("#scanHistoryIDropdown option:selected").text();
      const $_taskSubdomain = $("#subdomainDropdown option:selected").text();
      let $_targetText = '';

      if ($_taskScanHistory != 'Choose Scan History...') {
        $_targetText = $_taskScanHistory;
      }

      if ($_taskSubdomain != 'Choose Subdomain...') {
        $_targetText += ' Subdomain : ' + $_taskSubdomain;
      }

      let data = {
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

      let response = await fetch('/api/add/recon_note/', {
        method: 'post',
        headers: {
          "X-CSRFToken": getCookie("csrftoken"),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });

      const responseData = await response.json();
      swal.queue([{
        title: response.status === 200 ? 'Note added successfully!' : 
              response.status === 400 ? 'Oops! Unable to add todo!\r\n' + responseData.error : 
              response.status === 404 ? 'Oops! Note not found!\r\n' + responseData.error : 
              'Oops! An error occurred!\r\n' + responseData.error,
        icon: response.status === 200 ? 'success' : 'error'
      }]);

      if (response.status === 200) {
        const newNote = {
          id: responseData.id,
          title: htmlEncode($_task),
          description: htmlEncode($_taskDescriptionText),
          domain_name: htmlEncode($_targetText),
          subdomain_name: htmlEncode($_taskSubdomain),
          is_done: false
        };
      
        let todoHTML = $('#todo-template').html();
      
        todoHTML = todoHTML
          .replace(/{task_id}/g, newNote.id)
          .replace(/{title}/g, newNote.title)
          .replace(/{target_text}/g, newNote.domain_name ? `Domain: ${newNote.domain_name}` : '')
          .replace(/{description}/g, newNote.description)
          .replace(/{is_done}/g, newNote.is_done ? 'todo-task-done' : '')
          .replace(/{checked}/g, newNote.is_done ? 'checked' : '');
      
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
    } catch (error) {
      console.error('Error adding todo:', error);
      swal('Oops! Something went wrong!', error.message, 'error');
    }
  });
  $('.tab-title .nav-pills a.nav-link').on('click', function(event) {
    $(this).parents('.mail-box-container').find('.tab-title').removeClass('mail-menu-show')
    $(this).parents('.mail-box-container').find('.mail-overlay').removeClass('mail-overlay-show')
  })
}

function dynamicBadgeNotification(setTodoCategoryCount) {
  const todoCategoryCount = setTodoCategoryCount;

  // Get Parents Div(s)
  const get_TodoAllListParentsDiv = $('.todo-item.all-list').not('.todo-item-template');
  const get_TodoCompletedListParentsDiv = $('.todo-item.todo-task-done').not('.todo-item-template');
  const get_TodoImportantListParentsDiv = $('.todo-item.todo-task-important').not('.todo-item-template');

  // Get Parents Div(s) Counts
  const get_TodoListElementsCount = get_TodoAllListParentsDiv.length;
  const get_CompletedTaskElementsCount = get_TodoCompletedListParentsDiv.length;
  const get_ImportantTaskElementsCount = get_TodoImportantListParentsDiv.length;

  // Get Badge Div(s)
  const getBadgeTodoAllListDiv = $('#all-list .todo-badge');
  const getBadgeCompletedTaskListDiv = $('#todo-task-done .todo-badge');
  const getBadgeImportantTaskListDiv = $('#todo-task-important .todo-badge');

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
  $('.action-dropdown .dropdown-menu .delete.dropdown-item').click(async function() {
    const id = this.id.split('_')[1];
    const main_this = this;
    const result = await swal.queue([{
      title: 'Are you sure you want to delete this Recon Note?',
      text: "You won't be able to revert this!",
      icon: 'warning',
      showCancelButton: true,
      confirmButtonText: 'Delete',
      padding: '2em',
      showLoaderOnConfirm: true,
      preConfirm: async function() {
        const response = await fetch('/recon_note/delete_note', {
          method: 'POST',
          credentials: "same-origin",
          headers: {
            "X-CSRFToken": getCookie("csrftoken")
          },
          body: JSON.stringify({ 'id': parseInt(id) })
        }).catch(error => {
          swal('Network error', 'An error occurred while deleting the note.', 'error');
          throw error;
        });

        if (!response.ok) {
          const errorMessages = {
            400: 'Oops! Unable to delete todo!',
            404: 'Oops! Note not found!',
            200: 'Note deleted successfully!'
          };
          swal.insertQueueStep({
            icon: response.status === 200 ? 'success' : 'error',
            title: errorMessages[response.status] || 'An unknown error occurred.'
          });
          return;
        }

        const responseData = await response.json();
        swal.insertQueueStep({
          icon: response.status === 200 ? 'success' : 'error',
          title: response.status === 200 ? 'Note deleted successfully!' : 'Oops! An error occurred!\r\n' + responseData.error
        });

        if (response.status === 200) {
          const getTodoParent = $(main_this).parents('.todo-item');
          getTodoParent.remove();
          new dynamicBadgeNotification('allList');
          new dynamicBadgeNotification('completedList');
          new dynamicBadgeNotification('importantList');
        }
      }
    }]);
  });
}
function checkCheckbox() {
  $('.inbox-chkbox').click(async function() {
    if ($(this).is(":checked")) {
      $(this).parents('.todo-item').addClass('todo-task-done');
    } else if ($(this).is(":not(:checked)")) {
      $(this).parents('.todo-item').removeClass('todo-task-done');
    }
    new dynamicBadgeNotification('completedList');
    await fetch('/recon_note/flip_todo_status', {
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
  $('.important').click(async function() {
    badge_id = this.id.split('_')[1];
    if(!$(this).parents('.todo-item').hasClass('todo-task-important')){
      $(this).parents('.todo-item').addClass('todo-task-important');

      const is_important_badge = document.createElement("div");
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
    await fetch('/recon_note/flip_important_status', {
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
    const $_taskTitle = $(this).find('.todo-heading').text();
    const $_taskTarget = $(this).find('.target').text();
    const $todoDescription = $(this).find('.todo-text').text();

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
      const option = document.createElement('option');
      option.value = history_object['id'];
      option.innerHTML = history_object['domain']['name'] + ' - Scanned ' + moment.utc(history_object['start_scan_date']).fromNow();
      scan_history_select.appendChild(option);
    }
  });
}
