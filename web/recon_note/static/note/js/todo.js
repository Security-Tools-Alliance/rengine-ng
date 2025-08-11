const populateTodo = function(project=null){
  new PerfectScrollbar('.task-text', {
    wheelSpeed:.5,
    swipeEasing:!0,
    minScrollbarLength:40,
    maxScrollbarLength:300,
    suppressScrollX : true
  });
  new PerfectScrollbar('.todo-box-scroll', {
    suppressScrollX : true
  });

  new PerfectScrollbar('.todoList-sidebar-scroll', {
    suppressScrollX : true
  });

  addTaskPopupListener(project);
  addTaskBtnListener(project);
  actionsBtnListener();
  checkBtnListener();
  importantBtnListener();
  todoItemListener();
  deleteBtnListener();

  // Load search term from local storage if it exists
  const savedSearchTerm = localStorage.getItem('searchTerm');
  if (savedSearchTerm) {
    $('.input-search').val(savedSearchTerm); // Set the input value
    searchFunction();
  }
  updateBadgeCounts();
}

const actionsBtnListener = function(){
  const $btns = $('.list-actions').click((event) => {
      const selectedId = event.currentTarget.id;
      const $el = $('.' + selectedId);
      $('#ct > div').hide();
      $el.fadeIn();
      $btns.removeClass('active');
      $(event.currentTarget).addClass('active');
      
      // Apply search and filter when changing menu
      searchFunction();
  });
}

const addTaskBtnListener = function(project) {
  $('#addTask').on('click', function (event) {
    event.preventDefault();

    $('#task').val('');
    $('#taskdescription').val('');

    $('.add-tsk').show();
    $('.edit-tsk').hide();
    $('#addTaskModal').modal('show');
    const ps = new PerfectScrollbar('.todo-box-scroll', {
      suppressScrollX: true
    });

    populateScanHistory(project);

  });
}

const addTaskPopupListener = function(project) {
  $(".add-tsk").click(async function () {
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
      };

      if ($("#scanHistoryIDropdown").val() && $("#scanHistoryIDropdown").val() != 'Choose Scan History...') {
        data['scan_history_id'] = parseInt($("#scanHistoryIDropdown").val());
      }

      if ($("#subdomainDropdown").val() != 'Choose Subdomain...') {
        data['subdomain_id'] = parseInt($("#subdomainDropdown").val());
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
          is_done: false,
          is_important: false
        };

        let todoHTML = $('#todo-template').html();

        todoHTML = todoHTML
          .replace(/{task_id}/g, newNote.id)
          .replace(/{title}/g, newNote.title)
          .replace(/{target_text}/g, newNote.domain_name ? `Domain: ${newNote.domain_name}` : '')
          .replace(/{description}/g, newNote.description)
          .replace(/{is_done}/g, newNote.is_done ? 'todo-task-done' : '')
          .replace(/{checked}/g, newNote.is_done ? 'checked' : '')
          .replace(/{is_important}/g, newNote.is_important ? 'todo-task-important' : '');

        const $newTodo = $('<div class="todo-item all-list"></div>').append(todoHTML);

        $("#ct").prepend($newTodo);
        $('#addTaskModal').modal('hide');
        checkBtnListener();
        todoItemListener();
        importantBtnListener();
        deleteBtnListener();
        new dynamicBadgeNotification('allList');
        $(".list-actions#all-list").trigger('click');
      }
    } catch (error) {
      console.error('Error adding todo:', error);
      swal('Oops! Something went wrong!', error.message, 'error');
    }
  });
}

const dynamicBadgeNotification = function(setTodoCategoryCount) {
  const todoCategoryCount = setTodoCategoryCount;

  // Compter les éléments en se basant uniquement sur les classes CSS
  const get_TodoAllListParentsDiv = $('.todo-item').not('.todo-item-template');
  const get_TodoCompletedListParentsDiv = $('.todo-item.todo-task-done').not('.todo-item-template');
  const get_TodoImportantListParentsDiv = $('.todo-item.todo-task-important').not('.todo-item-template');

  // Obtenir les comptes
  const get_TodoListElementsCount = get_TodoAllListParentsDiv.length;
  const get_CompletedTaskElementsCount = get_TodoCompletedListParentsDiv.length;
  const get_ImportantTaskElementsCount = get_TodoImportantListParentsDiv.length;

  // Obtenir les éléments de badge
  const getBadgeTodoAllListDiv = $('#all-list .todo-badge');
  const getBadgeCompletedTaskListDiv = $('#todo-task-done .todo-badge');
  const getBadgeImportantTaskListDiv = $('#todo-task-important .todo-badge');

  // Fonction pour mettre à jour un badge
  const updateBadge = function(badgeElement, count) {
    if (count === 0) {
      badgeElement.text('');
    } else {
      badgeElement.text(count);
      if (count > 9) {
        badgeElement.css({
          padding: '2px 0px',
          height: '25px',
          width: '25px'
        });
      } else {
        badgeElement.removeAttr('style');
      }
    }
  };

  // Update badges based on the category
  if (todoCategoryCount === 'allList' || todoCategoryCount === undefined) {
    updateBadge(getBadgeTodoAllListDiv, get_TodoListElementsCount);
  }
  if (todoCategoryCount === 'completedList' || todoCategoryCount === undefined) {
    updateBadge(getBadgeCompletedTaskListDiv, get_CompletedTaskElementsCount);
  }
  if (todoCategoryCount === 'importantList' || todoCategoryCount === undefined) {
    updateBadge(getBadgeImportantTaskListDiv, get_ImportantTaskElementsCount);
  }
}

const deleteBtnListener = function() {
  $('.actions-btn .delete-btn').click(async function() {
    const id = this.id.split('_')[1];
    const main_this = this;
    await swal.queue([{
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
          $(main_this).parents('.todo-item').remove();
          updateBadgeCounts();
        }
      }
    }]);
  });
}
const checkBtnListener = function() {
  $('.actions-btn .done-btn').click(async function() {
    const todoItem = $(this).parents('.todo-item');
    todoItem.toggleClass('todo-task-done'); // Toggle the done class

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

const importantBtnListener = function() {
  $('.actions-btn .important-btn').click(async function() {
    badge_id = this.id.split('_')[1];
    if(!$(this).parents('.todo-item').hasClass('todo-task-important')){
      $(this).parents('.todo-item').addClass('todo-task-important');

      const is_important_badge = document.createElement("div");
      is_important_badge.classList.add("priority-dropdown");
      is_important_badge.classList.add("custom-dropdown-icon");
      is_important_badge.id = 'important-badge-' + this.id.split('_')[1];

      badge = `
          <div class="dropdown p-dropdown">
            <span class="text-danger bs-tooltip" title="Important to-do">
              <i class="fa fa-exclamation-circle"></i>
            </span>
          </div>`;

      is_important_badge.innerHTML = badge;

      $(this).parents('.todo-item').find('.todo-content').after(is_important_badge);
    }
    else if($(this).parents('.todo-item').hasClass('todo-task-important')){
      $(this).parents('.todo-item').removeClass('todo-task-important');
      $("#important-badge-"+badge_id).remove();
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

const todoItemListener = function() {
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

const populateScanHistory = function(project) {
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

// Function to update badge counts
const updateBadgeCounts = function() {
  new dynamicBadgeNotification('allList');
  new dynamicBadgeNotification('completedList');
  new dynamicBadgeNotification('importantList');
};

// Updated search function
const searchFunction = function() {
  const searchTerm = $('.input-search').val();
  const rex = new RegExp(searchTerm, 'i'); // Create a regex from the input
  $('.todo-box .todo-item').hide(); // Hide all items
  $('.todo-box .todo-item').filter(function() {
      return rex.test($(this).text()); // Show items that match the regex
  }).show();

  // Apply the current filter after search
  applyCurrentFilter();

  // Update badge counts after filtering
  updateBadgeCounts();
};

// Function to apply the current filter (To-do, Done, Important)
const applyCurrentFilter = function() {
  const currentFilter = $('.list-actions.active').attr('id');
  if (currentFilter === 'todo-task-done') {
      $('.todo-box .todo-item:visible').not('.todo-task-done').hide();
  } else if (currentFilter === 'todo-task-important') {
      $('.todo-box .todo-item:visible').not('.todo-task-important').hide();
  }
};

$(document).ready(function() {
  // Show or hide the clear button based on input
  const updateClearButtonVisibility = function() {
    const searchTerm = $('.input-search').val();
    $('#clear-search').toggle(searchTerm.length > 0); // Show the clear button if there's text
  };

  // Initial check to show the clear button if there's a saved search term
  const savedSearchTerm = localStorage.getItem('searchTerm');
  if (savedSearchTerm) {
    $('.input-search').val(savedSearchTerm); // Set the input value
    updateClearButtonVisibility(); // Update visibility based on the saved term
  }

  // Show or hide the clear button on input
  $('.input-search').on('input', function() {
    updateClearButtonVisibility();
  });

  // Clear the search input when the clear button is clicked
  $('#clear-search').on('click', function() {
    $('.input-search').val(''); // Clear the input
    $(this).hide(); // Hide the clear button
    localStorage.removeItem('searchTerm'); // Remove the search term from local storage
    searchFunction(); // Call the search function to refresh the list
  });

  // Attach search function to input
  $('.input-search').on('keyup', function() {
    const searchTerm = $(this).val();
    localStorage.setItem('searchTerm', searchTerm); // Save the search term to local storage
    searchFunction(); // Call the search function
  });
});
