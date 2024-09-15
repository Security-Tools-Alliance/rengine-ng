"""
Views for the recon_note app.

This module contains the views for the recon_note app, which handles 
the management of todo notesand related operations.
"""
import json
import logging

from django.http import JsonResponse
from django.shortcuts import render

from recon_note.models import TodoNote

def list_note(request, slug):
    """
    list_note renders the list view for recon notes associated with a specific project. 
    It prepares the context for the template and returns the rendered HTML response.

    Args:
        request (HttpRequest): The HTTP request object containing metadata about the request.
        slug (str): The slug of the project for which the recon notes are being listed.

    Returns:
        HttpResponse: The rendered HTML response for the note list view.
    """
    context = {'recon_note_active': 'active'}
    return render(request, 'note/index.html', context)

def flip_todo_status(request):
    """
    flip_todo_status toggles the completion status of a todo note based on the provided request data. 
    It processes a POST request, validates the input, and updates the note's status, 
    returning a JSON response indicating the result.

    Args:
        request (HttpRequest): The HTTP request object containing the note ID and the request method.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation,
        along with the updated completion status if successful.

    Raises:
        JsonDecodeError: If the request body contains invalid JSON.
        Http404: If the specified todo note does not exist.
    """
    if request.method != "POST":
        return JsonResponse({'status': False, 'error': 'Invalid request method.'}, status=400)

    try:
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
    except json.JSONDecodeError as e:
        logging.error('JSON decode error: %s', e)
        return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)

    note_id = body.get('id')
    if note_id is None:
        return JsonResponse({'status': False, 'error': 'ID is required.'}, status=400)

    try:
        note = TodoNote.objects.get(id=note_id)
    except TodoNote.DoesNotExist:
        return JsonResponse({'status': False, 'error': 'Note not found.'}, status=404)

    note.is_done = not note.is_done
    note.save()
    return JsonResponse({'status': True, 'error': False, 'is_done': note.is_done}, status=200)

def flip_important_status(request):
    """
    flip_important_status toggles the importance status of a todo note based on the provided request data.
    It processes a POST request, validates the input, and updates the note's status,
    returning a JSON response indicating the result.

    Args:
        request (HttpRequest): The HTTP request object containing the note ID and the request method.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation,
        along with the updated importance status if successful.

    Raises:
        JsonDecodeError: If the request body contains invalid JSON.
        Http404: If the specified todo note does not exist.
    """
    if request.method != "POST":
        return JsonResponse({'status': False, 'error': 'Invalid request method.'}, status=400)

    try:
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
    except json.JSONDecodeError as e:
        logging.error('JSON decode error: %s', e)
        return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)

    note_id = body.get('id')
    if note_id is None:
        return JsonResponse({'status': False, 'error': 'ID is required.'}, status=400)

    try:
        note = TodoNote.objects.get(id=note_id)
    except TodoNote.DoesNotExist:
        return JsonResponse({'status': False, 'error': 'Note not found.'}, status=404)

    note.is_important = not note.is_important
    note.save()
    return JsonResponse({'status': True, 'error': False, 'is_important': note.is_important}, status=200)

def delete_note(request):
    """
    delete_note handles the deletion of a todo note based on the provided request data.
    It processes a POST request, validates the input, and removes the specified note,
    returning a JSON response indicating the result.

    Args:
        request (HttpRequest): The HTTP request object containing the note ID and the request method.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the deletion operation.

    Raises:
        JsonDecodeError: If the request body contains invalid JSON.
        Http404: If the specified todo note does not exist.
    """
    if request.method != "POST":
        return JsonResponse({'status': False, 'error': 'Invalid request method.'}, status=400)

    try:
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
    except json.JSONDecodeError as e:
        logging.error('JSON decode error: %s', e)
        return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)

    note_id = body.get('id')
    if note_id is None:
        return JsonResponse({'status': False, 'error': 'ID is required.'}, status=400)

    if not TodoNote.objects.filter(id=note_id).exists():
        return JsonResponse({'status': False, 'error': 'Note not found.'}, status=404)

    TodoNote.objects.filter(id=note_id).delete()
    return JsonResponse({'status': True, 'error': False, 'deleted': True}, status=200)
