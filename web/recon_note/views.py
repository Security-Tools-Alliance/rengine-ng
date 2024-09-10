import json

from django.http import JsonResponse
from django.shortcuts import render

from recon_note.models import *
from startScan.models import *


def list_note(request, slug):
    context = {}
    context['recon_note_active'] = 'active'
    return render(request, 'note/index.html', context)

def flip_todo_status(request):
    if request.method == "POST":
        try:
            body_unicode = request.body.decode('utf-8')
            body = json.loads(body_unicode)
        except json.JSONDecodeError:
            return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)

        # Check if the ID is present in the request body
        note_id = body.get('id')
        if note_id is None:
            return JsonResponse({'status': False, 'error': 'ID is required.'}, status=400)

        # Check if the note exists before attempting to update its status
        try:
            note = TodoNote.objects.get(id=note_id)
        except TodoNote.DoesNotExist:
            return JsonResponse({'status': False, 'error': 'Note not found.'}, status=404)

        # Toggle the done status of the note
        note.is_done = not note.is_done
        note.save()
        return JsonResponse({'status': True, 'error': False, 'is_done': note.is_done}, status=200)

    return JsonResponse({'status': False, 'error': 'Invalid request method.'}, status=400)

def flip_important_status(request):
    if request.method == "POST":
        try:
            body_unicode = request.body.decode('utf-8')
            body = json.loads(body_unicode)
        except json.JSONDecodeError:
            return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)

        # Check if the ID is present in the request body
        note_id = body.get('id')
        if note_id is None:
            return JsonResponse({'status': False, 'error': 'ID is required.'}, status=400)

        # Check if the note exists before attempting to update its status
        try:
            note = TodoNote.objects.get(id=note_id)
        except TodoNote.DoesNotExist:
            return JsonResponse({'status': False, 'error': 'Note not found.'}, status=404)

        # Toggle the important status of the note
        note.is_important = not note.is_important
        note.save()
        return JsonResponse({'status': True, 'error': False, 'is_important': note.is_important}, status=200)

    return JsonResponse({'status': False, 'error': 'Invalid request method.'}, status=400)

def delete_note(request):
    if request.method == "POST":
        try:
            body_unicode = request.body.decode('utf-8')
            body = json.loads(body_unicode)
        except json.JSONDecodeError:
            return JsonResponse({'status': False, 'error': 'Invalid JSON.'}, status=400)

        # Check if the ID is present in the request body
        note_id = body.get('id')
        if note_id is None:
            return JsonResponse({'status': False, 'error': 'ID is required.'}, status=400)

        # Check if the note exists before attempting to delete it
        if not TodoNote.objects.filter(id=note_id).exists():
            return JsonResponse({'status': False, 'error': 'Note not found.'}, status=404)

        TodoNote.objects.filter(id=note_id).delete()
        return JsonResponse({'status': True, 'error': False, 'deleted': True}, status=200)

    return JsonResponse({'status': False, 'error': 'Invalid request method.'}, status=400)
