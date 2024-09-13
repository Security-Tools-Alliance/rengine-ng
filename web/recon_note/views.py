import json

from django.http import JsonResponse
from django.shortcuts import render

from recon_note.models import TodoNote

def list_note(request, slug):
    if not slug:
        return JsonResponse({'status': False, 'error': 'Slug is required.'}, status=400)

    context = {'recon_note_active': 'active'}
    return render(request, 'note/index.html', context)

def flip_todo_status(request):
    if request.method == "POST":
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)

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

    return JsonResponse({'status': True})

def flip_important_status(request):
    if request.method == "POST":
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)

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

    return JsonResponse({'status': True})

def delete_note(request):
    if request.method == "POST":
        # Check if the ID is present in the request body
        note_id = request.POST.get('id')
        if note_id is None:
            return JsonResponse({'status': False, 'error': 'ID is required.'}, status=400)

        # Check if the note exists before attempting to delete it
        if not TodoNote.objects.filter(id=note_id).exists():
            return JsonResponse({'status': False, 'error': 'Note not found.'}, status=404)

        TodoNote.objects.filter(id=note_id).delete()

    return JsonResponse({'status': True})
