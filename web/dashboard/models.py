from django.db import models
from django.contrib.auth.models import User

class SearchHistory(models.Model):
	query = models.CharField(max_length=1000)

	def __str__(self):
		return self.query


class Project(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	description = models.TextField(blank=True, null=True)
	slug = models.SlugField(unique=True)
	insert_date = models.DateTimeField()
	users = models.ManyToManyField(User, related_name='projects')

	def __str__(self):
		return self.slug

	def is_user_authorized(self, user):
		return user.is_superuser or self.users.filter(id=user.id).exists()
	
	@classmethod
	def get_from_slug(cls, slug):
		return cls.objects.get(slug=slug)


class OpenAiAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key
	

class OllamaSettings(models.Model):
	id = models.AutoField(primary_key=True)
	selected_model = models.CharField(max_length=500)
	use_ollama = models.BooleanField(default=True)

	def __str__(self):
		return self.selected_model


class NetlasAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key