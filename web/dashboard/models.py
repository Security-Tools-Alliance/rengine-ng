from django.contrib.auth.models import User
from django.db import models
from rest_framework_api_key.models import AbstractAPIKey


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
    users = models.ManyToManyField(User, related_name="projects")

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


class UserAPIKey(AbstractAPIKey):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="api_keys")
    name = models.CharField(max_length=100, help_text="Name to identify this API key")
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def get_url_id(self):
        """Return a URL-safe integer ID for this API key."""
        return hash(self.id) % 2147483647  # Convert hash to positive 32-bit int

    class Meta:
        verbose_name = "User API Key"
        verbose_name_plural = "User API Keys"

    def __str__(self):
        return f"{self.user.username} - {self.name}"
