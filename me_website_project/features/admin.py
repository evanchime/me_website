from django.contrib import admin
from .models import Post
from .models import Question
from .models import Choice

# Register your models here.
admin.site.register(Post)
admin.site.register(Question)
admin.site.register(Choice)
