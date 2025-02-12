from django.db import models

# Create your models here.
class Post(models.Model):
    # Default behaviour - Django creates primary keys for you
    title = models.CharField(max_length=140)
    body = models.TextField()
    # author = models.CharField(max_length=140)
    signature = models.CharField(max_length=140, default="Evan")
    date = models.DateTimeField()

    def __str__(self):
        return self.title
    

class Question(models.Model):
    question_text = models.CharField(max_length=200)
    pub_date = models.DateTimeField('date published')

    def __str__(self):
        return self.question_text


class Choice(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    choice_text = models.CharField(max_length=200)
    votes = models.IntegerField(default=0)

    def __str__(self):
        return self.choice_text