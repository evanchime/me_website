"""
Django models defining core application data structures.

This module contains three models representing blog posts, poll 
questions, and answer choices.
Models include field definitions and basic string representations.

Models:
    Post: Represents a blog post with timestamp and author signature.
    Question: Represents a poll question with publication date.
    Choice: Represents an answer choice linked to a Question.
"""

from django.db import models

class Post(models.Model):
    """
    Blog post model containing content and metadata.

    Attributes:
        title: Post title with 140 characters max
        body: Main content of the post
        signature: Author identifier. Defaults to 'Evan'
        date: Creation timestamp

    Methods:
        __str__: Returns post title for string representation
    """
    
    title = models.CharField(max_length=140)
    body = models.TextField()
    signature = models.CharField(max_length=140, default="Evan")
    date = models.DateTimeField()

    def __str__(self) -> str:
        """Return post title as string representation."""
        return self.title


class Question(models.Model):
    """
    Poll question model with publication date tracking.

    Attributes:
        question_text: Question content 200 characters max
        pub_date: Publication date/time. 'date published' is the 
        human-readable name for the field.

    Methods:
        __str__: Returns question text for string representation
    """

    question_text = models.CharField(max_length=200)
    pub_date = models.DateTimeField('date published')

    def __str__(self) -> str:
        """Return question text as string representation."""
        return self.question_text


class Choice(models.Model):
    """
    Answer choice model associated with a Question.

    Attributes:
        question: Reference to parent Question. If a Question is deleted, 
        all related Choice objects will be automatically deleted
        choice_text: Choice content 200 characters max
        votes: Vote counter. Defaults to 0

    Methods:
        __str__: Returns choice text for string representation
    """

    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    choice_text = models.CharField(max_length=200)
    votes = models.PositiveIntegerField(default=0)

    def __str__(self) -> str:
        """Return choice text as string representation."""
        return self.choice_text
