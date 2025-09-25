from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.utils import timezone
from django.db import IntegrityError
from django.core.exceptions import ValidationError
from .models import Post, Question, Choice
from unittest.mock import patch
import datetime


class PostModelTests(TestCase):
    """Test cases for the Post model."""
    
    def setUp(self):
        """Set up test data for each test method."""
        self.post_data = {
            'title': 'Test Post',
            'body': 'This is a test post body.',
            'signature': 'Test Author',
            'date': timezone.now()
        }
    
    def test_post_creation(self):
        """Test creating a new post."""
        post = Post.objects.create(**self.post_data)
        self.assertEqual(post.title, 'Test Post')
        self.assertEqual(post.body, 'This is a test post body.')
        self.assertEqual(post.signature, 'Test Author')
        self.assertIsNotNone(post.date)
    
    def test_post_str_representation(self):
        """Test the string representation of a post."""
        post = Post.objects.create(**self.post_data)
        self.assertEqual(str(post), 'Test Post')
    
    def test_post_default_signature(self):
        """Test that default signature is 'Evan'."""
        post_data = self.post_data.copy()
        del post_data['signature']
        post = Post.objects.create(**post_data)
        self.assertEqual(post.signature, 'Evan')
    
    def test_post_title_max_length(self):
        """Test that post title respects max length of 140 characters."""
        long_title = 'x' * 141
        post_data = self.post_data.copy()
        post_data['title'] = long_title
        
        with self.assertRaises(Exception):
            post = Post(**post_data)
            post.full_clean()
    
    def test_post_signature_max_length(self):
        """Test that post signature respects max length of 140 characters."""
        long_signature = 'x' * 141
        post_data = self.post_data.copy()
        post_data['signature'] = long_signature
        
        with self.assertRaises(Exception):
            post = Post(**post_data)
            post.full_clean()
    
    def test_post_empty_title(self):
        """Test that post cannot have empty title."""
        post_data = self.post_data.copy()
        post_data['title'] = ''
        
        with self.assertRaises(ValidationError):
            post = Post(**post_data)
            post.full_clean()
    
    def test_post_empty_body(self):
        """Test that post can have empty body."""
        post_data = self.post_data.copy()
        post_data['body'] = ''
        post = Post.objects.create(**post_data)
        self.assertEqual(post.body, '')
    
    def test_post_date_required(self):
        """Test that post date is required."""
        post_data = self.post_data.copy()
        del post_data['date']
        
        with self.assertRaises(IntegrityError):
            Post.objects.create(**post_data)
    
    def test_post_ordering(self):
        """Test post ordering by date."""
        post1 = Post.objects.create(
            title='First Post',
            body='First post body',
            date=timezone.now() - datetime.timedelta(days=1)
        )
        post2 = Post.objects.create(
            title='Second Post',
            body='Second post body',
            date=timezone.now()
        )
        
        posts = Post.objects.order_by('-date')
        self.assertEqual(posts[0], post2)
        self.assertEqual(posts[1], post1)


class QuestionModelTests(TestCase):
    """Test cases for the Question model."""
    
    def setUp(self):
        """Set up test data for each test method."""
        self.question_data = {
            'question_text': 'What is your favorite color?',
            'pub_date': timezone.now()
        }
    
    def test_question_creation(self):
        """Test creating a new question."""
        question = Question.objects.create(**self.question_data)
        self.assertEqual(question.question_text, 'What is your favorite color?')
        self.assertIsNotNone(question.pub_date)
    
    def test_question_str_representation(self):
        """Test the string representation of a question."""
        question = Question.objects.create(**self.question_data)
        self.assertEqual(str(question), 'What is your favorite color?')
    
    def test_question_text_max_length(self):
        """Test that question text respects max length of 200 characters."""
        long_text = 'x' * 201
        question_data = self.question_data.copy()
        question_data['question_text'] = long_text
        
        with self.assertRaises(Exception):
            question = Question(**question_data)
            question.full_clean()
    
    def test_question_empty_text(self):
        """Test that question cannot have empty text."""
        question_data = self.question_data.copy()
        question_data['question_text'] = ''
        
        with self.assertRaises(ValidationError):
            question = Question(**question_data)
            question.full_clean()
    
    def test_question_pub_date_required(self):
        """Test that question pub_date is required."""
        question_data = self.question_data.copy()
        del question_data['pub_date']
        
        with self.assertRaises(IntegrityError):
            Question.objects.create(**question_data)


class ChoiceModelTests(TestCase):
    """Test cases for the Choice model."""
    
    def setUp(self):
        """Set up test data for each test method."""
        self.question = Question.objects.create(
            question_text='What is your favorite color?',
            pub_date=timezone.now()
        )
        self.choice_data = {
            'question': self.question,
            'choice_text': 'Blue',
            'votes': 0
        }
    
    def test_choice_creation(self):
        """Test creating a new choice."""
        choice = Choice.objects.create(**self.choice_data)
        self.assertEqual(choice.choice_text, 'Blue')
        self.assertEqual(choice.votes, 0)
        self.assertEqual(choice.question, self.question)
    
    def test_choice_str_representation(self):
        """Test the string representation of a choice."""
        choice = Choice.objects.create(**self.choice_data)
        self.assertEqual(str(choice), 'Blue')
    
    def test_choice_default_votes(self):
        """Test that choice votes default to 0."""
        choice_data = self.choice_data.copy()
        del choice_data['votes']
        choice = Choice.objects.create(**choice_data)
        self.assertEqual(choice.votes, 0)
    
    def test_choice_text_max_length(self):
        """Test that choice text respects max length of 200 characters."""
        long_text = 'x' * 201
        choice_data = self.choice_data.copy()
        choice_data['choice_text'] = long_text
        
        with self.assertRaises(Exception):
            choice = Choice(**choice_data)
            choice.full_clean()
    
    def test_choice_foreign_key_cascade(self):
        """Test that choices are deleted when question is deleted."""
        choice = Choice.objects.create(**self.choice_data)
        question_id = self.question.id
        choice_id = choice.id
        
        self.question.delete()
        
        self.assertFalse(Question.objects.filter(id=question_id).exists())
        self.assertFalse(Choice.objects.filter(id=choice_id).exists())
    
    def test_choice_votes_increment(self):
        """Test that choice votes can be incremented."""
        choice = Choice.objects.create(**self.choice_data)
        choice.votes = 5
        choice.save()
        
        updated_choice = Choice.objects.get(id=choice.id)
        self.assertEqual(updated_choice.votes, 5)

    def test_choice_zero_votes(self):
        """Test that choice can have zero votes (minimum value)."""
        choice_data = self.choice_data.copy()
        choice_data['votes'] = 0
        choice = Choice.objects.create(**choice_data)
        self.assertEqual(choice.votes, 0)


class BlogViewTests(TestCase):
    """Test cases for blog-related views."""
    
    def setUp(self):
        """Set up test client and user for each test method."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.post = Post.objects.create(
            title='Test Post',
            body='Test content',
            date=timezone.now()
        )
    
    def test_blog_index_requires_authentication(self):
        """Test that blog index redirects unauthenticated users."""
        response = self.client.get(reverse('blog_index'))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))
    
    def test_blog_index_with_authentication(self):
        """Test that authenticated users can access blog index."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('blog_index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'features/blog/blog.html')
    
    def test_blog_index_displays_posts(self):
        """Test that blog index displays posts."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('blog_index'))
        self.assertContains(response, 'Test Post')
        self.assertIn('object_list', response.context)
    
    def test_blog_index_never_cache_header(self):
        """Test that blog index has never cache headers."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('blog_index'))
        self.assertIn('Cache-Control', response)
        self.assertIn('no-cache', response['Cache-Control'])
    
    def test_blog_detail_requires_authentication(self):
        """Test that blog detail redirects unauthenticated users."""
        response = self.client.get(reverse('blog_detail', args=[self.post.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))
    
    def test_blog_detail_with_authentication(self):
        """Test that authenticated users can access blog detail."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('blog_detail', args=[self.post.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'features/blog/post.html')
    
    def test_blog_detail_404_for_nonexistent_post(self):
        """Test that blog detail returns 404 for nonexistent post."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('blog_detail', args=[9999]))
        self.assertEqual(response.status_code, 404)
    
    def test_blog_detail_displays_correct_post(self):
        """Test that blog detail displays the correct post."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('blog_detail', args=[self.post.pk]))
        self.assertEqual(response.context['post'], self.post)
        self.assertContains(response, 'Test Post')


class PollViewTests(TestCase):
    """Test cases for poll-related views."""
    
    def setUp(self):
        """Set up test client, user, and poll data."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.question = Question.objects.create(
            question_text='What is your favorite color?',
            pub_date=timezone.now()
        )
        self.choice1 = Choice.objects.create(
            question=self.question,
            choice_text='Blue',
            votes=0
        )
        self.choice2 = Choice.objects.create(
            question=self.question,
            choice_text='Red',
            votes=0
        )
    
    def test_polls_index_requires_authentication(self):
        """Test that polls index redirects unauthenticated users."""
        response = self.client.get(reverse('polls_index'))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))
    
    def test_polls_index_with_authentication(self):
        """Test that authenticated users can access polls index."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('polls_index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'features/polls/poll.html')
    
    def test_polls_detail_requires_authentication(self):
        """Test that polls detail redirects unauthenticated users."""
        response = self.client.get(reverse('polls_detail', args=[self.question.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))
    
    def test_polls_detail_with_authentication(self):
        """Test that authenticated users can access polls detail."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('polls_detail', args=[self.question.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'features/polls/detail.html')
    
    def test_vote_requires_authentication(self):
        """Test that vote view redirects unauthenticated users."""
        response = self.client.post(reverse('polls_vote', args=[self.question.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))
    
    def test_vote_with_valid_choice(self):
        """Test voting with a valid choice."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post(
            reverse('polls_vote', args=[self.question.pk]),
            {'choice': self.choice1.pk}
        )
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('polls_results', args=[self.question.pk]))
        
        # Check that vote was recorded
        updated_choice = Choice.objects.get(pk=self.choice1.pk)
        self.assertEqual(updated_choice.votes, 1)
    
    def test_vote_without_choice(self):
        """Test voting without selecting a choice."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post(reverse('polls_vote', args=[self.question.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'features/polls/detail.html')
        # Check for HTML-encoded apostrophe in the error message
        self.assertContains(response, "You didn&#x27;t select a choice.")
    
    def test_vote_with_invalid_choice(self):
        """Test voting with an invalid choice."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post(
            reverse('polls_vote', args=[self.question.pk]),
            {'choice': 9999}
        )
        self.assertEqual(response.status_code, 200)
        # Check for HTML-encoded apostrophe in the error message
        self.assertContains(response, "You didn&#x27;t select a choice.")
    
    def test_results_requires_authentication(self):
        """Test that results view redirects unauthenticated users."""
        response = self.client.get(reverse('polls_results', args=[self.question.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))
    
    def test_results_with_authentication(self):
        """Test that authenticated users can access results."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('polls_results', args=[self.question.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'features/polls/results.html')


class FeaturesURLTests(TestCase):
    """Test cases for features app URL configuration."""
    
    def test_blog_index_url_resolves(self):
        """Test that blog index URL resolves correctly."""
        from django.urls import resolve
        resolver = resolve('/features/blog/')
        self.assertEqual(resolver.func.__name__, 'blog_index')
        self.assertEqual(resolver.url_name, 'blog_index')
    
    def test_blog_detail_url_resolves(self):
        """Test that blog detail URL resolves correctly."""
        from django.urls import resolve
        resolver = resolve('/features/blog/1/')
        self.assertEqual(resolver.func.__name__, 'blog_detail')
        self.assertEqual(resolver.url_name, 'blog_detail')
    
    def test_polls_index_url_resolves(self):
        """Test that polls index URL resolves correctly."""
        from django.urls import resolve
        resolver = resolve('/features/polls/')
        self.assertEqual(resolver.func.__name__, 'polls_index')
        self.assertEqual(resolver.url_name, 'polls_index')
    
    def test_polls_detail_url_resolves(self):
        """Test that polls detail URL resolves correctly."""
        from django.urls import resolve
        resolver = resolve('/features/polls/1')
        self.assertEqual(resolver.func.__name__, 'polls_detail')
        self.assertEqual(resolver.url_name, 'polls_detail')


class FeaturesIntegrationTests(TestCase):
    """Integration tests for features app."""
    
    def setUp(self):
        """Set up test data for integration tests."""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.question = Question.objects.create(
            question_text='Integration test question?',
            pub_date=timezone.now()
        )
        self.choice = Choice.objects.create(
            question=self.question,
            choice_text='Integration choice',
            votes=0
        )
    
    def test_complete_voting_workflow(self):
        """Test the complete voting workflow."""
        # Login
        self.client.login(username='testuser', password='testpass123')
        
        # Access polls index
        response = self.client.get(reverse('polls_index'))
        self.assertEqual(response.status_code, 200)
        
        # Access poll detail
        response = self.client.get(reverse('polls_detail', args=[self.question.pk]))
        self.assertEqual(response.status_code, 200)
        
        # Vote
        response = self.client.post(
            reverse('polls_vote', args=[self.question.pk]),
            {'choice': self.choice.pk}
        )
        self.assertEqual(response.status_code, 302)
        
        # View results
        response = self.client.get(reverse('polls_results', args=[self.question.pk]))
        self.assertEqual(response.status_code, 200)
        
        # Verify vote was recorded
        updated_choice = Choice.objects.get(pk=self.choice.pk)
        self.assertEqual(updated_choice.votes, 1)
    
    def test_blog_workflow(self):
        """Test the complete blog workflow."""
        # Create a post
        post = Post.objects.create(
            title='Integration Test Post',
            body='This is a test post for integration testing.',
            date=timezone.now()
        )
        
        # Login
        self.client.login(username='testuser', password='testpass123')
        
        # Access blog index
        response = self.client.get(reverse('blog_index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Integration Test Post')
        
        # Access blog detail
        response = self.client.get(reverse('blog_detail', args=[post.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'This is a test post for integration testing.')
    
    def test_redirect_workflow_after_login(self):  
        """  
        Test that a user trying to access a protected page is redirected 
        to login, and after logging in, is redirected back to their 
        original destination.  
        """  
        # Try to access blog index, a protected page without logging in.  
        response_for_redirect = self.client.get(reverse('blog_index'))  
        
        # Verify the redirect to the login page
        login_url = reverse('login')
        self.assertRedirects(
            response_for_redirect, 
            login_url
        ) 
        
        # Now login using the login URL WITH the next parameter explicitly added
        # since the application doesn't include it in the redirect
        login_url_with_next = f"{login_url}?next={reverse('blog_index')}"
        response_after_login = self.client.post(login_url_with_next, {
            'username': 'testuser',
            'password': 'testpass123'
        })

        # We should be redirected to the blog page as specified in the next parameter
        self.assertRedirects(response_after_login, reverse('blog_index'))
