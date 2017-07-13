import os
import webapp2
import jinja2
import re
import hashlib
import hmac
import random
import time
from string import letters

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET = 'supercalifraglisticspalidoesous'

# Keys
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# Security
def make_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_val(val):
    original = val.split('|')[0]
    if make_val(original) == val:
        return original

def create_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

def create_hash(name, pw, salt=None):
    if not salt:
        salt = create_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, pw, h):
    salt = h.split('|')[0]
    return h == create_hash(name, pw, salt)

# Database
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.StringProperty()
    modified = db.DateTimeProperty(auto_now_add=True)
    likes = db.ListProperty(int)

    def number_of_likes(self):
        number_of_likes = len(self.likes)
        return number_of_likes

class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.StringProperty()
    modified = db.DateTimeProperty(auto_now_add=True)
    user_id = db.IntegerProperty()
    post_id = db.IntegerProperty()

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        return User.all().filter('name =', name).get()

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = create_hash(name, pw)
        return User(name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = User.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# Validation for Signup and Login

def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)

def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)

def valid_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return not email or EMAIL_RE.match(email)

# Handlers

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def make_cookie(self, name, val):
        cookie_val = make_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_val(cookie_val)

    def login_cookie(self, user):
        self.make_cookie('user_id', str(user.key().id()))

    def cookie_logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class SignUp(BlogHandler):
    def get(self):
        self.render('signup.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify_password = self.request.get('verify_password')
        email = self.request.get('email')
        have_error = False

        params = dict(username=username, email=email)

        if not valid_username(username):
            params['error_username'] = 'Not a valid username'
            have_error = True

        if not valid_password(password):
            params['error_password'] = 'Not a valid password'
            have_error = True

        elif password != verify_password:
            params['error_verify_password'] = 'Passwords did not match'
            have_error = True

        if not valid_email(email):
            params['error_email'] = 'Not a valid email'
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            u = User.by_name(username)
            if u:
                error_msg = 'User already exists'
                self.render('signup.html', error_username=error_msg)
            else:
                u = User.register(username, password, email)
                u.put()
                self.login_cookie(u)
                self.redirect('/welcome')

class SignUpWelcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user)
        else:
            self.redirect('/signup')

class Login(BlogHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login_cookie(u)
            self.redirect('/welcome2')
        else:
            msg = 'Login not valid'
            self.render('login.html', error=msg)

class LoginWelcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome2.html', username=self.user)
        else:
            self.redirect('/signup')
            
class Logout(BlogHandler):
    def get(self):
        self.cookie_logout()
        self.redirect('/posts')

class Where(BlogHandler):
    def get(self):
        if self.user:
            self.render('/where.html', username=self.user)
        else:
            self.redirect('/signup')

class MainPage(BlogHandler):
    def get(self):
        self.render('main.html', username=self.user)

class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery('select * from Post order by created DESC limit 5')
        if self.user:
            user = self.user
            logged_user = user.name
        else:
            logged_user = ''
        self.render('posts.html', posts=posts, username=self.user,
                    logged_user=logged_user)

class NewPost(BlogHandler):
    def get(self):
        if self.read_cookie('user_id'):
            self.render('newpost.html', username=self.user)
        else:
            self.redirect('/login')

    def post(self):
        if self.user:
            subject = self.request.get('subject')
            content = self.request.get('content')

            if not content or not subject:
                error = 'Need subject and content, please!'
                self.render('newpost.html', username=self.user, error=error,
                            subject=subject, content=content)
            else:
                user_id = self.read_cookie('user_id').split('|')[0]
                username = User.by_id(int(user_id)).name

                author = username

                Post(subject=subject, content=content, author=author).put()
                time.sleep(0.1)
                self.redirect('/posts')
        else:
            self.redirect('/login')

class EditPost(BlogHandler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))

        if self.read_cookie('user_id'):
            if post.author == self.user.name:
                self.render('editpost.html', post=post, username=self.user)
            else:
                error = 'You cannot Edit someone elses post!'
                self.render('error.html', error=error, post=post)
        else:
            self.redirect('/login')

    def post(self, post_id):
        post = Post.get_by_id(int(post_id))
        if self.user:
            if post and post.author == self.user.name:
                new_subject = self.request.get('subject')
                new_content = self.request.get('content')

                if not new_content or not new_subject:
                    post = Post.get_by_id(int(post_id))
                    error = 'Content and subject plez'
                    self.render('editpost.html', post=post, username=self.user,
                                error=error)
                else:
                    post.subject = new_subject
                    post.content = new_content
                    post.put()
                    time.sleep(0.1)
                    self.redirect('/posts')
            else:
                error = 'You cannot Edit someone elses post!'
                self.render('error.html', error=error, post=post)
        else:
            self.redirect('/login')

class DeletePost(BlogHandler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        if self.user:
            if post and post.author == self.user.name:
                post.delete()
                time.sleep(0.1)
                self.redirect('/posts')
            else:
                self.redirect('/login')

class BlogComment(BlogHandler):
    def get(self, post_id):
        if self.read_cookie('user_id'):
            post = Post.get_by_id(int(post_id))
            self.render('blogcomment.html', post=post, username=self.user)
        else:
            self.redirect('/login')

    def post(self, post_id):
        content = self.request.get('content')
        post = Post.get_by_id(int(post_id))
        if self.user:
            if not content and post:
                error = 'Comment needed'
                self.render('blogcomment.html', post=post,
                            username=self.user, error=error)
            else:
                user_id = self.read_cookie('user_id').split('|')[0]
                author = User.by_id(int(user_id)).name

                Comment(content=content, author=author,
                        post_id=int(post_id)).put()
                time.sleep(0.1)
                self.redirect('/posts/' + str(post_id))
        else:
            self.redirect('/login')

class EditComment(BlogHandler):
    def get(self, comment_id):
        if self.read_cookie('user_id'):

            post_info = db.GqlQuery("SELECT * FROM Comment where __key__ = "
                                    "KEY('Comment'," + comment_id +
                                    ")").fetch(1)
            post = Post.get_by_id(int(post_info[0].post_id))
            comment = Comment.get_by_id(int(comment_id))

            if comment and comment.author == self.user.name:
                self.render('editcomment.html', comment=comment, post=post,
                            username=self.user)
            else:
                error = 'You can not Edit smoeone elses comments'
                self.render('error.html', error=error, post=post)
        else:
            self.redirect('/login')

    def post(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        post = db.GqlQuery("SELECT * FROM Comment where __key__ = KEY("
                           "'Comment'," + comment_id + ")").fetch(1)
        if self.user:
            if comment and comment.author == self.user.name:
                content = self.request.get('content')
                comment.content = content
                comment.put()
                time.sleep(0.1)
                self.redirect('/posts/' + str(post[0].post_id))
            else:
                error = 'You can not Edit smoeone elses comments'
                self.render('error.html', error=error, post=post[0])
        else:
            self.redirect('/login')

class DeleteComment(BlogHandler):
    def get(self, comment_id):
        if self.read_cookie('user_id'):
            posts = db.GqlQuery("SELECT * FROM Comment where __key__ = KEY("
                               "'Comment'," + comment_id + ")").fetch(1)
            comment = Comment.get_by_id(int(comment_id))
            if comment and comment.author == self.user.name:
                comment.delete()
                time.sleep(0.1)
                self.redirect('/posts/' + str(posts[0].post_id))
            else:
                self.redirect('/login')

class PermaLink(BlogHandler):
    def get(self, post_id):
        if self.user:
            user = self.user
            logged_user = user.name
        else:
            logged_user = ''
        post = Post.get_by_id(int(post_id))
        comments = db.GqlQuery("select * from Comment where post_id="
                               + post_id).fetch(limit=3)
        self.render('permalink.html', post=post, username=self.user,
                    comments=comments, logged_user=logged_user)

class LikePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')
        post = Post.get_by_id(int(post_id))
        user_id = self.user.key().id()

        if post.author == self.user.name:
            return self.redirect('/posts/' + str(post_id))

        if user_id not in post.likes:
            post.likes.append(user_id)
        else:
            post.likes.remove(user_id)

        post.put()
        self.redirect('/posts/' + str(post_id))


app = webapp2.WSGIApplication([
    ('/', BlogFront),
    ('/posts', BlogFront),
    ('/posts/(\d+)', PermaLink),
    ('/newpost', NewPost),
    ('/signup', SignUp),
    ('/login', Login),
    ('/logout', Logout),
    ('/welcome', SignUpWelcome),
    ('/welcome2', LoginWelcome),
    ('/editpost/(\d+)', EditPost),
    ('/deletepost/(\d+)', DeletePost),
    ('/blogcomment/(\d+)', BlogComment),
    ('/editcomment/(\d+)', EditComment),
    ('/deletecomment/(\d+)', DeleteComment),
    ('/likepost/(\d+)', LikePost),
    ('/where', Where)
], debug=True)
