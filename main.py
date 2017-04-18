#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import re
import webapp2
import jinja2
import string
import random
# For security, safer than using hashlib
import hmac
import hashlib
from google.appengine.ext import db


# This is all helper stuff....
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
	                           autoescape=True)

# REGEX:
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{5,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_username(username):
	return username and USER_RE.match(username)


def valid_password(password):
		return password and PASS_RE.match(password)


def valid_email(email):
		return not email or EMAIL_RE.match(email)


# SECURITY (hasing, passwords, salts, etc)
# safer, hmac hashing function:


def hash_str(s):
	return hmac.new(secret, s).hexdigest()


def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

# This uses the above 2 fns to determine is the value entered is correct
# (eg, did the password entered match that originally created)


def check_secure_val(h):
	s = h.split("|")[0]
	if h == make_secure_val(s):
		return s

# SECRET:
secret = "super_secrety_secret"

# Adding the salt for security:
# How to implement password protection


def make_salt():
	salt = ''.join([random.choice(string.letters) for i in range(5)])
	return salt

# Now, making hash with the salt:


def make_hash_pw(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name+pw+salt).hexdigest()
	return "%s,%s" % (salt, h)


# Now it needs to be verified (and actually used)
# That is, when user enters name & pw:


def valid_pw(name, pw, h):
	salt = h.split(",")[0]
	return h == make_hash_pw(name, pw, salt)

# DB ENTRIES OF USERS:


def users_key(group='default'):
	return db.Key.from_path('users', group)

# Now, the user object which will be stored in the google datastre


class User(db.Model):
	name = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required=True)
	email = db.StringProperty()
# These are just methods for getting a user out of the db,
# by their name or their id.

	@classmethod
	def by_id(cls, uid):
		return cls.get_by_id(uid, parent=users_key())

	@classmethod
	def by_name(cls, name):
		u = cls.all().filter('name =', name).get()
		return u
# This would be similar to:
# Select * FROM user WHERE name = name
# Or: posts = db.GqlQuery("SELECT * FROM
# BlogEntry ORDER BY timestamp DESC")?not exactly

	@classmethod
	def register(cls, name, pw, email=None):
		pw_hash = make_hash_pw(name, pw)
		return cls(parent=users_key(),
			   name=name, pw_hash=pw_hash,
			   email=email)

	@classmethod
	def user_object_login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


# DB BLOG entries:


def blog_key(name='dafault'):
	return db.Key.from_path('blogs', name)


class BlogEntry(db.Model):
	author = db.StringProperty(required=True)
	subject = db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	timestamp = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now=True)
	likes = db.IntegerProperty()
	likers = db.StringListProperty()

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p=self)

	'''
	def get_author(self):
		author  = User.by_id(self.user_id)
		return author.name'''


def render_str(*template, **params):
	t = jinja_env.get_template(*template)
	return t.render(**params)


class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		t = jinja_env.get_template(template)
		return t.render(**params)

	def render(self, *template, **params):
		return self.write(self.render_str(*template, **params))


# Now, add code to set a cookie (go check notes on expiration)
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s = %s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

# -----COMMENTS -----


class Comment(db.Model):
	comment = db.TextProperty(required=True)
	commentauthor = db.StringProperty(required=True)
	post_id = db.IntegerProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)


class CommentHandler(Handler):
	def get(self, post_id):
		key = db.Key.from_path('BlogEntry', int(post_id), parent=blog_key())
		post = db.get(key)
		all_comments = Comment.all().filter('post_id =', post_id).order('-created')
		if post == None:
			self.redirect('/home')
		else:
			if self.user:
				if all_comments:
					self.render("comment.html", p=post, all_comments=all_comments)
				else:
					self.render("comment.html", p=post)
			else:
				error = "You need to be signed in to comment on a post"
				redirect('/signup', error=error)

	def post(self, post_id):
		key = db.Key.from_path('BlogEntry', 
			int(post_id), parent=blog_key())
		post = db.get(key)
		post_id = int(post_id)
		comment = self.request.get("comment")
		formatted_comment = comment.replace('\n', '<br>')
		all_comments = Comment.all().filter('post_id =',
			post_id).order('-created')
		if post == None:
			self.redirect('/home')
		else:
			if self.user and comment:
				c = Comment(parent=blog_key(), comment=formatted_comment, 
					commentauthor=self.user.name, post_id=post_id)
				c.put()
				self.redirect("/blog/%s" % post_id)
			else:
				error = ("To publish a blog post, comment content "
	            	"is required in the text area "
	            	"(& you must be signed in and )")
				self.render("comment.html", p=post,
	            	        all_comments=all_comments,
	            	        error=error, comment_prev=comment)


class EditComment(Handler):
	def get(self, post_id, comment_id):
		key = db.Key.from_path('BlogEntry', int(post_id), parent=blog_key())
		post = db.get(key)
		ckey = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
		c = db.get(ckey)
		if post == None:
			self.redirect('/home')
		else:
			if self.user and self.user.name == c.commentauthor:
				self.render("edit_comment.html", c=c, comment=c.comment, post=post)
			else:
				error = ("You can only edit your own comment, "
					"and you have to be signed in to do that")
				self.render("login.html", error=error)

	def post(self, post_id, comment_id):
		key = db.Key.from_path('BlogEntry', int(post_id), parent=blog_key())
		post = db.get(key)

		ckey = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
		c = db.get(ckey)
		comment = self.request.get("comment")
		if post == None:
			self.redirect('/home')
		else:
			if self.user and self.user.name == c.commentauthor:
				if comment:
					c.comment = comment
					c.put()
					self.redirect("/blog/%s" % post_id)
				else:
					error = "To EDIT and then publish a comment, content is required"
					self.render("edit_comment.html", c=c, comment=c.comment)
			else:
				error = ("You can only edit your own comment,"
				" and you have to be signed in to do that")
				self.render("login.html", error=error)


class DeleteComment(Handler):
	def get(self, post_id, comment_id):
		key = db.Key.from_path('BlogEntry', int(post_id), parent=blog_key())
		post = db.get(key)
		ckey = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
		c = db.get(ckey)
		if post == None:
			self.redirect('/home')
		else:
			if self.user.name == c.commentauthor:
				c.delete()
				self.redirect("/blog/%s" % post_id)
			else:
				error = "Sorry man, you can only delte your own comments"
				self.render('login.html', error)

# ########      ---- MAIN PAGE ----
#    ---- PARTICULAR POST -----


class PostPage(Handler):
	def get(self, post_id):
		key = db.Key.from_path('BlogEntry', int(post_id), parent=blog_key())
		post = db.get(key)
		comments = Comment.all().filter('post_id =', int(post_id)).order('-created')
		if not post:
			self.error(404)
			return
		if self.user:
			self.render("permalink.html", username=self.user.name,
			 post=post, comments=comments)
		else:
			self.render("permalink.html", username="Guest",
			 post=post, comments=comments)


class BlogFront(Handler):
	def get(self):
		posts = BlogEntry.all().order('-timestamp')
# comments = db.GqlQuery("SELECT
# * FROM Comment ORDER BY created DESC LIMIT 10")
# Rather use the filter plus .all() syntax...
		if self.user:
			self.render("homepage.html", username=self.
			user.name, posts=posts)
		else:
			self.render("homepage.html", username="Guest",
			posts=posts)


# ######    ---REGISTRATION PAGE----


class SignUp(Handler):
	def get(self):
			self.render("signup.html")

	def post(self):
		have_error = False
		self.username = self.request.get("username")
		self.password = self.request.get("password")
		self.verify = self.request.get("verify")
		self.email = self.request.get("email")

		params = dict(username=self.username, email=self.email)
# This is for string substitution back into the signup form

# Now, checking the signup form inputs:
		if not valid_username(self.username):
			params["name_error"] = "That is not a valid username"
			have_error = True

		if not valid_password(self.password):
			params["password_error"] = "That is not a valid password"
			have_error = True

		elif self.password != self.verify:
			params["verify_error"] = "Your passwords do not match"
			have_error = True

		if not valid_email(self.email):
			params["email_error"] = "That is not a valid email address"
			have_error = True

		if have_error:
			self.render("signup.html", **params)
		else:
			self.done()


# Register is descended from signup:


class Register(SignUp):
	def done(self):
		u = User.by_name(self.username)
		if u:
			msg = 'Unfortunately this username already exists'
			self.render('signup.html', name_error=msg)
# Dont let the username be 'Guest', so that I can hide buttons on permalinks:
		elif self.username == "Guest":
			msg = 'Guest is not a username you can use, sadly'
			self.render('signup.html', name_error=msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
# All that login does is set the cookie
			self.redirect('/')


class Login(Handler):
	def get(self):
		if self.user:
			self.render("login.html", username=self.user.name)
		self.render("login.html", username="Guest")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.user_object_login(username, password)
		if u:
			self.login(u)
			self.redirect('/')
		else:
			msg = 'Invalid login'
			self.render("login.html", error=msg)


class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/')


class Like(Handler):
	def post(self, post_id):
		key = db.Key.from_path('BlogEntry', int(post_id), parent=blog_key())
		p = db.get(key)
		post_id = str(p.key().id())

		if self.user and self.user.name != p.author:
			if self.user.name not in p.likers:
				p.likes = p.likes + 1
				p.likers.append(self.user.name)
				p.put()
				self.redirect("/blog/%s" % post_id)
			else:
				self.redirect("/blog/%s" % post_id)
		else:
			self.redirect("/blog/%s" % post_id)

# Blog post page


class FormPage(Handler):
	def render_form(self, author="", subject="", content="", error=""):
		self.render("blog_form.html", author=author, subject=subject, 
			content=content, error=error)

	def get(self):
		if self.user:
			self.render_form()
		else:
			self.redirect('/signup', name_error="Need to"+
				" be registered and logged in to make a post")

	def post(self):
		if not self.user:
			self.redirect('/login')

		subject = self.request.get("subject")
		content = self.request.get("content")
		author = self.user.name
		likes = 0
		if self.user:
			if subject and content:
				b = BlogEntry(parent=blog_key(), author=author, 
							  subject=subject, content=content, likes=likes)
				b.put()
				post_id = str(b.key().id())
				self.redirect("/blog/%s" % post_id)
			else:
				error = "To publish a blog post, both a subject, and content is required"
				self.render_form(author, subject, content, error)
		else:
			self.redirect('/signup', name_error="Need to be registered and logged in to make a post")


class EditBlogEntry(Handler):
	def get(self, post_id):
		key = db.Key.from_path('BlogEntry', int(post_id), parent=blog_key())
		p = db.get(key)
		if p == None:
			self.redirect('/home')
		else:
			if self.user and self.user.name == p.author:
				self.render("edit_blog_form.html", post=p,
				subject=p.subject, content=p.content)
			else:
				error = ("You can only edit your own post, "
					"and you have to be signed in to do that")
				self.render("login.html", error = error)

	def post(self, post_id):
		key = db.Key.from_path('BlogEntry', int(post_id), 
			parent=blog_key())
		p = db.get(key)
		if p == None:
			self.redirect('/home')
		else:
			subject = self.request.get("subject")
			content = self.request.get("content")
			if self.user and self.user.name == p.author:
				if subject and content:
					p.subject = subject
					p.content = content
					p.put()
					post_id = str(p.key().id())
					self.redirect("/blog/%s" % post_id)
				else:
					error = ("To publish a blog post, "
						"both a subject, and content is required")
					self.render_form(author, subject, content, error)
			else:
				error = ("You can only edit your own post,"
					" and you have to be signed in to do that")
				self.render("login.html", error=error)


class DeleteBlogEntry(Handler):
	def get(self, post_id):
		key = db.Key.from_path('BlogEntry', int(post_id),
			parent=blog_key())
		p = db.get(key)
		if p == None:
			self.redirect('/home')
		else:
			if self.user and self.user.name == p.author:
				p.delete()
				self.render('homepage.html', p=p)
			else:
				error = "Sorry man, you can only delete your own posts"
				self.render("login.html", error=error)


app = webapp2.WSGIApplication([('/', BlogFront),
								('/home', BlogFront),
								('/form', FormPage), # Where you make a blog submission
								('/signup', Register),
								('/login', Login),
								('/logout', Logout),
								('/blog/([0-9]+)', PostPage),
								('/blog/([0-9]+)/edit', EditBlogEntry),
								('/blog/([0-9]+)/delete', DeleteBlogEntry),
								('/blog/([0-9]+)/like', Like),
								('/blog/([0-9]+)/comment', CommentHandler),
								('/blog/([0-9]+)/comment/([0-9]+)/edit', EditComment),
								('/blog/([0-9]+)/comment/([0-9]+)/delete', DeleteComment)], debug=True)

