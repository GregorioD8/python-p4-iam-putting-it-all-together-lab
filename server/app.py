#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

# Middleware to check if user is logged in before accessing protected endpoints
@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup', 
        'login',
        'check_session'
    ]

    # If endpoint is not in open access list and user is not logged in, return 401 unauthorized
    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401
    
# Resource for handling user signup    
class Signup(Resource):
    def post(self):

        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')
        image_url = request_json.get('image_url')
        bio = request_json.get('bio')

        if not (username and password): 
            return {'error': 'Username and password are required'}, 422
        
        # Create a new User object with provided data
        user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )

        # Encrypt the password using bcrypt
        user.password_hash = password

        try:
            # Add user to database
            db.session.add(user)
            db.session.commit()

            # Store user_id in session to keep user logged in
            session['user_id'] = user.id

            # Return user data in JSON format with status code 201 created
            return user.to_dict(), 201
        
        except IntegrityError:
            # Handle IntegrityError (e.g. duplicate username) with status code 422 Unprocessable Entity
            return {'error': '422 Unprocessable Entity'}, 422
        
# Resource for checking if user session is active
class CheckSession(Resource):
    
    def get(self):
        # Retrieve user_id from session 
        user_id = session['user_id']

        if user_id:
            # If user_id is found, retrieve user data and return with status code 200 Success
            user =  User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        
        # If user is not logged in, return empty response with status code 401 Unauthorized
        return {}, 401
    
# Resource for handling user login
class Login(Resource):

    def post(self):
        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')

        # Query database for user with provided username
        user = User.query.filter(User.username == username).first()

        if user:
            if user.authenticate(password):
                # If password is authenticated, store user_id in session and return user data with code 200 Success
                session['user_id'] = user.id
                return user.to_dict(), 200
        
        # If authentication fails, return 401 Unauthorized
        return {'error': '401 Unauthorized'}, 401

# Resource for handling user login       
class Logout(Resource):

    def delete(self):
        # Clear user_id from session to log user out 
        session['user_id'] = None

        # Return empty response with status code 204 No Content
        return {}, 204
    
#Resource for retrieving and creating recipes
class RecipeIndex(Resource):
    
    def get(self):
        # Retrieve user from database based on user_id in session 
        user = User.query.filter(User.id == session['user_id']).first()

        # Return list of user's recipes in JSON format with status code 200 Success
        return [recipe.to_dict() for recipe in user.recipes], 200
    
    def post(self):
        request_json = request.get_json()

        title = request_json['title']
        instructions = request_json['instructions']
        minutes_to_complete = request_json['minutes_to_complete']

        if not (title and instructions and minutes_to_complete):
            return {'error': 'Title, instructions, and minutes_to_complete are required'}, 422
        
        try:
            # Create a new Recipe object associated with the logged_in user
            recipe = Recipe(
                title=title, 
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id'],
            ) 

            # Add recipe to database
            db.session.add(recipe)
            db.session.commit()

            # Return created recipe data in JSON format with status code 201 Created
            return recipe.to_dict(), 201
        
        except IntegrityError:
            # Handle IntegrityError (e.g. missing required fields) with status code 422 Unprocessable Entity
            return {'error': '422 Unprocessable Entity'}, 422
        
# Registering endpoints for each resource class        
api.add_resource(Signup, '/signup', endpoint='signup') 
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)