#!/usr/bin/env python3

from flask import request, session  
from flask_restful import Resource  
from sqlalchemy.exc import IntegrityError  

from config import app, db, api  
from models import User, Recipe  


class Signup(Resource):
    def post(self):
        # Getting JSON data from the request
        json = request.get_json()
        
        # Creating a new User instance with data from the request
        user = User(
            username=json.get('username'),
            image_url=json.get('image_url'),
            bio=json.get('bio')
        )
        
        # Setting the user's password hash from the provided password
        user.password_hash = json.get('password')

        try:
            # Adding the user to the database session and committing the changes
            db.session.add(user)
            db.session.commit()
            # Storing the user ID in the session for tracking logged-in user
            session['user_id'] = user.id
            return user.to_dict(), 201  # Returning the user data and a 201 status code
        except IntegrityError:
            # Handling case where adding the user violates database constraints
            return {'error': 'Unprocessable Entity'}, 422


class CheckSession(Resource):
    def get(self):
        # Checking if the user is logged in by checking the session
        if session.get('user_id'):
            user = User.query.filter(User.id == session['user_id']).first()
            return user.to_dict(), 200  # Returning the user's data with a 200 status code
        return {}, 401  # Returning an empty response with a 401 status code if not logged in


class Login(Resource):
    def post(self):
        # Getting JSON data from the request for login
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')
 
        # Querying the database for the user with the provided username
        user = User.query.filter(User.username == username).first()
        if user:
            # Checking if the provided password is correct
            if user.authenticate(password):
                session['user_id'] = user.id  # Storing user ID in the session
                return user.to_dict()  # Returning the user data
                
        # Returning an error if username or password is invalid
        return {'error': 'Invalid username or password'}, 401


class Logout(Resource):
    def delete(self):
        # Checking if the user is logged in by checking the session
        if session.get('user_id'):
            session['user_id'] = None  # Clearing the user ID from the session
            return {}, 204  # Returning an empty response with a 204 status code
            
        return {'error': 'not logged in'}, 401  # Returning an error if not logged in


@app.before_request
def check_if_logged_in():
    # Checking if the user is logged in before processing requests to certain endpoints
    if not session.get('user_id') and request.endpoint == 'recipes':
        return {'error': 'Unauthorized'}, 401  # Returning an error if not authorized


class RecipeIndex(Resource):
    def get(self):
        # Getting the currently logged-in user
        user = User.query.filter(User.id == session.get('user_id')).first()
        # Creating a list of the user's recipes as dictionaries
        user_recipes = [recipe.to_dict() for recipe in user.recipes]
        return user_recipes, 200  # Returning the recipes with a 200 status code
      
    def post(self):
        # Getting JSON data from the request to create a new recipe
        json = request.get_json()
        try:
            # Creating a new Recipe instance with data from the request
            new_recipe = Recipe(
                title=json['title'],
                instructions=json['instructions'],
                minutes_to_complete=json['minutes_to_complete'],
                user_id=session.get('user_id')  # Associating recipe with the logged-in user
            )
  
            db.session.add(new_recipe)  # Adding the new recipe to the session
            db.session.commit()  # Committing the changes to the database
            return new_recipe.to_dict(), 201  # Returning the new recipe data with a 201 status code
        except IntegrityError:
            return {'error': 'Unprocessable Entity'}, 422  # Handling any integrity errors


# Registering API resources with their respective endpoints
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)  # Running the Flask application on port 5555 with debug mode enabled
