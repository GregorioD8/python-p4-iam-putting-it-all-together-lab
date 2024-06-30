from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

# User model for representing users in the database
class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    #Serialization rules to exclude recipes and password hash from serialization 
    serialize_rules = ('-recipes.user', '-_password_hash',)

    # User attributes:
    # id that is an integer type and a primary key.
    id = db.Column(db.Integer, primary_key=True)
    # username that is a String type.
    username = db.Column(db.String, unique=True, nullable=False)
    # _password_hash that is a String type.
    _password_hash = db.Column(db.String)
    # image_url that is a String type.
    image_url = db.Column(db.String)
    # bio that is a String type.
    bio = db.Column(db.String)

    # Relationship: User has many recipes
    recipes = db.relationship('Recipe', backref='user')

    ## Assignment Requirements
    ## incorporate bcrypt to create a secure password. Attempts to access the password_hash should be met with an AttributeError.
    ## constrain the user's username to be present and unique (no two users can have the same username).
    ## have many recipes.

    # Hybrid property to raise AttributeError when accessing password hash directly
    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    # Setter for password hash using bcrypt
    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    # Method to authenticate user by comparing password hashes
    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f'User <{self.username}, ID: {self.id}>'

## Assignment Requirements
## Next, create a Recipe model with the following attributes:
## a recipe belongs to a user.
## id that is an integer type and a primary key.
## title that is a String type.
## instructions that is a String type.
## minutes_to_complete that is an Integer type.

# Recipe model for representing recipes in the database
class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    # Database constraints: instructions must be at least 50 characters long
    __table_args__ = (
        db.CheckConstraint('length(instructions) >= 50'), 
    )

    # Recipe attributes
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    # Relationship: Recipe belongs to a User
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<Recipe {self.id}: {self.title}>'