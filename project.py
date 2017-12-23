import json
import logging
import random
import string
from functools import wraps

import httplib2
import requests
from flask import Flask, render_template, request, redirect, url_for, flash
from flask import make_response, jsonify
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category, CatalogItem, User

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('/var/www/catalog/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

# Connect to Database and create database session
engine = create_engine('postgresql://catalog:catalog@localhost:5432/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def show_login():
    """ Method to display the login page to a user"""
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in
        range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


def login_required(f):
    """ Code to create a login decorator """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('show_login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ Method to log a user in through Google OAuth2"""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('/var/www/catalog/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 300px; height: 300px;border-radius: ' \
              '150px;-webkit-border-radius: 150px;-moz-border-radius: ' \
              '150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


# User Helper Functions
def create_user(login_session):
    """ A helper function to create a new user"""
    new_user = User(name=login_session['username'],
                    email=login_session[
                        'email'], picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    """ A helper method to return a user object for getting user info"""
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    """ A helper method to get a user id from the user's email"""
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception as e:
        logging.exception(e)
        return None


def get_user_by_item_id(item_id):
    """ A helper method to get the user who created an item by using the
    catalog item's ID"""
    item = session.query(CatalogItem).filter_by(id=item_id).one()
    user = session.query(User).filter_by(id=item.user.id).one()
    return user


@app.route('/logout')
@login_required
def logout():
    """ A method to log a user out and clear the login session"""
    response = gdisconnect()
    if response is not None:
        login_session.clear()
        flash("Successfully disconnected")
    return redirect(url_for("show_catalog"))


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
@login_required
def gdisconnect():
    """ A method to disconnect a user logged in through Google OAuth2"""
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % \
          access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']

        login_session.clear()

        response = make_response(json.dumps('Successfully disconnected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route("/")
@app.route("/catalog")
def show_catalog():
    """ A method to display the main catalog page or home page"""
    categories = session.query(Category).all()
    recent_items = session.query(CatalogItem).order_by(
        CatalogItem.id.desc()).limit(5).all()
    return render_template('catalog.html', categories=categories,
                           recent_items=recent_items)


@app.route("/catalog/<string:category>/items")
def show_catalog_items(category):
    """ A method to display the items in a specific catalog category """
    categories = session.query(Category).all()
    current_category = session.query(Category).filter_by(name=category).one()
    catalog_items = session.query(CatalogItem).filter_by(
        category_name=category).all()
    return render_template('category_items.html', category=current_category,
                           items=catalog_items, categories=categories)


@app.route("/catalog/<string:category>/<string:item_name>")
def show_item_description(category, item_name):
    """ A method to display information about a specific catalog item """
    current_category = session.query(Category).filter_by(name=category).one()
    catalog_item = session.query(CatalogItem).filter_by(name=item_name).one()
    return render_template('item_description.html', category=current_category,
                           item=catalog_item)


@app.route("/catalog/<string:category>/<string:item_name>.json")
def show_item_json(category, item_name):
    """ A JSON endpoint to display information about a specific catalog
    item """
    catalog_item = session.query(CatalogItem).filter_by(name=item_name).one()
    return jsonify(item=catalog_item.serialize)


@app.route("/catalog/items.json")
def show_all_items_json():
    """ A JSON endpoint to display information about all catalog items"""
    items = session.query(CatalogItem).all()
    return jsonify(items=[i.serialize for i in items])


@app.route("/catalog/new_category/", methods=['GET', 'POST'])
@login_required
def new_category():
    """ A method to create a new category, if the user is logged in"""
    if request.method == 'POST':
        # Add the category to the db and redirect to new category page
        category_name = request.form['category']
        add_category = Category(user_id=login_session['user_id'],
                                name=category_name)
        session.add(add_category)
        session.commit()
        return redirect(
            url_for('show_catalog_items', category=category_name))
    else:
        # Display the page to create a new category
        return render_template('new_category.html')


@app.route("/catalog/<string:item_name>/edit", methods=['GET', 'POST'])
@login_required
def edit_item(item_name):
    """ A method to edit an item, if the user is logged in"""
    edited_item = session.query(CatalogItem).filter_by(name=item_name).one()
    # Check to make sure only the creator can edit their item
    if login_session['user_id'] == get_user_by_item_id(
            edited_item.id).id:
        if request.method == 'POST':
            # Update db and redirect to current category's items page
            category_name = request.form['category']
            category = session.query(Category).filter_by(
                name=category_name).one()
            edited_item.category = category
            edited_item.name = request.form['name']
            edited_item.description = request.form['description']
            session.commit()
            flash('Item edited successfully')
            return redirect(
                url_for('show_catalog_items', category=category.name))
        else:
            # Display the page to make updates and pre-populate
            categories = session.query(Category).all()
            return render_template('edit_item.html', item=edited_item,
                                   categories=categories)
    else:
        # Redirect user, since they didn't create the item
        flash("You can only edit items you created.")
        return redirect(
            url_for('show_catalog_items',
                    category=edited_item.category_name))


@app.route("/catalog/new", methods=['GET', 'POST'])
@login_required
def new_item():
    """ A method to create a new catalog item. A user must be logged in to
    be able to create an item."""
    if request.method == 'POST':
        # Add item to db and redirect to current category's items page
        category_name = request.form['category']
        category = session.query(Category).filter_by(
            name=category_name).one()
        user_id = login_session['user_id']
        user = session.query(User).filter_by(
            id=user_id).one()
        item = CatalogItem(name=request.form['name'],
                           description=request.form['description'],
                           category=category,
                           user=user)
        session.add(item)
        session.commit()
        flash('New item successfully added to %s' % category.name)
        return redirect(
            url_for('show_catalog_items', category=category.name))
    else:
        # Display the page to create a new item
        categories = session.query(Category).all()
        return render_template('new_item.html', categories=categories)


@app.route("/catalog/<string:item_name>/delete", methods=['GET', 'POST'])
@login_required
def delete_item(item_name):
    """ Method to delete an item. Only the user who created the item can
    delete it."""
    item_to_delete = session.query(CatalogItem).filter_by(
        name=item_name).one()
    # Verify user is the item's creator, since user's can't delete other
    # user's items.
    if login_session['user_id'] == get_user_by_item_id(
            item_to_delete.id).id:
        if request.method == 'POST':
            # Delete the item and redirect to the list of catalog items
            previous_category = item_to_delete.category_name
            session.delete(item_to_delete)
            session.commit()
            flash('Item Successfully Deleted')
            return redirect(
                url_for('show_catalog_items', category=previous_category))
        else:
            # Display delete confirmation
            return render_template('delete_item.html',
                                   item=item_to_delete)
    else:
        # Redirect since the user didn't create the item
        flash("You can only delete items you created.")
        return redirect(
            url_for('show_catalog_items',
                    category=item_to_delete.category_name))


if __name__ == '__main__':
    """ Setting up app properties: secret_key, host, port, etc."""
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
