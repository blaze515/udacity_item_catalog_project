import json
import logging
import random
import string

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
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def show_login():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in
        range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
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
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
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
    new_user = User(name=login_session['username'],
                    email=login_session[
                        'email'], picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception as e:
        logging.exception(e)
        return None


def get_user_by_item_id(item_id):
    item = session.query(CatalogItem).filter_by(id=item_id).one()
    user = session.query(User).filter_by(id=item.user.id).one()
    return user


@app.route('/logout')
def logout():
    if 'username' in login_session:
        response = gdisconnect()
        if response is not None:
            login_session.clear()
            flash("Successfully disconnected")
        return redirect(url_for("show_catalog"))
    else:
        return redirect(url_for('show_catalog'))


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
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

        response = make_response(json.dumps('Successfully disconnected.'), 200)
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
    categories = session.query(Category).all()
    recent_items = session.query(CatalogItem).order_by(
        CatalogItem.id.desc()).limit(5).all()
    return render_template('catalog.html', categories=categories,
                           recent_items=recent_items)


@app.route("/catalog/<string:category>/items")
def show_catalog_items(category):
    categories = session.query(Category).all()
    current_category = session.query(Category).filter_by(name=category).one()
    catalog_items = session.query(CatalogItem).filter_by(
        category_name=category).all()
    return render_template('category_items.html', category=current_category,
                           items=catalog_items, categories=categories)


@app.route("/catalog/<string:category>/<string:item_name>")
def show_item_description(category, item_name):
    current_category = session.query(Category).filter_by(name=category).one()
    catalog_item = session.query(CatalogItem).filter_by(name=item_name).one()
    return render_template('item_description.html', category=current_category,
                           item=catalog_item)


@app.route("/catalog/<string:category>/<string:item_name>.json")
def show_item_json(category, item_name):
    catalog_item = session.query(CatalogItem).filter_by(name=item_name).one()
    return jsonify(item=catalog_item.serialize)


@app.route("/catalog/items.json")
def show_all_items_json():
    items = session.query(CatalogItem).all()
    return jsonify(items=[i.serialize for i in items])


@app.route("/catalog/new_category/", methods=['GET', 'POST'])
def new_category():
    if 'username' in login_session:
        if request.method == 'POST':
            category_name = request.form['category']
            add_category = Category(user_id=login_session['user_id'],
                                    name=category_name)
            session.add(add_category)
            session.commit()
            return redirect(
                url_for('show_catalog_items', category=category_name))
        else:
            return render_template('new_category.html')
    else:
        flash("You need to be logged in to do that.")
        return redirect(url_for('show_catalog'))


@app.route("/catalog/<string:item_name>/edit", methods=['GET', 'POST'])
def edit_item(item_name):
    edited_item = session.query(CatalogItem).filter_by(name=item_name).one()
    if 'username' in login_session:
        if login_session['user_id'] == get_user_by_item_id(
                edited_item.id).id:
            if request.method == 'POST':
                category_name = request.form['category']
                category = session.query(Category).filter_by(
                    name=category_name).one()
                edited_item.category = category
                edited_item.name = request.form['name']
                edited_item.description = request.form['description']
                session.commit()
                # flash('Item edited successfully)
                return redirect(
                    url_for('show_catalog_items', category=category.name))
            else:
                categories = session.query(Category).all()
                return render_template('edit_item.html', item=edited_item,
                                       categories=categories)
        else:
            flash("You can only edit items you created.")
            return redirect(
                url_for('show_catalog_items',
                        category=edited_item.category_name))
    else:
        flash("You need to be logged in to do that.")
        return redirect(url_for('show_catalog'))


@app.route("/catalog/new", methods=['GET', 'POST'])
def new_item():
    if 'username' in login_session:
        if request.method == 'POST':
            category_name = request.form['category']
            category = session.query(Category).filter_by(
                name=category_name).one()
            print("User ID: " + str(login_session['user_id']))
            user_id = login_session['user_id']
            print("user_id: " + str(user_id))
            user = session.query(User).filter_by(
                id=user_id).one()
            print("ID of new User: " + str(user.id))
            item = CatalogItem(name=request.form['name'],
                               description=request.form['description'],
                               category=category,
                               user=user)
            session.add(item)
            session.commit()
            # flash('New item successfully added to %s' % category.name)
            return redirect(
                url_for('show_catalog_items', category=category.name))
        else:
            categories = session.query(Category).all()
            return render_template('new_item.html', categories=categories)
    else:
        flash("You need to be logged in to do that.")
        return redirect(url_for('show_catalog'))


@app.route("/catalog/<string:item_name>/delete", methods=['GET', 'POST'])
def delete_item(item_name):
    item_to_delete = session.query(CatalogItem).filter_by(name=item_name).one()
    if 'username' in login_session:
        if login_session['user_id'] == get_user_by_item_id(
                item_to_delete.id).id:
            if request.method == 'POST':
                previous_category = item_to_delete.category_name
                session.delete(item_to_delete)
                session.commit()
                # flash('Item Successfully Deleted')
                return redirect(
                    url_for('show_catalog_items', category=previous_category))
            else:
                return render_template('delete_item.html', item=item_to_delete)
        else:
            flash("You can only delete items you created.")
            return redirect(
                url_for('show_catalog_items',
                        category=item_to_delete.category_name))
    else:
        flash("You need to be logged in to do that.")
        return redirect(url_for('show_catalog'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
