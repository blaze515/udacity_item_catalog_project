# Udacity Item Catalog Project

This project is an item catalog. After the database has been setup and populated, the default catalog has a categories for Books, Shoes, and Music. The app allows users who are not signed in to see the catalog, browse categories, and view individual items. Users who are signed in, can add categories, add items, edit items, and delete items. Sign in uses OAuth2 authentication from Google. The application uses the following technologies:
  -[Flask](http://flask.pocoo.org/)
  -[SQLAlchemy](http://flask-sqlalchemy.pocoo.org/2.3/)
  -[Google OAuth2](https://developers.google.com/identity/protocols/OAuth2)
  -[Vagrant](https://www.vagrantup.com/docs/virtualbox/)

Prerequisites
1. Vagrant/Virtualbox
3. Python 3.5

How to Run the Project

Setting Up OAuth 2.0
1. You will need to signup for a google account and set up a client id and secret.
2. Visit http://console.developers.google.com for google setup.

Setting Up the Project

1. Clone or download the repository into the vagrant shared directory.
2. In a conseole, type the following commands:
  - vagrant up
  - vagrant ssh
3. Once vagrant is up, type the following command:
  - cd /vagrant/catalog
4. Run python3 database_setup.py to create the catalog database.
5. Run python3 catalog_items.py to create the initial categories and items.
6. Run python3 project.py to run the program.
7. In a web browser, navigate to http://localhost:8000/catalog.

Note: The running project also includes two JSON API endpoints that can be accessed by using the following urls.
1. JSON for a specific item -- http://localhost:8000/catalog/{category_name}/{item_name}.json
2. JSON for all items in catalog -- http://localhost:8000/items.json

References
https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004
