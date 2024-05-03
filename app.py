from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from pymongo import MongoClient
from bson.json_util import dumps
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message, email_dispatched
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from authlib.integrations.flask_client import OAuth


app = Flask(__name__)


app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'



# MongoDB configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/mydatabase"
mongo = PyMongo(app)

users_collection = mongo.db.users
users_queries = mongo.db.contactus


# Okta OAuth configuration
OKTA_CLIENT_ID = 'a3BolZLieoX9d3Ocvwv3M0YPXKep0bg4'
OKTA_CLIENT_SECRET = '7u2D2RNVC46fJ96GJogz6pyd_OYO79J6Wn7zsMOJT8IWidLOAnjUK8eTJg02pFr7'
OKTA_DOMAIN = 'dev-5fvfbhr5pvs5n6tm.us.auth0.com'
OKTA_REDIRECT_URI = 'http://localhost:5000/okta-callback'

oauth = OAuth(app)
okta = oauth.register(
    'okta',
    client_id=OKTA_CLIENT_ID,
    client_secret=OKTA_CLIENT_SECRET,
    authorize_url=f'https://{OKTA_DOMAIN}/oauth2/v1/authorize',
    authorize_params=None,
    access_token_url=f'https://{OKTA_DOMAIN}/oauth2/v1/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri=OKTA_REDIRECT_URI,
    client_kwargs={'scope': 'openid profile email'}
)



def get_first_name():
    """
    Fetch the first name of the logged-in user from the database.
    """
    if session.get('logged_in'):
        user_email = session['email']
        user = users_collection.find_one({'email': user_email})
        if user:
            return user.get('first_name', '')
    return ''



@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login'))
        else:
            # Process the search query and redirect to the result page
            search_query = request.form.get('inp')
            return redirect(url_for('result', search_query=search_query))
    else:
        # Fetch the first name using the method
        first_name = get_first_name()

        # Render the home template with the logged_in status and first name
        return render_template('home.html', logged_in=session.get('logged_in', False), first_name=first_name)





@app.route('/thanks')
def thanks():
    return render_template('thanks.html')


@app.route('/aboutus')
def aboutus():
    # Fetch the first name using the method
    first_name = get_first_name()
    return render_template('aboutus.html',first_name=first_name)


@app.route('/contactus', methods=['GET', 'POST'])
def contactus():
    if request.method == 'POST':
        # Retrieve form data
        full_name = request.form['full_name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        
        # Use correct field names when inserting into MongoDB
        query = {'full_name': full_name, 'email': email, 'subject': subject, 'message': message}
        users_queries.insert_one(query)
        return redirect(url_for('thanks'))
    else:
        # Fetch the first name using the method
        first_name = get_first_name()
        return render_template('contactus.html', first_name=first_name)




@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        print(email)
        print(password)
        # Check if user exists
        user = users_collection.find_one({'email': email})
        if not user:
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # Check if password is correct
        if not check_password_hash(user['password'], password):
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # Set session variable to indicate user is logged in
        session['logged_in'] = True
        session['email'] = email
        # Redirect to home page after successful login
        return redirect(url_for('home'))
    else:
        return render_template('login.html')


@app.route('/google-login')
def google_login():
    return okta.authorize_redirect(redirect_uri=OKTA_REDIRECT_URI)

@app.route('/okta-callback')
def okta_callback():
    token = okta.authorize_access_token()
    userinfo = okta.parse_id_token(token)
    session['logged_in'] = True
    session['email'] = userinfo['email']
    return redirect(url_for('home'))




@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        data = request.get_json()
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        # Check if email already exists
        if users_collection.find_one({'email': email}):
            return jsonify({'message': 'Email already exists'}), 400
        
        # Check if passwords match
        if password != confirm_password:
            return jsonify({'message': 'Passwords do not match'}), 400
        
        # Hash password before storing it
        hashed_password = generate_password_hash(password)
        
        # Store user in the database
        user = {'first_name': first_name, 'last_name': last_name, 'email': email, 'password': hashed_password}
        users_collection.insert_one(user)
        # Set session variables to indicate user is logged in
        session['logged_in'] = True
        session['email'] = email
        # Redirect to home page after successful sign up
        return redirect(url_for('home'))
    else:
        return render_template('signup.html')


@app.route('/logout')
def logout():
    # Remove session variable to log out the user
    session.pop('logged_in', None)
    return redirect(url_for('home'))

@app.route('/result')
def result():
    # Fetch the first name using the method
    first_name = get_first_name()
    return render_template('result.html',first_name=first_name)


@app.route('/adminlogin', methods=['GET', 'POST'])
def adminlogin():
    if request.method == 'POST':
        password = request.form['password']
        if password == "ImagineXTeam@1234":
            # Fetch all contact queries from the database
            contact_queries = users_queries.find()
            # Render the admin login template with the contact queries
            return render_template('adminlogin.html', contact_queries=contact_queries)
        else:
            return "Invalid password"
    else:
        return render_template('adminlogin.html')


if __name__ == '__main__':
    app.run(debug=True)
