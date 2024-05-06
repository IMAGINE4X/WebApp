import pyrebase
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
from datetime import datetime
import firebase_admin
from firebase_admin import auth 
from flask_sslify import SSLify
import json
import requests
from authlib.integrations.flask_client import OAuth


app = Flask(__name__)
sslify = SSLify(app)




appConf = {
    "OAUTH2_CLIENT_ID": "1091458009156-39a3fudhvmt6romqn0sc4etl7drcrg6d.apps.googleusercontent.com",
    "OAUTH2_CLIENT_SECRET": "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",
    "OAUTH2_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": "ALongRandomlyGeneratedString",
    "FLASK_PORT": 5000
}
app.secret_key = appConf.get("FLASK_SECRET")
oauth = OAuth(app)
oauth.register(
    "myApp",
    client_id=appConf.get("OAUTH2_CLIENT_ID"),
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email https://www.googleapis.com/auth/user.birthday.read https://www.googleapis.com/auth/user.gender.read",
        # 'code_challenge_method': 'S256'  # enable PKCE
    },
    server_metadata_url=f'{appConf.get("OAUTH2_META_URL")}',
)


# Configuration for Firebase
config = {
    "apiKey": "AIzaSyDP0D0TBsKSx36UvMS1YSuqmoKjSXO9H9Q",
    "authDomain": "imaginex-ac5dc.firebaseapp.com",
    "databaseURL": "https://imaginex-ac5dc-default-rtdb.asia-southeast1.firebasedatabase.app",
    "projectId": "imaginex-ac5dc",
    "storageBucket": "imaginex-ac5dc.appspot.com",
    "messagingSenderId": "1091458009156",
    "appId": "1:1091458009156:web:4084638961adb99e931411",
    "measurementId": "G-VRJY5JFX9J"
}

# Initialize Firebase
firebase = pyrebase.initialize_app(config)

# Get reference to the auth service and database service
auth = firebase.auth()
db = firebase.database()




def get_first_name():
    """
    Fetch the first name of the logged-in user from the database.
    """
    if session.get('logged_in'):
        user_email = session['email']
        try:
            users = db.child("users").get().val()
            if users:
                for uid, user_data in users.items():
                    if user_data.get('email') == user_email:
                        full_name = user_data.get('name', '')
                        first_name = full_name.split()[0] if full_name else ''
                        return first_name
        except Exception as e:
            print("Error fetching user data:", e)
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
        
        if 'Google-login' in session:
            first_name = session["name"]
                
        else: # Fetch the first name using the method
            first_name = get_first_name()

        # Render the home template with the logged_in status and first name
        return render_template('home.html', logged_in=session.get('logged_in', False), first_name=first_name)





@app.route('/thanks')
def thanks():
    return render_template('thanks.html')


@app.route('/aboutus')
def aboutus():
    # Fetch the first name using the method
    if 'Google-login' in session:
            first_name = session["name"]
                
    else: # Fetch the first name using the method
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
        
        try:
            # Save the form data to Firebase
            data = {
                'full_name': full_name,
                'email': email,
                'subject': subject,
                'message': message
            }
            db.child('contact_queries').push(data)  # Assuming 'contact_queries' is the node to store contact queries
            return redirect(url_for('thanks'))
        except Exception as e:
            print("Error saving contact query:", e)
            # Handle the error, maybe show an error message to the user
            return render_template('contactus.html', error_message="Error saving contact query")
    else:
        if 'Google-login' in session:
            first_name = session["name"]
                
        else: # Fetch the first name using the method
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
        try:
            # Authenticate user
            user = auth.sign_in_with_email_and_password(email, password)
            session["logged_in"] = True
            session["email"] = user["email"]
            session["uid"] = user["localId"]
            # Fetch user data
            data = db.child("users").get().val()
            # Update session data
            if data and session["uid"] in data:
                session["name"] = data[session["uid"]]["name"]
                # Update last login time
                db.child("users").child(session["uid"]).update({"last_logged_in": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")})
            else:
                session["name"] = "User"
            # Redirect to welcome page
            return redirect(url_for('home'))
        except Exception as e:
            print("Error occurred: ", e)
            return redirect(url_for('login'))
    else:
        return render_template('login.html')




@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        data = request.get_json()
        app.logger.info("Received data: %s", data)  # Log the received data
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        # Check if passwords match
        if password != confirm_password:
            return jsonify({'message': 'Passwords do not match'}), 400
        
        full_name = first_name + " " + last_name
        try:
            # Create user account
            auth.create_user_with_email_and_password(email, password)
            # Authenticate user
            user = auth.sign_in_with_email_and_password(email, password)
            session["logged_in"] = True
            session["email"] = user["email"]
            session["uid"] = user["localId"]
            session["name"] = full_name
            # Save user data
            data = {"name": full_name, "email": email, "last_logged_in": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")}
            db.child("users").child(session["uid"]).set(data)
            return redirect(url_for('home'))
        except Exception as e:
            print("Error occurred during registration: ", e)
            return redirect(url_for('signup'))
    else:
        return render_template('signup.html')





# Route for password reset
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form["email"]
        try:
            # Send password reset email
            auth.send_password_reset_email(email)
            return render_template("reset_password_done.html")  # Show a page telling user to check their email
        except Exception as e:
            print("Error occurred: ", e)
            return render_template("reset_password.html", error="An error occurred. Please try again.")  # Show error on reset password page
    else:
        return render_template("resetpassword.html")


@app.route("/logout")
def logout():
    if 'Google-login' in session:
        session.pop('logged_in', None)
        session.pop('Google-login',None)
        session.pop('user',None)
    else:
        db.child("users").child(session["uid"]).update({"last_logged_out": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")})
        session.pop('logged_in', None)
    return redirect(url_for('home'))

@app.route('/result')
def result():
    # Fetch the first name using the method
    first_name = get_first_name()
    return render_template('result.html',first_name=first_name)


@app.route('/admindashboard', methods=['GET', 'POST'])
def admindashboard():
    if request.method == 'POST':
        password = request.form['password']
        if password == "ImagineXTeam@1234":
            try:
                # Fetch all contact queries from the Firebase database
                contact_queries = db.child('contact_queries').get().val()
                print("Contact Queries:", contact_queries)  # Print contact queries to the console
                
                # Extract required data from contact_queries
                formatted_queries = []
                for query_id, query_data in contact_queries.items():
                    formatted_query = {
                        'full_name': query_data['full_name'],
                        'email': query_data['email'],
                        'subject': query_data['subject'],  # Subject before message
                        'message': query_data['message']
                    }
                    formatted_queries.append(formatted_query)
                print("Formatted Queries:", formatted_queries)
                # Render the admin dashboard template with the formatted contact queries
                return render_template('admindashboard.html', contact_queries=formatted_queries)
            except Exception as e:
                print("Error fetching contact queries:", e)
                # Handle the error, maybe show an error message to the user
                return render_template('admindashboard.html', error_message="Error fetching contact queries")
        else:
            return "Invalid password"
    else:
        return render_template('admindashboard.html')



@app.route("/signin-google")
def googleCallback():
    # fetch access token and id token using authorization code
    token = oauth.myApp.authorize_access_token()

    # google people API - https://developers.google.com/people/api/rest/v1/people/get
    # Google OAuth 2.0 playground - https://developers.google.com/oauthplayground
    # make sure you enable the Google People API in the Google Developers console under "Enabled APIs & services" section

    # fetch user data with access token
    personDataUrl = "https://people.googleapis.com/v1/people/me?personFields=genders,birthdays,names"
    personData = requests.get(personDataUrl, headers={
        "Authorization": f"Bearer {token['access_token']}"
    }).json()
    token["personData"] = personData
    # set complete user information in the session
    # extract relevant user information
    print("Person Data:", personData)
    user_info = {
        "name": personData.get("names", [{"displayName": "Unknown"}])[0].get("displayName", "Unknown"),
        "email": personData.get("emailAddresses", [{"value": "Unknown"}])[0].get("value", "Unknown"),
        "profile_picture": personData.get("photos", [{"url": ""}])[0].get("url", "")
    }
    
    session["user"] = user_info
    return redirect(url_for("getuname"))

@app.route("/google-login")
def googleLogin():
    if "user" in session and "Google-login" in session:
        abort(404)
    return oauth.myApp.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))


@app.route("/get-uname",methods=['GET','POST'])
def getuname():
    if "user" in session:
        if request.method == 'POST':
            full_name = request.form['name']
            session["logged_in"] = True
            session["Google-login"] = True
            session["name"] = full_name
            return redirect(url_for("home"))
        else:
            return render_template('get-uname.html')
    else:
        abort(404)

if __name__ == '__main__':
    app.run(debug=True)
