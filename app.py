from flask import Flask,render_template


app = Flask(__name__)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')


@app.route('/contactus')
def contactus():
    return render_template('contactus.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/result')
def result():
    return render_template('result.html')



if __name__ == '__main__':
    app.run(debug=True)
