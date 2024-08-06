import pandas as pd
import numpy as np
import pickle
import os
import logging
from flask import Flask, request, render_template, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import redirect, url_for


app = Flask(__name__, template_folder="templates")
app.config['SECRET_KEY'] = '2ece243aa5bfad295dca55d8b38cdbcd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_admin_user():
    admin_username = "admin"
    admin_password = "12345"
    
    # Check if admin user already exists
    admin_user = User.query.filter_by(username=admin_username).first()
    if not admin_user:
        admin_user = User(username=admin_username, password=generate_password_hash(admin_password, method='pbkdf2:sha256'))
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created")

#@app.route('/', methods=['GET'])
#def index():
 #   return render_template('index1.html')

@app.route('/home', methods=['GET'])
def about():
    return render_template('index1.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            app.logger.info(f"User {username} logged in successfully")
            return redirect(url_for('upload'))  # Changed from 'pred' to 'upload'
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
        else:
            new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('predict'))
    return render_template('signup.html')

#logout code
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/pred', methods=['GET'])
@login_required
def upload():
    app.logger.info("Entered /pred route")
    try:
        return render_template('upload.html')
    except Exception as e:
        app.logger.error(f"Error in /pred route: {str(e)}")
        return "An error occurred", 500
    
@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    try:
        logging.info("[INFO] Loading model...")
        model_path = "fdemandnew.pkl"
        if not os.path.exists(model_path):
            logging.error(f"Model file {model_path} not found.")
            return jsonify({"error": "Model file not found."})
        
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        if request.method == 'POST':
            y = request.form.values()
            input_features = []
            logging.debug(f"Form values: {y}")
            for x in y:
                try:
                    logging.debug(f"Processing value: {x}")
                    input_features.append(float(x))
                except ValueError:
                    logging.error(f"Invalid input value: {x}")
                    return jsonify({"error": f"Invalid input value: {x}"})
            logging.debug(f"Input features: {input_features}")
            if len(input_features) == 0:
                logging.error("No valid input features provided.")
                return jsonify({"error": "No valid input features provided."})
            features_value = [np.array(input_features)]
            logging.debug(f"Features value array: {features_value}")
            prediction = model.predict(features_value)
            output = prediction[0]
            logging.debug(f"Prediction output: {output}")
            return jsonify({"prediction": float(output)})
        return render_template('upload.html')
    except Exception as e:
        app.logger.error(f"Error in /predict route: {str(e)}")
        return jsonify({"error": "An error occurred during prediction."})


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('upload'))
    return redirect(url_for('login'))

#@app.route('/logout', methods=['POST'])
#@login_required
#def logout():
    #logout_user()
    #return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()  #Call this function to create admin user
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
