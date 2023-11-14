import os
import os.path
from flask import Flask, request, redirect, url_for, render_template, session , send_from_directory, send_file, redirect
from werkzeug.utils import secure_filename
import DH
import pickle
import random

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
# Import additional libraries
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt



UPLOAD_FOLDER = './media/text-files/'
UPLOAD_KEY = './media/public-keys/'
ALLOWED_EXTENSIONS = set(['txt'])

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # SQLite database
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

'''db = SQLAlchemy(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
'''

def allowed_file(filename):
	return '.' in filename and \
		filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/dashboard', methods=['GET', 'POST'])
#@login_required
def dashboard():
    return render_template('dashboard.html')
























# Define your SQLAlchemy model for the User table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


db.create_all()

# Your routes go here


# Registration route
@app.route('/register1', methods=['GET', 'POST'])
def register1():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if the email or phone is already in use
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email is already registered.', 'danger')
            return redirect(url_for('register1'))

        existing_user = User.query.filter_by(phone=phone).first()
        if existing_user:
            flash('Phone number is already registered.', 'danger')
            return redirect(url_for('register1'))

        # Check if the passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register1'))

        # Hash the password before storing it in the database
        hashed_password = generate_password_hash(password, method='sha256')

        # Create a new User record and add it to the database
        new_user = User(name=name, email=email, phone=phone, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('registration.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']

        user = User.query.filter_by(email=email).first() or User.query.filter_by(phone=phone).first()

        if user and check_password_hash(user.password, password):
            # Log in the user
            session['user_id'] = user.id
            flash('Login successful.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your email/phone and password.', 'danger')

    return render_template('login.html')

# Index route
@app.route('/')
def index():
    return render_template('home.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))



'''
-----------------------------------------------------------
					PAGE REDIRECTS
-----------------------------------------------------------
'''

def post_upload_redirect():
	return render_template('post-upload.html')

@app.route('/register')
def call_page_register_user():
	return render_template('register.html')

@app.route('/home')
def back_home():
	return render_template('home.html')
'''
@app.route('/')
def index():
	return render_template('home.html')'''

@app.route('/upload-file')
def call_page_upload():
	return render_template('upload.html')


'''
-----------------------------------------------------------
				DOWNLOAD KEY-FILE
-----------------------------------------------------------
'''
@app.route('/public-key-directory/retrieve/key/<username>')
def download_public_key(username):
	for root,dirs,files in os.walk('./media/public-keys/'):
		for file in files:
			list = file.split('-')
			if list[0] == username:
				filename = UPLOAD_KEY+file
				return send_file(filename, attachment_filename='publicKey.pem',as_attachment=True)

@app.route('/file-directory/retrieve/file/<filename>')
def download_file(filename):
	filepath = UPLOAD_FOLDER+filename
	if(os.path.isfile(filepath)):
		return send_file(filepath, attachment_filename='Encrypted-File.txt',as_attachment=True)
	else:
		return render_template('file-list.html',msg='An issue encountered, our team is working on that')

'''
-----------------------------------------------------------
		BUILD - DISPLAY FILE - KEY DIRECTORY
-----------------------------------------------------------
'''
# Build public key directory
@app.route('/public-key-directory/')
def downloads_pk():
	username = []
	if(os.path.isfile("./media/database/database_1.pickle")):
		pickleObj = open("./media/database/database_1.pickle","rb")
		username = pickle.load(pickleObj)
		pickleObj.close()
	if len(username) == 0:
		return render_template('public-key-list.html',msg='Aww snap! No public key found in the database')
	else:
		return render_template('public-key-list.html',msg='',itr = 0, length = len(username),directory=username)

# Build file directory
@app.route('/file-directory/')
def download_f():
	for root,dirs,files in os.walk(UPLOAD_FOLDER):
		if(len(files) == 0):
			return render_template('file-list.html',msg='Aww snap! No file found in directory')
		else:
			return render_template('file-list.html',msg='',itr=0,length=len(files),list=files)

'''
-----------------------------------------------------------
				UPLOAD ENCRYPTED FILE
-----------------------------------------------------------
'''

@app.route('/data', methods=['GET', 'POST'])
def upload_file():
	if request.method == 'POST':
		# check if the post request has the file part
		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
		# if user does not select file, browser also
		# submit a empty part without filename
		if file.filename == '':
			flash('No selected file')
			return 'NO FILE SELECTED'
		if file:
			filename = secure_filename(file.filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
			return post_upload_redirect()
		return 'Invalid File Format !'

'''
-----------------------------------------------------------
REGISTER UNIQUE USERNAME AND GENERATE PUBLIC KEY WITH FILE
-----------------------------------------------------------
'''
@app.route('/register-new-user', methods = ['GET', 'POST'])
def register_user():
	files = []
	privatekeylist = []
	usernamelist = []
	# Import pickle file to maintain uniqueness of the keys
	if(os.path.isfile("./media/database/database.pickle")):
		pickleObj = open("./media/database/database.pickle","rb")
		privatekeylist = pickle.load(pickleObj)
		pickleObj.close()
	if(os.path.isfile("./media/database/database_1.pickle")):
		pickleObj = open("./media/database/database_1.pickle","rb")
		usernamelist = pickle.load(pickleObj)
		pickleObj.close()
	# Declare a new list which consists all usernames 
	if request.form['username'] in usernamelist:
		return render_template('register.html', name='Username already exists')
	username = request.form['username']
	firstname = request.form['first-name']
	secondname = request.form['last-name']
	pin = int(random.randint(1,128))
	pin = pin % 64
	#Generating a unique private key
	privatekey = DH.generate_private_key(pin)
	while privatekey in privatekeylist:
		privatekey = DH.generate_private_key(pin)
	privatekeylist.append(str(privatekey))
	usernamelist.append(username)
	#Save/update pickle
	pickleObj = open("./media/database/database.pickle","wb")
	pickle.dump(privatekeylist,pickleObj)
	pickleObj.close()
	pickleObj = open("./media/database/database_1.pickle","wb")
	pickle.dump(usernamelist,pickleObj)
	pickleObj.close()
	#Updating a new public key for a new user
	filename = UPLOAD_KEY+username+'-'+secondname.upper()+firstname.lower()+'-PublicKey.pem'
	# Generate public key and save it in the file generated
	publickey = DH.generate_public_key(privatekey)
	fileObject = open(filename,"w")
	fileObject.write(str(publickey))
	return render_template('key-display.html',privatekey=str(privatekey))


	
if __name__ == '__main__':
#app.run(host="0.0.0.0", port=80)
	app.run(debug=True)
