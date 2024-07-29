# from crypt import methods
from ast import Assign
from flask import Flask, render_template, redirect, url_for, session, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length
import pyodbc
import secrets
import hashlib  # Use hashlib for password hashing

app = Flask(__name__)

app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate and set secrets key

connection_string = (
    r'DRIVER={ODBC Driver 17 for SQL Server};'
    r'SERVER=(localdb)\MSSQLLocalDB;'
    r'DATABASE=ResourceManagementDB;'
    r'Trusted_Connection=yes;'
)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(),Length(min=4, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=50)])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('company', 'Company')], validators=[DataRequired()])
    submit = SubmitField('Register')
    

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=50)])
    submit = SubmitField('Login')

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_active_tasks():
    with pyodbc.connect(connection_string) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT TaskID, TaskName FROM Task WHERE IsActive = 1")
        return cursor.fetchall()
    
# Function to fetch available people
def get_available_people():
    with pyodbc.connect(connection_string) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID, Name FROM Users WHERE IsAbsent = 0")
        return cursor.fetchall()

# Function to activate a task
def activate_task(task_id):
    with pyodbc.connect(connection_string) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE Task SET IsActive = 1 WHERE TaskID = ?", task_id)
        conn.commit()

# Function to mark person as absent
def mark_absent(person_id, is_absent):
    with pyodbc.connect(connection_string) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE Users SET IsAbsent = ? WHERE ID = ?", is_absent, person_id)
        conn.commit()

# Function to get dashboard data
def get_dashboard():
    with pyodbc.connect(connection_string) as conn:
        cursor = conn.cursor()
        cursor.execute("""
           SELECT t.TaskName, u.UserName, a.IsCompleted,u.Id as UserId, u.IsAdmin, a.AssignmentID
           FROM Assignment a
           JOIN Task t ON a.TaskID = t.TaskID
           JOIN Users u ON a.PersonID = u.Id
           WHERE 
               t.IsActive = 1 
               AND a.AssignmentDate = '2024-07-25'
        """)
        
        # cursor.execute("""
        #     SELECT t.TaskName, u.UserName, a.IsCompleted, count(at.ApproverId) as IsCompletedCount
        #     FROM Assignment a
        #     JOIN Task t ON a.TaskID = t.TaskID
        #     JOIN Users u ON a.PersonID = u.Id
        #     left join ApprovalTable at on at.AssignmentId = a.AssignmentID
        #     WHERE 
	       #      t.IsActive = 1 
	       #      AND a.AssignmentDate = '2024-07-25'
        #     GROUP BY t.TaskName,
		      #        u.UserName,
		      #        a.IsCompleted
        # """)
        result = cursor.fetchall()
        print (result[0][0])
        return result



@app.route('/')
def Home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = hash_password(form.password.data)
        role = form.role.data 
        if role == 'admin':
            isAdmin = 1
        else:   
            isAdmin = 0
        print(username)
        with pyodbc.connect(connection_string) as conn:
            cursor = conn.cursor()
            cursor.execute("Insert into Users (username,password,role, isAdmin) Values (?, ?, ?, ?)", (username, password, role, isAdmin))
            conn.commit()
            return redirect(url_for('login'))
    return render_template('register.html',form=form)

    
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = hash_password(form.password.data)
        with pyodbc.connect(connection_string) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Users WHERE Username = ? AND Password = ?", (username, password))
            user = cursor.fetchone()
            cursor.execute("SELECT TaskID, TaskName FROM Task WHERE IsActive = 1")
            task = cursor.fetchall()
            

            if user:
                session['username'] = user.UserName  # Store username in session
                session['IsAdmin'] = user.IsAdmin  # Store role in session
                # print(session['role'])
                if user[3] == 'company':
                    print ("Hello from company")
                    if task:
                        print (task[0][0])
                        print (task[0][1])
                        # print (task[1])
                    else:
                        print ("no task")
                    return redirect(url_for('dashboard'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                return "Invalid credentials"
    return render_template('login.html',form = form)

@app.route('/welcome')
def welcome():
    username = session.get('username')  # Get username from session
    role = session.get('role')
    return render_template('welcome.html', username=username, role=role)


@app.route('/company')
def company():
    username = session.get('username')  # Get username from session
    role = session.get('role')
    return render_template('company.html', username=username, role=role)


@app.route('/dashboard')
def dashboard():
    dashboard_data = get_dashboard()
    # dashboard_data.IsCompletedCount
    # for i,task in enumerate(dashboard_data):        
    #     if task[3]>=2:
    #         print(task.IsCompletedCount)
    #         updated_task = (task[0],task[1],task[2],1)
    #     else:
    #         updated_task = (task[0],task[1],task[2],0)
    #     dashboard_data[i]=updated_task    
    # print(dashboard_data)   
    isAdmin = session.get('IsAdmin')
    print(isAdmin )   

    return render_template('dashboard.html', dashboard=dashboard_data, isAdmin=isAdmin)

@app.route('/toggle_task_status',methods=["POST"])
def toggle_task_status():
    assignment_id = request.form.get('assignment_id')
    print(assignment_id)
    with pyodbc.connect(connection_string) as conn:
         cursor = conn.cursor()
         cursor.execute('UPDATE Assignment SET IsCompleted = ~IsCompleted WHERE AssignmentID = ?',assignment_id)    
         conn.commit()
         print("in the completed method")
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)