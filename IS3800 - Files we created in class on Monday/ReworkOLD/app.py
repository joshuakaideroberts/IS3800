#!/usr/bin/env python3
import random
from datetime import datetime
from flask import Flask, render_template_string, request, redirect, url_for
from markupsafe import Markup
import configparser
import mysql.connector
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

# Read configuration from file
config = configparser.ConfigParser()
configFile = '/Users/samtanner/Desktop/Final Project IS3800/IS3800/IS3800/Rework/contacts.cfg'
config.read(configFile)
database = config['database']
db = database['db']
dbHost = database['host']
dbUser = database['user']
dbPass = database['pass']

# Database connection
cnx = mysql.connector.connect(user=dbUser, password=dbPass, host=dbHost, database=db)

app = Flask(__name__)

# Basic authentication setup
webAuth = config['httpAuth']
httpUser = webAuth['user']
httpPass = webAuth['pass']

auth = HTTPBasicAuth()
users = {httpUser: generate_password_hash(httpPass)}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

# Base template string
base_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ titleText }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f9; }
        h1 { color: #333; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .content { padding: 20px; }
    </style>
</head>
<body>
    <div class="content">
        <h1>{{ titleText }}</h1>
        <div>{{ bodyText | safe }}</div>
    </div>
</body>
</html>
"""

# Home page
@app.route('/')
def home():
    titleText = "Welcome to the Interactive Reference Tool"
    bodyText = """
        <p>This is a simple app where you can explore topics covered in class.</p>
        <a href="/login">Login</a>
    """
    return render_template_string(base_template, titleText=titleText, bodyText=bodyText)

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check credentials
        if username in users and check_password_hash(users[username], password):
            return redirect(url_for('dashboard'))
        else:
            titleText = "Login"
            bodyText = """
                <p style="color:red;">Invalid credentials. Please try again.</p>
                <form method="POST">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required><br><br>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required><br><br>
                    <button type="submit">Login</button>
                </form>
            """
            return render_template_string(base_template, titleText=titleText, bodyText=bodyText)
    
    titleText = "Login"
    bodyText = """
        <form method="POST">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br><br>
            <button type="submit">Login</button>
        </form>
    """
    return render_template_string(base_template, titleText=titleText, bodyText=bodyText)

# Dashboard page (after login)
@app.route('/dashboard')
@auth.login_required
def dashboard():
    titleText = "Class Topics Dashboard"
    bodyText = """
        <h2>Welcome to the Interactive Reference Tool</h2>
        <p>Click on the topics below to explore:</p>
        <ul>
            <li><a href="/sql_injection">SQL Injection</a></li>
            <li><a href="/cross_site_scripting">Cross-Site Scripting (XSS)</a></li>
            <li><a href="/database_normalization">Database Normalization</a></li>
        </ul>
        <br><a href="/">Home</a>
    """
    return render_template_string(base_template, titleText=titleText, bodyText=bodyText)

# SQL Injection explanation page
@app.route('/sql_injection')
def sql_injection():
    titleText = "SQL Injection"
    bodyText = """
        <h3>What is SQL Injection?</h3>
        <p>SQL Injection is a code injection technique that exploits a vulnerability in an application's software by manipulating SQL queries.</p>
        <h4>Types of SQL Injection:</h4>
        <ul>
            <li><b>In-band SQL Injection:</b> The attacker uses the same channel to launch the attack and gather the results.</li>
            <li><b>Inferential SQL Injection:</b> The attacker sends data to the server, observing the server's response to determine if the query was successful.</li>
            <li><b>Out-of-band SQL Injection:</b> The attacker relies on the database server's ability to make DNS or HTTP requests to retrieve data.</li>
        </ul>
        <p><a href="/dashboard">Back to Dashboard</a></p>
    """
    return render_template_string(base_template, titleText=titleText, bodyText=bodyText)

# Cross-Site Scripting (XSS) explanation page
@app.route('/cross_site_scripting')
def cross_site_scripting():
    titleText = "Cross-Site Scripting (XSS)"
    bodyText = """
        <h3>What is XSS?</h3>
        <p>Cross-Site Scripting (XSS) is a vulnerability that allows an attacker to inject malicious scripts into web pages viewed by other users.</p>
        <h4>Types of XSS:</h4>
        <ul>
            <li><b>Stored XSS:</b> The malicious script is stored on the server and delivered to the victim whenever they access the vulnerable page.</li>
            <li><b>Reflected XSS:</b> The malicious script is reflected off a web server, typically as part of a query string or HTTP response.</li>
            <li><b>DOM-based XSS:</b> The attack is executed when the page's client-side JavaScript processes the input, and it is not properly sanitized.</li>
        </ul>
        <p><a href="/dashboard">Back to Dashboard</a></p>
    """
    return render_template_string(base_template, titleText=titleText, bodyText=bodyText)

# Database Normalization explanation page
@app.route('/database_normalization')
def database_normalization():
    titleText = "Database Normalization"
    bodyText = """
        <h3>What is Database Normalization?</h3>
        <p>Database normalization is the process of organizing the attributes and tables of a relational database to minimize redundancy and dependency.</p>
        <h4>Types of Normal Forms:</h4>
        <ul>
            <li><b>First Normal Form (1NF):</b> Ensures that each column contains atomic values, meaning there are no repeating groups of columns.</li>
            <li><b>Second Normal Form (2NF):</b> Meets all the requirements of 1NF and removes partial dependencies between attributes and the primary key.</li>
            <li><b>Third Normal Form (3NF):</b> Meets all the requirements of 2NF and removes transitive dependencies between attributes.</li>
        </ul>
        <p><a href="/dashboard">Back to Dashboard</a></p>
    """
    return render_template_string(base_template, titleText=titleText, bodyText=bodyText)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
