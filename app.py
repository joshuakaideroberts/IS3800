#!/usr/bin/env python3
import random
from datetime import datetime
from flask import Flask, render_template
from markupsafe import Markup
import configparser
# import mysql.connector
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

config=configparser.ConfigParser()
configFile = 'contacts.cfg'
config.read(configFile)
# database = config['database']
# db=database['db']
# dbHost=database['host']
# dbUser=database['user']
# dbPass=database['pass']

# cnx=mysql.connector.connect(user=dbUser, password=dbPass, host=dbHost, database=db)

app = Flask(__name__)

webAuth = config['httpAuth']
httpUser = webAuth['user']
httpPass = webAuth['pass']

auth = HTTPBasicAuth()
users = { httpUser : generate_password_hash(httpPass) }

@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@app.route('/')
def index():
    titleText = "The Cybersecurity Reference Tool"
    bodyText = "Welcome to the Cybersecurity Reference Tool! This is your one stop shop for looking up the basics of Cybersecurity! For Demo Purposes: username = username; password = password."
    bodyText += Markup("""
    <br>
     <a href=/sqlInjection>Basics of SQL Injection</a>
    <br>
     <a href=/linuxBasics>Intro to Linux</a>
    <br>
     <a href=/access>Access, Compartmentalization, and Privilege Seperation</a>
    <br>
     <a href=/networking>Intro to Networking</a>
    <br>
     <a href=/owasp>Learn about OWASP Top 10</a>
    <br>
     <a href=/xss>Basics of Cross Site Scripting</a>
    <br>
     <a href=/passwords>Password Security: Hashes, Salts, and Password Cracking</a>
    <br>
     <a href=/phishing>Overview of Phishing</a>
    <br>
     <a href=/cybersec>The Future of Cybersecurity</a>
    <br>
    </br>""")
    bodyText += Markup("By: Samuel Tanner, Joshua Roberts, Kylie Evans, and Owen")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/sqlInjection')
@auth.login_required #login required becuase this is more sensistive
def sqlInjection():
    titleText = "SQL Injection"
    bodyText = Markup("""
    <h2>What is SQL Injection?</h2>
    <p>SQL injection is a type of attack that allows users to execute arbitrary SQL code on a database by manipulating user input.
        Attackers often use SQLi to bypass login security measures, retrieve sensitive data, and even adding malicious code to databases. They can even drop tables, destroying database integrity!</p>
    <p>DO NOT DO THIS WITHOUT PERMISSION AS IT IS ILLEGAL. Three types of payloads we would like to discuss are:</p>
    <ul>
        <li>Comment Payload - </li>
            <div style="margin-left: 20px;">Example: admin' -- </div>
        <li>OR Payload</li>
            <div style="margin-left: 20px;">Example: admin' or '1' = '1</div>
        <li>Combined OR/Comment Payload - best used when there isn't a known username</li>
            <div style="margin-left: 20px;">Example: ' OR 1 = 1 --</div>
    </ul>
    <p>The purpose of a comment payload is to comment out the rest of a query, which is useful in injecting your own logic. Conversely, the OR payload is used to create a logical condition that always
        turns true, which allows a hacker to bypass authentification. Finally, the combined payload is a mix of both methods.</p>
    <p>SQLi is one of the most common attacks out there due to it's simplicty. A great way to mitigate SQLi attacks is to NEVER concatanate user input and to ALWAYS implement the principle of least privilege when setting up access controls. 
        Prepared statements (which are pre-compiled SQL statement that can be used repeatedly with different parameters) are also a highly effective tool to mitigate SQLi attacks. It is highly recommended to use all of these techniques in conjunction.
        SQL Views can also be used to mitigate these attacks.To learn how, visit the W3 Schools guide here: https://www.w3schools.com/sql/sql_view.asp </p>
                      
    <hr>
    <h3>Test Your Knowledge</h3>
    <form id="quizForm">
        <p>1. SQL Injection can allow an attacker to delete entire tables. <br>
        <input type="radio" name="q1" value="True">True
        <input type="radio" name="q1" value="False">False</p>

        <p>2. Concatenating user input in SQL queries is safe if the input is short. <br>
        <input type="radio" name="q2" value="True">True
        <input type="radio" name="q2" value="False">False</p>

        <p>3. Using prepared statements helps prevent SQL Injection. <br>
        <input type="radio" name="q3" value="True">True
        <input type="radio" name="q3" value="False">False</p>

        <button type="button" onclick="checkQuiz()">Submit Answers</button>
    </form>
    <div id="quizResult" style="margin-top: 10px; font-weight: bold;"></div>

    <script>
    function checkQuiz() {
        const answers = {
            q1: "True",
            q2: "False",
            q3: "True"
        };
        let score = 0;
        for (let q in answers) {
            const selected = document.querySelector('input[name="' + q + '"]:checked');
            if (selected && selected.value === answers[q]) {
                score++;
            }
        }
        const total = Object.keys(answers).length;
        document.getElementById("quizResult").innerText = "You got " + score + " out of " + total + " correct.";
    }
    </script>

    <br><a href=/>Back to home</a>
    """)
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/linuxBasics')
def linuxBasics():
    titleText = "A Random Number"
    bodyText = "Your random number is " + str(random.randint(0, 10000))
    bodyText += Markup("""
    <br>
     <a href=/>Back to home</a>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/access')
def access():
    titleText = "The Current Time"
    bodyText = "The time is " + str(datetime.now().time())
    bodyText += Markup("""
    <br>
     <a href=/>Back to home</a>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/networking')
def networking():
    titleText = "About This App"
    bodyText = "This app is a reference tool for IS3800 topics. More content to come!"
    bodyText += Markup("""
    <br>
     <a href=/>Back to home</a>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/owasp')
def owasp():
    titleText = "About This App"
    bodyText = "This app is a reference tool for IS3800 topics. More content to come!"
    bodyText += Markup("""
    <br>
     <a href=/>Back to home</a>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/xss')
@auth.login_required #login required because this is more sensitive
def xss():
    titleText = "About This App"
    bodyText = "This app is a reference tool for IS3800 topics. More content to come!"
    bodyText += Markup("""
    <br>
     <a href=/>Back to home</a>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/passwords')
@auth.login_required #login required because this is more sensitive
def passwords():
    titleText = "About This App"
    bodyText = "This app is a reference tool for IS3800 topics. More content to come!"
    bodyText += Markup("""
    <br>
     <a href=/>Back to home</a>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/phishing')
def phishing():
    titleText = "About This App"
    bodyText = "This app is a reference tool for IS3800 topics. More content to come!"
    bodyText += Markup("""
    <br>
     <a href=/>Back to home</a>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/cybersec') #we could mention career outlook, how to become a professional (certs and such), evolving techonology (e.g., quantum computing), etc.
def cybersec():
    titleText = "What is the future of Cybersecurity?"
    bodyText = "This app is a reference tool for IS3800 topics. More content to come!"
    bodyText += Markup("""
    <br>
     <a href=/>Back to home</a>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

# Commented-out contact related route:
# @app.route('/contacts')
# def contacts():
#    cursor=cnx.cursor()
#    ...

# @app.route('/contactsDetail/<id>/')
# @auth.login_required
# def contactsDetail(id):
#    ...

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

