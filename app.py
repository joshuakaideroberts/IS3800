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
     <a href=/linuxBasics>Intro to Linux Commands</a>
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
    titleText = "Introduction to Linux Commands"
    bodyText = Markup("""
    <h2>Introduction to Linux Commands</h2>
    <table class="linux-table">
        <thead>
            <tr>
                <th>Category</th>
                <th>Commands</th>
            </tr>
        </thead>
        <tbody>
            <tr><td>Navigation</td><td><ul><li>ls</li><li>cd</li><li>pwd</li><li>cwd</li><li>top</li><li>htop</li><li>ps</li><li>kill</li></ul></td></tr>
            <tr><td>Connections</td><td><ul><li>ssh</li><li>scp</li><li>sftp</li><li>ftp</li><li>telnet</li></ul></td></tr>
            <tr><td>Files</td><td><ul><li>rm</li><li>mv</li><li>cp</li><li>rmdir</li></ul></td></tr>
            <tr><td>Text Processing</td><td><ul><li>grep</li><li>less</li><li>more</li><li>vi</li><li>nano</li><li>gedit</li><li>sed</li><li>awk</li><li>diff</li><li>comm</li><li>sort</li><li>uniq</li><li>tail</li><li>head</li></ul></td></tr>
            <tr><td>Devices</td><td><ul><li>mount/umount</li><li>lsusb</li></ul></td></tr>
            <tr><td>Package Managers</td><td><ul><li>yum</li><li>dnf</li><li>apt</li><li>rpm</li><li>snap</li></ul></td></tr>
            <tr><td>Useful Directories</td><td><ul><li>/var</li><li>/var/log</li><li>/tmp</li><li>/home</li><li>/proc</li><li>/bin</li><li>/sbin</li><li>/etc</li></ul></td></tr>
            <tr><td>System Info</td><td><ul><li>lsb_release</li><li>uname</li><li>cat /etc/redhat-release</li><li>iptables</li><li>runlevel</li><li>systemctl</li><li>hostname</li></ul></td></tr>
            <tr><td>Misc Utilities</td><td><ul><li>screen</li><li>nohup</li><li>date</li><li>cal</li><li>df</li><li>du</li><li>wget</li><li>curl</li><li>journalctl</li><li>dmesg</li></ul></td></tr>
            <tr><td>I/O Redirection</td><td><ul><li>&gt;</li><li>&gt;&gt;</li><li>&lt;</li><li>&lt;&lt;</li></ul></td></tr>
            <tr><td>Operators</td><td><ul><li>&&</li><li>||</li><li>;</li></ul></td></tr>
            <tr><td>Networking</td><td><ul><li>ifconfig</li><li>ip</li><li>route</li><li>iwconfig</li><li>tcpdump</li><li>nmap</li><li>ss</li><li>netstat</li></ul></td></tr>
            <tr><td>Shell Variables</td><td><ul><li>$$</li><li>$?</li></ul></td></tr>
            <tr><td>Archives</td><td><ul><li>tar</li><li>gzip</li><li>gunzip</li><li>zip</li><li>unzip</li><li>bunzip2</li></ul></td></tr>
            <tr><td>Privilege Escalation</td><td><ul><li>sudo</li><li>su</li></ul></td></tr>
            <tr><td>Bash Tips</td><td><ul><li>Use your arrows</li><li>CTRL-A</li><li>CTRL-E</li><li>history | grep foo</li></ul></td></tr>
        </tbody>
    </table>
                      
    <hr>
    <h3>Test Your Knowledge</h3>
    <form id="quizForm">
        <p>1. Grep is one of the most useful tools you will use? <br>
        <input type="radio" name="q1" value="True">True
        <input type="radio" name="q1" value="False">False</p>

        <p>2.  Netstat shows you what processes are listening? <br>
        <input type="radio" name="q2" value="True">True
        <input type="radio" name="q2" value="False">False</p>   

        <p>3. If you hit the tab key twice it will not complete the name of files or commands? <br>
        <input type="radio" name="q3" value="True">True
        <input type="radio" name="q3" value="False">False</p>         
                      

        <button type="button" onclick="checkQuiz()">Submit Answers</button>
    </form>
    <div id="quizResult" style="margin-top: 10px; font-weight: bold;"></div>

    <script>
    function checkQuiz() {
        const answers = {
            q1: "True",
            q2: "True",     
            q3: "False"    
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


@app.route('/access')
def access():
    titleText = "Access, Compartmentalization, & Privilege Separation"
    bodyText = Markup("""
    <h2>Access, Identification, & Privilege Separation</h2>
    <p><strong>Identification</strong> is the act of claiming an identity, such as providing a username. But identification alone doesn't prove you are who you say you are.</p>
    <p><strong>Authentication</strong> is the process of verifying that identity. This often involves something you know (password), something you have (MFA token), or something you are (fingerprint).</p>
    <p>For example: typing your username is identification; entering your password and using MFA is authentication.</p>

    <h3>Passwords and Hashing</h3>
    <p>Passwords should never be stored in plain text. They are typically hashed using algorithms like SHA-1. To make these hashes more secure, we add a <strong>salt</strong>, which is a random string added before hashing. This ensures that even identical passwords result in different hashes.</p>
    
    <h3>Compartmentalization & Privilege Separation</h3>
    <p><strong>Compartmentalization</strong> involves dividing systems and networks into isolated sections. If one area is compromised, the rest stays secure. For example, keeping HR systems separate from public web servers.</p>
    <p><strong>Privilege Separation</strong> is the idea that users should only have the minimum access necessary to do their jobs. This is the principle of least privilege. It prevents unnecessary risk by limiting who can do what within a system.</p>
    <p>These concepts help uphold the <strong>CIA Triad</strong>: Confidentiality, Integrity, and Availability.</p>

    <p>Bonus tip: Don’t let users perform everyday tasks using an admin account. Always separate admin access from regular use!</p>

    <hr>
    <h3>Test Your Knowledge</h3>
    <form id="quizForm">
        <p>1. Authentication is the process of claiming who you are. <br>
        <input type="radio" name="q1" value="True">True
        <input type="radio" name="q1" value="False">False</p>

        <p>2. The principle of least privilege helps protect sensitive data by limiting access. <br>
        <input type="radio" name="q2" value="True">True
        <input type="radio" name="q2" value="False">False</p>

        <p>3. Two users with the same password will always have the same password hash. <br>
        <input type="radio" name="q3" value="True">True
        <input type="radio" name="q3" value="False">False</p>

        <button type="button" onclick="checkQuiz()">Submit Answers</button>
    </form>
    <div id="quizResult" style="margin-top: 10px; font-weight: bold;"></div>

    <script>
    function checkQuiz() {
        const answers = {
            q1: "False",
            q2: "True",
            q3: "False"
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

