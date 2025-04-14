#!/usr/bin/env python3
import random
from datetime import datetime
from flask import Flask, render_template
from markupsafe import Markup
import configparser
import mysql.connector
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

config=configparser.ConfigParser()
configFile = 'contacts.cfg'
config.read(configFile)
database = config['database']
db=database['db']
dbHost=database['host']
dbUser=database['user']
dbPass=database['pass']

cnx=mysql.connector.connect(user=dbUser, password=dbPass, host=dbHost, database=db)

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
    titleText="Hello Title"
    bodyText="Hello World"
    bodyText=bodyText + Markup("""
    Welcome to Flask
    <br>
     <a href=/aggie>Say Hi to an Aggie</a>
    <br>
     <a href=/randomNumber>Get a random number</a>
    <br>
     <a href=/showTime>Show time</a>
    <br>
     <a href=/about>About</a>
    <br>
     <a href="/contacts">Contacts</a>
    <br>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)
@app.route('/aggie')
def aggie():
    titleText="Hello Aggie"
    bodyText=Markup("""
    You have reached an aggie
    <br>
     <a href=/>home</a>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)
@app.route('/randomNumber')
def randomNumber():
    titleText="A Random Number"
    bodyText="Your random number is " + str(random.randint(0,10000))
    bodyText=bodyText + Markup("""
    <br>
     <a href=/>home</a>
    </br>""")
    return render_template('template.html',titleText=titleText, bodyText=bodyText)
@app.route('/showTime')
def showTime():
    titleText="The current time"
    bodyText="The time is " + str(datetime.now().time())
    bodyText=bodyText + Markup("""
    <br>
     <a href=/>home</a>
    </br>""")
    return render_template('template.html',titleText=titleText, bodyText=bodyText)
@app.route('/about')
def about():
    titleText="About me"
    bodyText="This is a really cool app that doesn't really do much"
    bodyText=bodyText + Markup("""
    <br>
     <a href=/>home</a>
    </br>""")
    return render_template('template.html',titleText=titleText, bodyText=bodyText)
@app.route('/contacts')
def contacts():
   cursor=cnx.cursor()
   titleText="Everest Legends"
   bodyText=Markup("<table><tr><td> Legends </td><td>")
   query='select id, CONCAT(first, " ", last) from contactsTable'
   cursor.execute(query)
   for id, name in cursor:
       newRow="<tr><td> <a href=/contactsDetail/" + str(id) + ">"
       newRow=newRow + name + "</a></td></td> \n "
       bodyText=bodyText + Markup(newRow)
   bodyText=bodyText + Markup("</table>")
   bodyText=bodyText + Markup("""
    <br>
     <a href=/>home</a>
    </br>""")
   cursor.close()
   return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/contactsDetail/<id>/')
@auth.login_required
def contactsDetail(id):
   cursor=cnx.cursor(prepared=True)
   query='select CONCAT(first, \" \", last), email, phoneNum from contactsTable where id = %s'
   cursor.execute(query, (id,))
   for name, email, phoneNum in cursor:
       name=name
       email=email
       phoneNum = phoneNum
   cursor.close()
   titleText="Details for " + name
   bodyText="Name: " + name + Markup("<br>")
   bodyText= bodyText + "Email: " + email + Markup("<br>")
   bodyText= bodyText + "Phone Number: " + phoneNum + Markup("<br><a href=/> back </a>")
   return render_template('template.html', titleText=titleText, bodyText=bodyText)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
