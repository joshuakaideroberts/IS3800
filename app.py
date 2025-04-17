#!/usr/bin/env python3
import random
from datetime import datetime
from flask import Flask, render_template, request
from markupsafe import Markup
import configparser
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

config=configparser.ConfigParser()
configFile = 'contacts.cfg'
config.read(configFile)

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
    bodyText = "Welcome to the Cybersecurity Reference Tool! This is your one stop shop for looking up the basics of Cybersecurity!"
    bodyText += Markup("""
    <div style="text-align: center;">
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
    </div>
    </br>""")
    bodyText += Markup("By: Samuel Tanner, Joshua Roberts, Kylie Evans, and Owen Jensen")
    bodyText += Markup("For Demo Purposes: username = username; password = password")
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
        SQL Views can also be used to mitigate these attacks. To learn how, visit the W3 Schools guide here: https://www.w3schools.com/sql/sql_view.asp </p>
    
    <hr>

    <h2>SQL Injection Simulation</h2>
    <p>This simulates a vulnerable login form where input isn't sanitized.</p>
    <p>Try entering a username like: <code>' OR 1=1 --</code></p>

    <form method="POST" action="/sqltest">
        <label>Username:</label><br>
        <input type="text" name="username"><br><br>
        <label>Password:</label><br>
        <input type="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
                 
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

@app.route('/sqltest', methods=['POST'])
def sqltest():
    username = request.form.get('username')
    password = request.form.get('password')

    # Unsafe, simulated logic for teaching only
    if username == "admin" and password == "password":
        result = "Login successful!"
    elif "' OR 1=1 --" in username:
        result = "Login bypassed using SQL Injection!"
    else:
        result = "Login failed."

    titleText = "SQL Injection Result"
    bodyText = Markup(f"""
    <h2>SQL Injection Result</h2>
    <p><strong>Username:</strong> {username}</p>
    <p><strong>Password:</strong> {password}</p>
    <p><strong>Result:</strong> {result}</p>
    <br><a href="/xss">Try Again</a><br>
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
    titleText = "Introduction to Networking"
    bodyText = Markup("""
    <h2>What is Networking?</h2>
    <p>Networking is the practice of connecting computers and other devices to share resources and information. It allows data to be exchanged over local or global distances.</p>

    <h3>Basic Components</h3>
    <ul>
        <li><strong>Devices:</strong> Computers, servers, switches, routers, phones, etc.</li>
        <li><strong>Connections:</strong> Wired (Ethernet) or wireless (Wi-Fi) links between devices.</li>
        <li><strong>Protocols:</strong> Rules for communication. Examples: TCP/IP, HTTP, FTP.</li>
    </ul>

    <h3>Common Network Types</h3>
    <ul>
        <li><strong>LAN (Local Area Network):</strong> Covers a small geographic area like a home or office.</li>
        <li><strong>WAN (Wide Area Network):</strong> Spans large areas—like the internet!</li>
        <li><strong>WLAN:</strong> A wireless LAN (like your home Wi-Fi).</li>
    </ul>

    <h3>Why is Networking Important?</h3>
    <p>Networking enables communication, collaboration, file sharing, and access to the internet. It supports businesses, education, entertainment, and daily life.</p>

    <hr>
    <h3>Test Your Knowledge</h3>
    <form id="quizForm">
        <p>1. What type of network typically spans a home or office?<br>
        <input type="radio" name="q1" value="WAN">WAN<br>
        <input type="radio" name="q1" value="LAN">LAN<br>
        <input type="radio" name="q1" value="MAN">MAN</p>

        <p>2. Which protocol is responsible for delivering web pages?<br>
        <input type="radio" name="q2" value="FTP">FTP<br>
        <input type="radio" name="q2" value="DNS">DNS<br>
        <input type="radio" name="q2" value="HTTP">HTTP</p>

        <p>3. What device directs traffic between networks?<br>
        <input type="radio" name="q3" value="Router">Router<br>
        <input type="radio" name="q3" value="Switch">Switch<br>
        <input type="radio" name="q3" value="Modem">Modem</p>

        <button type="button" onclick="checkQuiz()">Submit Answers</button>
    </form>
    <div id="quizResult" style="margin-top: 10px; font-weight: bold;"></div>

    <script>
    function checkQuiz() {
        const answers = {
            q1: "LAN",
            q2: "HTTP",
            q3: "Router"
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


@app.route('/owasp')
def owasp():
    titleText = "OWASP Top 10 (2021)"
    bodyText = Markup("""
    <h2>OWASP Top 10 Security Vulnerabilities</h2>
    <p>This is only a quick overview, please visit <a href="https://owasp.org/Top10/" target="_blank">OWASP Top 10</a> for better details and accuracy.</p>

    <ol>
        <li>
            <strong>Broken Access Control:</strong> Users can act outside their intended permissions. Prevent this by enforcing least privilege, denying access by default, and monitoring for failures.
        </li><br>
        <li>
            <strong>Cryptographic Failures:</strong> Sensitive data is exposed due to weak or missing encryption. Always use strong algorithms, encrypt data in transit and at rest, and securely store passwords.
        </li><br>
        <li>
            <strong>Injection:</strong> Untrusted input can be executed as code (e.g., SQL injection). Use parameterized queries, validate inputs, and avoid dynamic queries.
        </li><br>
        <li>
            <strong>Insecure Design:</strong> Applications lack proper security architecture. Incorporate threat modeling and secure design principles from the start.
        </li><br>
        <li>
            <strong>Security Misconfiguration:</strong> Default settings, unnecessary features, and exposed error messages open the door to attacks. Harden your environments and review configurations regularly.
        </li><br>
        <li>
            <strong>Vulnerable & Outdated Components:</strong> Using old or untrusted software components introduces risk. Maintain an inventory and update dependencies often.
        </li><br>
        <li>
            <strong>Identification & Authentication Failures:</strong> Weak login and session controls allow unauthorized access. Enforce MFA, use secure password storage, and expire sessions properly.
        </li><br>
        <li>
            <strong>Software & Data Integrity Failures:</strong> Trusting code or data without validation can lead to compromise. Use signed updates, secure CI/CD, and verify dependencies.
        </li><br>
        <li>
            <strong>Security Logging & Monitoring Failures:</strong> Without logging and alerting, attacks can go undetected. Log key events and establish incident response processes.
        </li><br>
        <li>
            <strong>Server-Side Request Forgery (SSRF):</strong> Attackers force servers to make internal requests. Sanitize user input and isolate internal resources.
        </li>
    </ol>
                      
    <hr>
    <h3>Test Your Knowledge</h3>
    <form id="quizForm">

        <p>1. What does 'Broken Access Control' allow an attacker to do?<br>
        <input type="radio" name="q1" value="A">Access restricted resources<br>
        <input type="radio" name="q1" value="B">Encrypt passwords<br>
        <input type="radio" name="q1" value="C">Improve application speed<br>
        </p>

        <p>2. Which of the following is an example of Security Misconfiguration?<br>
        <input type="radio" name="q2" value="A">Using a secure password<br>
        <input type="radio" name="q2" value="B">Leaving default admin credentials enabled<br>
        <input type="radio" name="q2" value="C">Logging out after each session<br>
        </p>

        <button type="button" onclick="checkQuiz()">Submit Answers</button>
    </form>
    <div id="quizResult" style="margin-top: 10px; font-weight: bold;"></div>

    <script>
    function checkQuiz() {
    const answers = {
        q1: "A",
        q2: "B"
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


    <br><a href="/">Back to home</a>
    """)
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/xss', methods=['GET', 'POST'])
def xss():
    titleText = "XSS"
    output = ""
    user_input = ""

    if request.method == 'POST':
        user_input = request.form.get('comment')
        output = f"<p><strong>You entered:</strong> {user_input}</p>"

    bodyText = Markup(f"""
    <h2>Cross-Site Scripting (XSS)</h2>
    <p><strong>What is XSS?</strong> Cross-Site Scripting (XSS) is a vulnerability that allows attackers to inject malicious scripts into content from otherwise trusted websites. It is one of the most common web security issues.</p>
    
    <p><strong>Types of XSS Attacks:</strong></p>
    <ul>
        <li><strong>Stored XSS:</strong> The malicious script is permanently stored on the target server (e.g., in a database).</li>
        <li><strong>Reflected XSS:</strong> The script is reflected off a web server, like in a URL or search result.</li>
        <li><strong>DOM-based XSS:</strong> The vulnerability exists in the client-side script, modifying the DOM environment.</li>
    </ul>

    <p><strong>Why it matters:</strong> An attacker can hijack user sessions, steal cookies, log keystrokes, redirect users, and more.</p>

    <hr>

    <p>Try submitting a script to see how an XSS attack might work:</p>
    <p>Example: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>

    <form method="POST">
        <label for="comment">Try your input below:</label><br>
        <input type="text" name="comment" size="50"><br><br>
        <input type="submit" value="Submit">
    </form>
    <div style="margin-top: 15px;">
        {output}
    </div>

    <hr>

    <h3>Test Your Knowledge</h3>
    <form id="quizForm">
        <p>1. What does an XSS attack typically do?<br>
        <input type="radio" name="q1" value="A">Deletes files on the server<br>
        <input type="radio" name="q1" value="B">Executes scripts in the victim's browser<br>
        <input type="radio" name="q1" value="C">Changes user passwords<br></p>

        <p>2. Which of the following is an example of an XSS payload?<br>
        <input type="radio" name="q2" value="A">&lt;b&gt;Bold Text&lt;/b&gt;<br>
        <input type="radio" name="q2" value="B">&lt;script&gt;alert('XSS')&lt;/script&gt;<br>
        <input type="radio" name="q2" value="C">http://example.com/home<br></p>

        <p>3. What is a good way to prevent XSS?<br>
        <input type="radio" name="q3" value="A">Use MD5 hashing<br>
        <input type="radio" name="q3" value="B">Run input through JavaScript<br>
        <input type="radio" name="q3" value="C">Sanitize and escape user input<br></p>

        <button type="button" onclick="checkQuiz()">Submit Answers</button>
    </form>
    <div id="quizResult" style="margin-top: 10px; font-weight: bold;"></div>

    <script>
    function checkQuiz() {{
        const answers = {{
            "q1": "B",
            "q2": "B",
            "q3": "C"
        }};
        let score = 0;
        for (let q in answers) {{
            const selected = document.querySelector('input[name="' + q + '"]:checked');
            if (selected && selected.value === answers[q]) {{
                score++;
            }}
        }}
        const total = Object.keys(answers).length;
        document.getElementById("quizResult").innerText = "You got " + score + " out of " + total + " correct.";
    }}
    </script>

    <br><a href=/>Back to home</a>
    """)

    return render_template('template.html', titleText=titleText, bodyText=bodyText)
   



@app.route('/passwords')
def passwords():
    titleText = "Password Security & Cracking Techniques"
    bodyText = Markup("""
    <h2>Password Security & Cracking Techniques</h2>

    <h3>1. The Importance of Password Security</h3>
    <p>Passwords are often the first line of defense against unauthorized access. Weak or reused passwords can lead to devastating breaches. One major example is the <strong>Target breach in 2013</strong>, which exposed data from over 110 million customers.</p>
    <ul>
        <li>Attackers used a phishing attack to install a trojan on a third-party vendor's system (Fazio Mechanical).</li>
        <li>Due to poor network segmentation, they moved into Target’s internal network and deployed <strong>BlackPOS</strong> malware on POS systems.</li>
        <li>Credit card data was harvested and sent to external servers, eventually ending up in Russia.</li>
    </ul>

    <h3>2. Account Takeover (ATO)</h3>
    <p><strong>Account Takeover</strong> attacks occur when hackers gain access to user accounts, often through leaked credentials or password-guessing techniques.</p>
    <p>Common methods include:</p>
    <ul>
        <li><strong>Credential Stuffing</strong>: Using credentials from previous breaches to access other accounts.</li>
        <li><strong>Brute Force Attacks</strong>: Attempting a large number of random or common passwords.</li>
    </ul>

    <h3>3. Password Cracking Tools</h3>
    <p>Attackers use specialized tools to automate the process of password guessing and cracking. Here are a few:</p>

    <ul>
        <li><strong>John The Ripper</strong>
            <ul>
                <li>Install: <code>sudo snap install john-the-ripper</code></li>
                <li>Create combined password file: <code>sudo unshadow /etc/passwd /etc/shadow > ./combined.pass</code></li>
                <li>Run: <code>john-the-ripper ./combined.pass --show</code></li>
            </ul>
        </li>

        <li><strong>Hashcat</strong>
            <ul>
                <li>Uses GPU for password cracking</li>
                <li>Supports custom password lists or generates random ones</li>
                <li>Example list: 
                    <a href="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt" target="_blank">Top 10M Passwords List</a>
                </li>
            </ul>
        </li>

        <li><strong>Hydra</strong>
            <ul>
                <li>Install: <code>sudo apt install hydra</code></li>
                <li>Used for attacking login forms and services</li>
                <li>Example options:
                    <pre>
-l : single username
-L : list of usernames
-P : list of passwords
-s : specify port
http-post-form: "/path:user=^USER^&pass=^PASS^:F=failedMessage"
                    </pre>
                </li>
            </ul>
        </li>

        <li>Other tools: <strong>Medusa</strong>, <strong>NCrack</strong></li>
    </ul>

    <h3>4. Prevention Techniques</h3>
    <ul>
        <li>Use <strong>Multi-Factor Authentication (MFA)</strong> to add an extra layer of security</li>
        <li>Set <strong>rate limits</strong> to block automated login attempts</li>
        <li>Implement <strong>device/browser detection</strong> to monitor suspicious logins</li>
        <li>Check password safety via <a href="https://haveibeenpwned.com/Passwords" target="_blank">Have I Been Pwned</a></li>
    </ul>

    <h3>5. Best Practices for Passwords</h3>
    <ul>
        <li>Use long, random, and unique passwords for every account</li>
        <li>Avoid reusing passwords across different services</li>
        <li>Use a password manager to generate and store secure credentials</li>
    </ul>

<hr>
    <h3>Test Your Knowledge</h3>
    <form id="quizForm">
        <p>1. What is Credential Stuffing?<br>
        <input type="radio" name="q1" value="A">Trying every possible password combination.<br>
        <input type="radio" name="q1" value="B">Using leaked username/password pairs from past breaches.<br>
        <input type="radio" name="q1" value="C">Forcing password resets on all user accounts.<br></p>

        <p>2. What does the tool 'John the Ripper' do?<br>
        <input type="radio" name="q2" value="A">Secures login pages from brute force attacks.<br>
        <input type="radio" name="q2" value="B">Hashes passwords using SHA-256.<br>
        <input type="radio" name="q2" value="C">Cracks hashed passwords using a command-line interface.<br></p>

        <p>3. What is one way to prevent Account Takeover (ATO)?<br>
        <input type="radio" name="q3" value="A">Reuse the same password across all accounts.<br>
        <input type="radio" name="q3" value="B">Disable password expiration policies.<br>
        <input type="radio" name="q3" value="C">Use multi-factor authentication (MFA).<br></p>

        <button type="button" onclick="checkQuiz()">Submit Answers</button>
    </form>
    <div id="quizResult" style="margin-top: 10px; font-weight: bold;"></div>

    <script>
    function checkQuiz() {
        const answers = {
            q1: "B",
            q2: "C",
            q3: "C"
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

    <br><a href=/>Back to home</a><br>
    """)
    return render_template('template.html', titleText=titleText, bodyText=bodyText)


@app.route('/phishing')
def phishing():
    titleText = "Phishing"
    bodyText = Markup("""
       <h2>What is Phishing</h2>
    <p>Phishing is an attack often used by hackers to fool unsuspecting victim. Phishing attacks can come in many forms with the most typical ones being text messages or emails, and the attacker poses as a legitamate source (e.g., USPS, Amazon, Netflix, etc.).
         These types of attacks often utilize malicious code that execute attacks like XSS. They also often link to forms that will have the user fill in sensitive information, and it can be very harmful. Furthemore, phishing scams are very cheap and extremely easy to edit and scale.
        Common signs of phishing include (but are NOT limited to):</p>
    <ul>
        <li>Poor grammer/Obvious typos </li>
        <li>Unexpected words</li>
        <li>Generic greetings</li>
        <li>Bloated email domain names</li>
        <li>Requests for immediate action</li>
    </ul>
        <h2>Why is it effective</h2>
    <p>You may be wondering why phishing is so effective when it is usally fairly obvious. They usually invoke a threat which often leads to a disregard for caution. It is hard to be completely rational when you have something potentially on the line.
        As for numerous typos, those are often on purpose because it is tactic to weed out people who are more careful.</p>

        <h2>Examples</h2>  
            <p>Email</p>
            <img src="/static/email_phishing_ex.png" style="width:50%;">
            <p>Text Message</p>
            <img src="/static/text_phishing_ex.png" style="width:50%;">
    
   <h3>Test Your Knowledge: Phishing Edition</h3>
<form id="quizForm">
    <p>1. Phishing emails often include urgent requests to act immediately. <br>
    <input type="radio" name="q1" value="True">True
    <input type="radio" name="q1" value="False">False</p>

    <p>2. Clicking unknown links in emails is safe as long as the email looks official. <br>
    <input type="radio" name="q2" value="True">True
    <input type="radio" name="q2" value="False">False</p>

    <p>3. Phishing attacks only occur over email and text messages. <br>
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

    <br>
     <a href=/>Back to home</a>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/cybersec') #we could mention career outlook, how to become a professional (certs and such), evolving techonology (e.g., quantum computing), etc.
def cybersec():
    titleText = "What is the future of Cybersecurity?"
    bodyText = Markup("""
        <h2>Evolving Threats</h2>
    <p>Hopefully, you now understand the importance Cybersecurity in an ever-evolving cyber and data driven world. As technology and new threats contiinues to evolve, the need for skilled Cybersecurity profesionals will continue to expand. </p>
    <p>Ultimately, the future is very unknowable. New technologies will be able to upend the modern world of cybersecurity, and new breakthroughs are already laying the groundwork. Generative AI, for instance, will continue to evolve
        and is already capable of creating executable hacks that anyone can create. Quantum computing is another examplee - Google just recently came out with the "Majorna 1" chip back in February 2025 and it is a huge step in the field of Quantum Computing.
        Already, there are theories that quantum computing will be able to almost instantly break modern encryption protocols.
    </p>
        <h2>How do you become a professional</h2>
    <p>As the cyberworld continues to expand with technologies like the Internet of Things connecting nearly every part of our lives, the demand for cybersecurity professionals is growing faster than ever.
         A strong starting point is to pursue formal education and earn industry-recognized certifications, such as CompTIA Security+, Cisco’s CCNA, and/or Certified Ethical Hacker (CEH), to name but a few.
        While some believe cybersecurity is a field best entered later in your career, that isn't always the case. One effective way to break in early is by gaining practical experience through internships, bug bounties, or participating in cybersecurity competitions. 
        These opportunities allow you to build real-world skills and showcase your abilities to potential employers.
        Perhpas most importantly, make sure it is something you are passionate about. It can be a very stressful career, and it is essential that professionals stay up to date with current events.</p>
    <br>
     <a href=/>Back to home</a>
    </br>""")
    return render_template('template.html', titleText=titleText, bodyText=bodyText)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

