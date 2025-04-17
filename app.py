#!/usr/bin/env python3
import random
from datetime import datetime
from flask import Flask, render_template, request
from markupsafe import Markup
import configparser
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask import jsonify

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
    <h3 style="color: #96ee96;">Bonus:</h3>
    <a href="/keylogger">Simulate a Keylogger</a>
    <br>
    <a href="/logged">View Logged Keystrokes</a>
    <hr style="border: 1px solid #61a361; margin: 20px 0;">

    </div>
    </br>""")
    bodyText += Markup("""
    <div style="text-align: center;">
    By: Samuel Tanner, Joshua Roberts, Kylie Evans, and Owen Jensen
    <br>
    For Demo Purposes: username = username; password = password
    """)
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
    <br><a href="/sqlInjection">Try Again</a><br>
    """)

    return render_template('template.html', titleText=titleText, bodyText=bodyText)

@app.route('/linuxBasics')
def linuxBasics():
    titleText = "Intro to Linux Commands"
    bodyText = Markup("""

<h2>Basic Linux Commands</h2>
<hr>
<h3>Navigation & File Management</h3>
<ul>
    <li><code>ls</code>: List contents of a directory
        <ul><li>-a: show all files</li><li>-l: long format</li><li>-h: human readable</li></ul>
    </li>
    <li><code>cd</code>: Change directory (<code>cd /</code>, <code>cd ..</code>, <code>cd ~</code>)</li>
    <li><code>pwd</code>: Print current working directory</li>
    <li><code>df -h</code>: Show disk space usage</li>
    <li><code>du -sh *</code>: Show space used by each item in current dir</li>
</ul>

<h3>Processes & System Monitoring</h3>
<ul>
    <li><code>ps -ef</code>: Show all running processes</li>
    <li><code>ps -ef | grep bash</code>: Find specific processes</li>
    <li><code>top</code> / <code>htop</code>: View real-time system usage</li>
    <li><code>kill</code>: Terminate a process</li>
</ul>

<h3>Networking & Connectivity</h3>
<ul>
    <li><code>ssh</code>, <code>scp</code>, <code>sftp</code>, <code>ftp</code>, <code>telnet</code>: Remote access & file transfers</li>
    <li><code>netstat -an</code>: Show active network connections</li>
    <li><code>ifconfig</code>, <code>ip</code>, <code>route</code>: View and manage network settings</li>
</ul>

<h3>Text Processing Tools</h3>
<ul>
    <li><code>grep</code>: Search text (use <code>-i</code> for case-insensitive, <code>-v</code> to exclude)</li>
    <li><code>cat</code>, <code>less</code>, <code>more</code>, <code>head</code>, <code>tail -f</code>: View file contents</li>
    <li><code>sed</code>, <code>awk</code>, <code>diff</code>, <code>comm</code>, <code>sort</code>, <code>uniq</code>: Modify and compare text</li>
</ul>

<h3>Package Management</h3>
<ul>
    <li><code>apt update</code> / <code>apt upgrade</code>: Refresh and update packages</li>
    <li><code>apt install &lt;package&gt;</code>: Install software</li>
    <li>Other tools: <code>yum</code>, <code>dnf</code>, <code>rpm</code>, <code>snap</code></li>
</ul>

<h3>Useful System Tools</h3>
<ul>
    <li><code>lsb_release</code>, <code>uname</code>, <code>hostname</code>: System information</li>
    <li><code>systemctl</code>, <code>iptables</code>: Manage services and firewall</li>
    <li><code>screen</code>, <code>nohup</code>: Persistent terminal sessions</li>
    <li><code>journalctl</code>, <code>dmesg</code>: System logs</li>
</ul>

<h3>Editors</h3>
<ul>
    <li><code>nano</code>: Simple, menu-driven editor</li>
    <li><code>vi</code>: Advanced editor (ESC to command mode, <code>:wq</code> to save and quit)</li>
</ul>

<h3>I/O Redirection & Operators</h3>
<ul>
    <li><code>&gt;</code>, <code>&gt;&gt;</code>: Output redirection</li>
    <li><code>&lt;</code>, <code>&lt;&lt;</code>: Input redirection</li>
    <li><code>&&</code>, <code>||</code>, <code>;</code>: Command chaining and logic</li>
</ul>

<h3>Shell Variables & Bash Tips</h3>
<ul>
    <li><code>$$</code>: Current shell PID</li>
    <li><code>$?</code>: Exit status of last command</li>
    <li>Use <strong>arrow keys</strong> to scroll command history</li>
    <li><code>CTRL-A</code>, <code>CTRL-E</code>: Move to beginning/end of line</li>
    <li><code>history | grep &lt;command&gt;</code>: Find a command from history</li>
</ul>

<h3>Directories to Know</h3>
<ul>
    <li><code>/var</code>, <code>/var/log</code>: System logs and runtime files</li>
    <li><code>/etc</code>: Configuration files</li>
    <li><code>/home</code>, <code>/tmp</code>, <code>/proc</code>, <code>/bin</code>, <code>/sbin</code>: Core system paths</li>
</ul>

<h3>File Archiving & Compression</h3>
<ul>
    <li><code>tar</code>, <code>gzip</code>, <code>gunzip</code>, <code>zip</code>, <code>unzip</code>, <code>bunzip2</code>: Create and extract archives</li>
</ul>

<h3>Privilege Escalation</h3>
<ul>
    <li><code>sudo</code>: Run commands as another user (typically root)</li>
    <li><code>su</code>: Switch to another user shell</li>
</ul>

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
    <p>The OWASP Foundation identifies the most critical security risks to web applications. Here's a summary of each, with examples and prevention tips. For more details, visit the <a href="https://owasp.org/Top10/" target="_blank">official OWASP site</a>.</p>

    <ol>
        <li>
            <strong>Broken Access Control:</strong><br>
            Users act outside their permissions due to poor access restrictions.
            <ul>
                <li><em>Example:</em> <strong>CVE-2019-0211</strong> let attackers escalate to root via Apache.</li>
                <li><strong>Prevent:</strong> Deny access by default, enforce least privilege, log failures, rate-limit API calls.</li>
            </ul>
        </li><br>

        <li>
            <strong>Cryptographic Failures:</strong><br>
            Sensitive data exposed due to weak or missing encryption.
            <ul>
                <li>Use strong, up-to-date algorithms like AES, TLS 1.2+.</li>
                <li>Store passwords with bcrypt, Argon2, or scrypt.</li>
                <li>Encrypt all data in transit and at rest.</li>
            </ul>
        </li><br>

        <li>
            <strong>Injection:</strong><br>
            Untrusted data triggers unintended code execution (e.g., SQL injection).
            <ul>
                <li>Use parameterized queries or ORM frameworks.</li>
                <li>Validate inputs on server-side, escape dangerous characters.</li>
                <li>Limit results returned in queries (e.g., using <code>LIMIT</code>).</li>
            </ul>
        </li><br>

        <li>
            <strong>Insecure Design:</strong><br>
            Missing or flawed security architecture leaves the system exposed.
            <ul>
                <li>Use secure design patterns and threat modeling early in development.</li>
                <li>Establish a secure development lifecycle (SDLC).</li>
            </ul>
        </li><br>

        <li>
            <strong>Security Misconfiguration:</strong><br>
            Default credentials, overly verbose errors, or unused features.
            <ul>
                <li><em>Example:</em> Nissan left a Git server open with username: <code>admin</code>, password: <code>admin</code>.</li>
                <li>Harden environments, automate configuration reviews, and remove unused services.</li>
            </ul>
        </li><br>

        <li>
            <strong>Vulnerable and Outdated Components:</strong><br>
            Old or unpatched libraries lead to exploits.
            <ul>
                <li>Track versions of all components (client & server).</li>
                <li>Use tools like OWASP Dependency Check, retire.js.</li>
                <li>Subscribe to CVE alerts and patch regularly.</li>
            </ul>
        </li><br>

        <li>
            <strong>Identification and Authentication Failures:</strong><br>
            Weak login systems enable account compromise.
            <ul>
                <li>Enforce MFA, use strong password storage, limit session reuse.</li>
                <li>Invalidate sessions after logout or inactivity.</li>
                <li>Avoid default or weak passwords.</li>
            </ul>
        </li><br>

        <li>
            <strong>Software and Data Integrity Failures:</strong><br>
            Trusting code or data without verification (e.g., unsigned updates).
            <ul>
                <li>Use digital signatures on updates and packages.</li>
                <li>Secure the CI/CD pipeline and use trusted package sources.</li>
                <li>Prevent insecure deserialization by verifying object integrity.</li>
            </ul>
        </li><br>

        <li>
            <strong>Security Logging and Monitoring Failures:</strong><br>
            Without logs and alerts, attacks can go undetected.
            <ul>
                <li>Log access failures, suspicious activity, and high-value transactions.</li>
                <li>Monitor logs centrally and trigger alerts.</li>
            </ul>
        </li><br>

        <li>
            <strong>Server-Side Request Forgery (SSRF):</strong><br>
            Attacker tricks the server into making unintended requests.
            <ul>
                <li>Validate and sanitize user-supplied URLs.</li>
                <li>Enforce allowlists and block internal network access.</li>
                <li>Disable redirects and strip raw responses.</li>
            </ul>
        </li>
    </ol>

    <hr>
    <h3>Test Your Knowledge</h3>
    <form id="quizForm">
        <p>1. Which of the following is a real example of Broken Access Control?<br>
        <input type="radio" name="q1" value="A">CVE-2019-0211 Apache escalation<br>
        <input type="radio" name="q1" value="B">Use of TLS 1.3<br>
        <input type="radio" name="q1" value="C">Multi-factor authentication<br></p>

        <p>2. What’s a common prevention strategy for Injection attacks?<br>
        <input type="radio" name="q2" value="A">Use bcrypt<br>
        <input type="radio" name="q2" value="B">Parameterize queries<br>
        <input type="radio" name="q2" value="C">Use raw SQL strings<br></p>

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

logged_keys = []

@app.route('/keylogger')
def keylogger():
    titleText = "Keylogger Simulation"

    bodyText = Markup("""
    <h2>Keylogger Demo (Client-Side)</h2>

    <p><strong>What is a Keylogger?</strong></p>
    <p>A <strong>keylogger</strong> (short for keystroke logger) is a type of surveillance tool that records the keys a user types on their keyboard, usually without their knowledge. Keyloggers can be used by attackers to steal sensitive information such as passwords, credit card numbers, or personal messages.</p>

    <p>There are two main types of keyloggers:</p>
    <ul>
        <li><strong>Hardware keyloggers</strong> – physical devices plugged between a keyboard and a computer to capture input.</li>
        <li><strong>Software keyloggers</strong> – programs that run silently in the background, recording keystrokes and possibly sending them to a remote attacker.</li>
    </ul>

    <p>This simulation demonstrates a simple, client-side keylogger written in JavaScript. It captures your keystrokes in the text box below and displays them as they're typed. It also sends them to the server (just for demo purposes, not stored permanently).</p>

    <p><strong>How to Defend Against Keyloggers:</strong></p>
    <ul>
        <li>Use up-to-date antivirus and anti-malware tools</li>
        <li>Avoid downloading untrusted software</li>
        <li>Be cautious on public/shared computers</li>
        <li>Use on-screen keyboards or password managers with auto-fill (they bypass keystroke logging)</li>
        <li>Employ multi-factor authentication to minimize risk</li>
    </ul>

    <hr>

    <label for="keyInput"><strong>Try typing something below:</strong></label><br>
    <input type="text" id="keyInput" placeholder="Type something..." style="width: 100%; padding: 8px;"><br><br>
    <div><strong>Keystrokes:</strong></div>
    <pre id="keyDisplay" style="background:#222; padding:10px; color:#ffcc00; min-height:50px;"></pre>

    <script>
        const display = document.getElementById('keyDisplay');
        const inputBox = document.getElementById('keyInput');
        let logged = [];

        inputBox.addEventListener('keydown', (e) => {
            const key = e.key;
            logged.push(key);
            display.textContent = logged.join(' ');
            fetch('/logkeys', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key: key })
            });
        });
    </script>

    <br><a href="/logged">View Logged Keystrokes</a><br>
    <br><a href="/">Back to Home</a>
    """)
    return render_template('template.html', titleText=titleText, bodyText=bodyText)


@app.route('/logkeys', methods=['POST'])
def log_keys():
    data = request.get_json()
    if 'key' in data:
        logged_keys.append(data['key'])
    return jsonify({'status': 'ok'})

@app.route('/logged')
def show_logged():
    titleText = "Logged Keystrokes"
    bodyText = Markup(f"""
    <h2>Logged Keystrokes</h2>
    <pre>{' '.join(logged_keys)}</pre>
    <br><a href="/">Back to Home</a>
    """)
    return render_template('template.html', titleText=titleText, bodyText=bodyText)
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

