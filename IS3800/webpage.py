from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/module<int:num>')
def module(num):
    if 1 <= num <= 8:
        return render_template(f"module{num}.html", module_num=num)
    else:
        return "Module not found", 404

if __name__ == '__main__':
    app.run(debug=True)
