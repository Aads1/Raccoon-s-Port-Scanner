from flask import Flask
app = Flask(__name__)

@app.route("/")
def home():
    return "Apache/2.4.49"

app.run(port=8080)
