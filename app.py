from flask import Flask

app = Flask(__name__)
app.secret_key = 'you-must-be-kidding-me'

import routes

if __name__ == '__main__':
    app.run(debug=True)
