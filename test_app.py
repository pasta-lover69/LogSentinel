from flask import Flask

# Create a minimal Flask app for testing
app = Flask(__name__)

@app.route('/')
def hello():
    return "<h1>LogSentinel Test - App is Working!</h1>"

if __name__ == '__main__':
    print("Starting minimal test app...")
    app.run(debug=True, host='127.0.0.1', port=5001)
