import functions
from flask import Flask, request, send_from_directory


app = Flask(__name__)
functions.config()

@app.route('/notify', methods=['POST'])
def handle_webhook():
    # Handle webhook notifications from Google Pub/Sub
    data = request.json
    result = functions.handle_notify(data)
    if result:
        return result
    else:
        return 'No payment verified!', 200
    
@app.route('/stopWatch')
def handle_stop_request():
    # Handle webhook notifications from Google Pub/Sub
    functions.stop_watch()
    return 'Watch on gmail inbox stopped.', 200
    
@app.route('/update', methods=['POST'])
def handle_update():
    # Handle webhook notifications from Google Pub/Sub
    data = request.json
    functions.update_data(data)
    return 'OK', 200

@app.route('/')
def index():
    return 'Google gmail automation is working!'

@app.route('/favicon.ico')
def favicon():
    return send_from_directory("./static", 'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=80)
