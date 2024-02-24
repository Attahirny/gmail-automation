import functions
from flask import Flask, request, session, redirect, url_for, send_from_directory, render_template



app = Flask(__name__)
app.secret_key = functions.config()

@app.route('/')
def index():
    # Load stored credentials from session
    if session.get('credentials'):
        functions.check_credentials(None, session['credentials'])
    else:
        return redirect('authorize')

    return render_template("index.html")

@app.route('/favicon.ico')
def favicon():
    return send_from_directory("./static", 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/authorize')
def authorize():

    cred = functions.create_credentials()
    authorization_url, session['state'] = functions.check_credentials(cred)

    # Redirect user to Google's authorization page
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    # Check for errors
    if 'error' in request.args:
        return 'Error: ' + request.args.get('error')

    # Verify state token to prevent CSRF attacks
    if request.args.get('state') != session.get('state'):
        return 'Invalid state parameter', 401

    # Get authorization code from the callback URL
    code = request.args.get('code')

    # Exchange authorization code for tokens
    cred = functions.create_credentials()
    if code:
        session['credentials'] = functions.finalize_auth(cred, code)

    return redirect(url_for('index'))

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


if __name__ == '__main__':
    app.run('localhost', 80, debug=True)
