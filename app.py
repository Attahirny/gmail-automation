import functions
from flask import Flask, request, session, redirect, url_for, send_from_directory, render_template


app = Flask(__name__)
app.secret_key = functions.config()

@app.route('/')
def index():
    # Load stored credentials from session
    if session.get('credentials'):
        functions.check_credentials(None, session['credentials'])
        return render_template("index.html")
    else:
        return render_template("index.html", message="User unauthorized!")
            

    
@app.route('/favicon.ico')
def favicon():
    return send_from_directory("./static", 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/authorize')
def authorize():
    try:
        if not session.get('credentials'):
            cred = functions.create_credentials()
            authorization_url, session['state'] = functions.check_credentials(cred)
            # Redirect user to Google's authorization page
            return redirect(authorization_url)
        else:
            return redirect(url_for('index'))
    except ValueError as e:
        print("Error: ", e)
        return '<h2>App not ready!</h2>', 500

@app.route('/oauth2callback')
def oauth2callback():
    # Check for errors
    if 'error' in request.args:
        return '<h2>Error: ' + request.args.get('error') + "<h2>"

    # Verify state token to prevent CSRF attacks
    if request.args.get('state') != session.get('state'):
        return '<h2>Invalid state parameter</h2>', 401
    
    try:
        # Get authorization code from the callback URL
        code = request.args.get('code')

        # # Exchange authorization code for tokens
        cred = functions.create_credentials()
        if code:
            session['credentials'] = functions.get_token(cred, code=code)
    except Exception as e:
        print("Error: ", e)
        return '<h2>Invalid state parameter</h2>', 401

    return redirect(url_for('index'))

@app.route('/revoke')
def revoke():
    if 'credentials' not in session:
        return ('<h2>You need to be <a href="/authorize">authorized</a> before ' +
                'trying to revoke credentials.</h2>')

    # Get the revoke token
    revoke = functions.revoke_token()

    if revoke:
        status_code = getattr(revoke, 'status_code')
        if status_code == 200:
            return('<h2>Credentials successfully revoked.</h2>' + print_index_table())
    return('<h2>An error occurred while trying to revoke credentials</h2>' + print_index_table())
    

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
    if "credentials" in session:
        functions.stop_watch()
        return 'Watch on gmail inbox stopped.'
    else:
        return ('<h2>You need to be <a href="/authorize">authorized</a> before ' +
                'trying to stow watch on google pub/sub!</h2>')
    
@app.route('/update', methods=['POST'])
def handle_update():
    # Handle webhook notifications from Google Pub/Sub
    data = request.json
    functions.update_data(data)
    return 'OK', 200

@app.route('/clear')
def clear_credentials():
    if 'credentials' in session:
        del session['credentials']
    return ('<h2>Credentials have been cleared.</h2><br><br>' +
            print_index_table())

def print_index_table():
  return ('<table>' +
          '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
          '<td>Go directly to the authorization flow. If there are stored ' +
          '    credentials, you still might not be prompted to reauthorize ' +
          '    the application.</td></tr>' +
          '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
          '<td>Revoke the access token associated with the current user ' +
          '    session. After revoking credentials, if you go to the test ' +
          '    page, you should see an <code>invalid_grant</code> error.' +
          '</td></tr>' +
          '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
          '<td>Clear the access token currently stored in the user session. ' +
          '    After clearing the token, you can <a href="/authorize">log in</a> again, back to the auth flow.' +
          '</td></tr></table>')


if __name__ == '__main__':
    app.run('localhost', 80, debug=True)
