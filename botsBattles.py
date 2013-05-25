# all the imports
from __future__ import with_statement
from flask import Flask, request, session, redirect, url_for, \
     render_template, flash
from time import gmtime, strftime
import json
import md5
import urllib2
from urllib2 import URLError

# configuration
DEBUG = True
SECRET_KEY = '\xc0\xd7O\xb3\'q\\\x19m\xb3uW\x16\xc2\r\x88\x91\xdbIv\x8d\x8f\xe9\x1f'
# localhost will be changed as the local network arise
WEBSERVICE_IP = "http://localhost:9000"
TESTING = False
# list of allowed extensions
ALLOWED_EXTENSIONS_FILE = set(['jar', 'exe'])
ALLOWED_EXTENSIONS_DOC = set(['zip'])
ALLOWED_EXTENSIONS_IMAGE = set(['png', 'jpg', 'jpeg', 'gif'])

# create our application
app = Flask(__name__)
app.config.from_object(__name__)

# methods


from BeautifulSoup import BeautifulSoup

VALID_TAGS = ['strong', 'em', 'p', 'ul', 'li', 'br']


def sanitize_html(value):
    soup = BeautifulSoup(value)
    for tag in soup.findAll(True):
        if tag.name not in VALID_TAGS:
            tag.hidden = True
    return soup.renderContents()


def postToWebService(payload, subpage):
    data = json.dumps(payload)
    clen = len(data)
    app.logger.debug("[POST]Connection with WS started: "
        + strftime("%a, %d %b %Y %X +0000", gmtime()))
    req = urllib2.Request(WEBSERVICE_IP + subpage, data,
        {'Content-Type': 'application/json', 'Content-Length': clen})
    try:
        response = urllib2.urlopen(req)
        app.logger.debug("[POST]Response received: "
            + strftime("%a, %d %b %Y %X +0000", gmtime()))
        data = json.load(response)
    except URLError, e:
        if hasattr(e, 'reason'):
            error = e.reason
            app.logger.error('We failed to reach a server.\nReason: ' + error)
        elif hasattr(e, 'code'):
            error = e.code
            app.logger.error('The server couldn\'t fulfill the request.'
                + '\nError code:' + error)
    except ValueError, e:
        if hasattr(e, 'reason'):
            error = e.reason
            app.logger.error('Value Error has been found.\nReason: ' + error)
        elif hasattr(e, 'code'):
            error = e.code
            app.logger.error('Value Error has been found.\nError code:' + error)
    else:
        return data
    errorMessage = {"Status": False, "Komunikat": error}
    return errorMessage


def allowed_codeFile(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS_FILE


def sendCompiledBotToWebService(fileData, subpage):
    if file and allowed_codeFile(file.filename):
        data = file
        req = urllib2.Request(WEBSERVICE_IP + subpage, data,
            {'Content-Type': 'application/octet-stream '})
        try:
            response = urllib2.urlopen(req)
            data = json.load(response)
        except URLError, e:
            if hasattr(e, 'reason'):
                error = e.reason
                app.logger.error('We failed to reach a server.\nReason: '
                    + error)
            elif hasattr(e, 'code'):
                error = e.code
                app.logger.error('The server couldn\'t fulfill the request.'
                    + '\nError code:' + error)
        except ValueError:
            if hasattr(e, 'reason'):
                error = e.reason
                app.logger.error('Value Error has been found.\nReason: ' + error)
            elif hasattr(e, 'code'):
                error = e.code
                app.logger.error('Value Error has been found.\nError code:' + error)
        else:
            return data
    else:
        error = 'File format not valid!'
        app.logger.error(error)
    errorMessage = {"Status": False, "Komunikat": error}
    return errorMessage


def getFromWebService(subpage):
    req = urllib2.Request(WEBSERVICE_IP + subpage)
    app.logger.debug("[GET]Connection with WS started: "
        + strftime("%a, %d %b %Y %X +0000", gmtime()))
    try:
        response = urllib2.urlopen(req)
        app.logger.debug("[GET]Response received: "
            + strftime("%a, %d %b %Y %X +0000", gmtime()))
        data = json.load(response)
    except URLError, e:
        if hasattr(e, 'reason'):
            error = e.reason
            app.logger.error('We failed to reach a server.\nReason: ' + error)
        elif hasattr(e, 'code'):
            error = e.code
            app.logger.error('The server couldn\'t fulfill the request.'
                + '\nError code:' + error)
    except ValueError:
        if hasattr(e, 'reason'):
            error = e.reason
            app.logger.error('Value Error has been found.\nReason: ' + error)
        elif hasattr(e, 'code'):
            error = e.code
            app.logger.error('Value Error has been found.\nError code:' + error)
    else:
        return data
    errorMessage = {"Status": False, "Komunikat": error}
    return errorMessage

# error pages


@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', username=session['username'],
        errorNo=404, errorMe="The page You're looking for isn't here!")


@app.errorhandler(503)
def app_error(error):
    return render_template('error.html', username=session['username'],
        errorNo=503, errorMe="Application have some problems."
        + "Contact us to help solve them.\n" + error)

# page methods


@app.route('/')
def news():
    if "username" in session:
        return render_template('news.html', username=session['username'],
            cMessages=check_messages())
    else:
        return render_template('news.html', username="")


@app.route('/main.js')
def main_js():
    return render_template('main.js')


@app.route('/tournaments')
def tournaments():
    return render_template('tournaments.html', username=session['username'],
        cMessages=check_messages())


@app.route('/user')
def user():
    return show_user_profile(session['username'])


@app.route('/battles')
def battles():
    error = None
    response = getFromWebService("/" + session['username'] + "/duels")
    # print response
    # I get only nr's of duels. It would be nice to get more info.
    if response.get('Status') is True:
        return render_template('battles.html', username=session['username'],
            entries=response, cMessages=check_messages())
    else:
        error = response.get('Komunikat')
    return render_template('battles.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        mdpass = md5.new(request.form['password'])
        payload = {
            "Login": sanitize_html(request.form['username']),
            "Password": mdpass.hexdigest(),
            "Name": sanitize_html(request.form['name']),
            "Surname": sanitize_html(request.form['surname']),
            "Email": request.form['e_mail'],
            "Sex": request.form['sex']
        }
        response = postToWebService(payload, "/user/registration")
        if response.get('Status') is True:
            return render_template('message.html',
                message="Check your e-mail account!")
        else:
            error = response.get('Komunikat')
    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        mdpass = md5.new(request.form['password'])
        payload = {
            "Login": sanitize_html(request.form['username']),
            "Password": mdpass.hexdigest(),
        }
        response = postToWebService(payload, "/login")
        if response.get('Status') is True:
            session['logged_in'] = True
            session['admin_box'] = response.get('Admin')
            session['username'] = request.form['username']
            session['pagination'] = 7
            flash('You were logged in %s' % session['username'])
            return redirect(url_for('news'))
        else:
            error = response.get('Komunikat')
    return render_template('login.html', error=error)


@app.route('/sendCode', methods=['GET', 'POST'])
def send_code():
    error = None
    return render_template('send_code.html', error=error,
        cMessages=check_messages())


@app.route('/activation/<webHash>')
def try_to_activate(webHash):
    error = None
    payload = {
        "Hash": sanitize_html(webHash)
    }
    response = postToWebService(payload, "/user/registration/activation")
    if response.get('Status') is True:
        return render_template('message.html',
            message="User successfuly activated!")
    else:
        error = response.get('Komunikat')
    return render_template('message.html', message=error)


@app.route('/user/<nick>')
def show_user_profile(nick):
    response = getFromWebService("/" + sanitize_html(nick) + "/about")
    if response.get('Status') is True:
        return render_template('profile.html', cMessages=check_messages(),
            username=session['username'], profile=nick)
    else:
        error = response.get('Komunikat')
    return render_template('profile.html', username=session['username'],
        profile=nick, error=error, cMessages=check_messages())


@app.route('/choose_oponent')
def choose_oponent():
    error = None
    # gamesRes = getFromWebService("/games")
    # if gamesRes.get('Status') is True:
    userRes = getFromWebService("/games/duels/" + session['username']
        + "/0/list")
    if userRes.get('Status') is True:
    #         games = []
        logins = []
        for i in range(1, session['pagination']):
            nextOne = userRes.get(str(i))
            if nextOne is not None:
                logins.append(nextOne)
        return render_template('choose_oponent.html',
            cMessages=check_messages(), username=session['username'],
            users=logins)
    else:
        error = userRes.get('Komunikat')
    return render_template('choose_oponent.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/duel', methods=['GET', 'POST'])
def new_duel():
    return register_battle(sanitize_html(session['username']),
        sanitize_html(request.form['oponent']),
        sanitize_html(request.form['game']))


def register_battle(login1, login2, gameName):
    error = None
    payload = {
        "User1": login1,
        "User2": login2,
        "GameName": gameName
    }
    response = postToWebService(payload, "/games/duels/registry")
    if response.get('Status') is True:
        flash("Successful registration of battle.")
        return redirect(url_for('news'))
    else:
        error = "Major error of WebService! " + str(response.get('Komunikat'))
    return render_template('choose_oponent.html', username=session['username'],
        error=error, cMessages=check_messages())


def check_messages():
    error = None
    response = getFromWebService("/notice/" + session['username'] + "/new")
    if response.get('Status') is True:
        return response.get('Count')
    else:
        error = "Problem with messages! " + str(response.get('Komunikat'))
    return error


@app.route('/admin_tools')
def admin_box():
    return render_template('admin_tools.html', username=session['username'],
            cMessages=check_messages())


@app.route('/post_box')
def post_box():
    return render_template('post_box.html', username=session['username'],
            cMessages=check_messages())


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', "")
    session.pop('pagination', 5)
    session.pop('admin_box', None)
    flash('You were logged out')
    return redirect(url_for('news'))

if __name__ == '__main__':
    app.run(host='0.0.0.0')
