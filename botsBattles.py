# all the imports
from __future__ import with_statement
from flask import Flask, request, session, redirect, url_for, \
     render_template, flash
import json
import md5
import urllib2
from urllib2 import URLError

# configuration
DEBUG = True
SECRET_KEY = 'development_key'
# localhost will be changed as the local network arise
WEBSERVICE_IP = "http://77.65.54.170:9000"
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
    req = urllib2.Request(WEBSERVICE_IP + subpage, data,
        {'Content-Type': 'application/json', 'Content-Length': clen})
    response = urllib2.urlopen(req)
    try:
        data = json.load(response)
    except URLError, e:
        if hasattr(e, 'reason'):
            print 'We failed to reach a server.'
            error = e.reason
            print 'Reason: ', error
        elif hasattr(e, 'code'):
            print 'The server couldn\'t fulfill the request.'
            error = e.code
            print 'Error code: ', error
    except ValueError:
        return render_template('dump.html', dump=response)
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
        response = urllib2.urlopen(req)
        try:
            data = json.load(response)
        except URLError, e:
            if hasattr(e, 'reason'):
                print 'We failed to reach a server.'
                error = e.reason
                print 'Reason: ', error
            elif hasattr(e, 'code'):
                print 'The server couldn\'t fulfill the request.'
                error = e.code
                print 'Error code: ', error
        except ValueError:
            return render_template('dump.html', dump=response)
        else:
            return data
    else:
        error = 'File not valid!'
    errorMessage = {"Status": False, "Komunikat": error}
    return errorMessage


def getFromWebService(subpage):
    req = urllib2.Request(WEBSERVICE_IP + subpage)
    response = urllib2.urlopen(req)
    try:
        data = json.load(response)
    except URLError, e:
        if hasattr(e, 'reason'):
            print 'We failed to reach a server.'
            error = e.reason
            print 'Reason: ', error
        elif hasattr(e, 'code'):
            print 'The server couldn\'t fulfill the request.'
            error = e.code
            print 'Error code: ', error
    except ValueError:
        return render_template('dump.html', dump=response)
    else:
        return data
    errorMessage = {"Status": False, "Komunikat": error}
    return errorMessage

# error pages


@app.errorhandler(404)
def not_found(error):
    return render_template('error.html'), 404

# page methods


@app.route('/')
def news():
    if "username" in session:
        return render_template('news.html', username=session['username'])
    else:
        return render_template('news.html', username="")


@app.route('/tournaments')
def tournaments():
    return render_template('tournaments.html', username=session['username'])


@app.route('/user')
def user():
    return show_user_profile(session['username'])


@app.route('/battles')
def battles():
    error = None
    response = getFromWebService("/" + session['username'] + "/duels")
    # I get only nr's of duels. It would be nice to get more info.
    if response.get('Status') is True:
        return render_template('battles.html', username=session['username'],
            entries=response)
    else:
        error = response.get('Komunikat')
    return render_template('battles.html', username=session['username'],
        error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        # alternative hash:
        # import hashlib
        # hashlib.sha224(text)
        mdpass = md5.new(request.form['password'])
        payload = {
            "Login": sanitize_html(request.form['username']),
            "Password": sanitize_html(mdpass.hexdigest()),
            "Permissions": 0,
            "Groups": request.form['group'],
            "Name": sanitize_html(request.form['name']),
            "Surname": sanitize_html(request.form['surname']),
            "Email": request.form['e_mail'],
            "Sex": request.form['sex']
        }
        response = postToWebService(payload, "/user/registration")
        if response.get('Status') is True:
            session['logged_in'] = True
            if request.form['username'] is "admin":
                session['admin_box'] = True
            else:
                session['admin_box'] = False
            session['username'] = request.form['username']
            session['pagination'] = 7
            flash('You were logged in %s' % session['username'])
            return redirect(url_for('news'))
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
            if request.form['username'] == 'admin':
                session['admin_box'] = True
            else:
                session['admin_box'] = False
            session['username'] = request.form['username']
            session['pagination'] = 7
            print str(session['admin_box']) + " " + session['username']
            flash('You were logged in %s' % session['username'])
            return redirect(url_for('news'))
        else:
            error = response.get('Komunikat')
    return render_template('login.html', error=error)


@app.route('/duel', methods=['GET', 'POST'])
def new_duel():
    error = None
    register_battle(sanitize_html(session['username']),
        sanitize_html(request.form['oponent']),
        sanitize_html(request.form['game']))
    return render_template('send_code.html', error=error)


@app.route('/sendCode', methods=['GET', 'POST'])
def send_code():
    error = None
    return render_template('send_code.html', error=error)


@app.route('/user/<nick>')
def show_user_profile(nick):
    response = getFromWebService("/" + sanitize_html(nick) + "/about")
    if response.get('Status') is True:
        return render_template('profile.html',
            username=session['username'], profile=nick)
    else:
        error = response.get('Komunikat')
    return render_template('profile.html', username=session['username'],
        profile=nick, error=error)


@app.route('/choose_oponent')
def choose_oponent():
    error = None
    response = getFromWebService("/games/duels/" + session['username']
    + "/0/list")
    if response.get('Status') is True:
        logins = []
        for i in range(1, session['pagination']):
            nextOne = response.get(str(i))
            if nextOne is not None:
                logins.append(nextOne)
        return render_template('choose_oponent.html',
            username=session['username'], users=logins)
    else:
        error = response.get('Komunikat')
    return render_template('choose_oponent.html', username=session['username'],
        error=error)


def register_battle(login1, login2, gameName):
    error = None
    payload = {
        "User1": sanitize_html(login1),
        "User2": sanitize_html(login2),
        "GameName": sanitize_html(gameName)
    }
    response = postToWebService(payload, "/games/duels/registry")
    if response.get('Status') is True:
        flash("Successful registration of battle.")
        return redirect(url_for('news'))
    else:
        error = "Major error of WebService!"
    return redirect(url_for('battles'), error=error)


@app.route('/admin_tools')
def admin_box():
    return render_template('admin_tools.html', username=session['username'])


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
