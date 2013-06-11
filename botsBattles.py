# -*- coding: utf-8 -*-

# all the imports
from __future__ import with_statement
from flask import Flask, request, session, redirect, url_for, \
     render_template, flash
# from time import gmtime, strftime
from BeautifulSoup import BeautifulSoup
import json
import md5
import requests
import urllib2
from urllib2 import URLError

# configuration
DEBUG = True
SECRET_KEY = '\xc0\xd7O\xb3\'q\\\x19m\xb3uW\x16\xc2\r\x88\x91\xdbIv\x8d\x8f\xe9\x1f'

import socket

timeout = 15
socket.setdefaulttimeout(timeout)

# address of WebService server
WEBSERVICE_IP = "http://77.65.54.170:9000"
TESTING = False

# list of allowed extensions
ALLOWED_EXTENSIONS_FILE = set(['jar', 'exe'])
ALLOWED_EXTENSIONS_DOC = set(['zip'])

VALID_TAGS = ['strong', 'em', 'p', 'ul', 'li', 'br']

# create our application
app = Flask(__name__)
app.config.from_object(__name__)

# methods


def allowed_codeFile(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS_FILE


def getFromWebService(subpage):
    try:
        f = requests.get(WEBSERVICE_IP + subpage)
        data = f.json()
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
            error = e
    except requests.exceptions.ConnectionError:
        error = "Connection Error!"
        app.logger.error(error)
    else:
        return data
    errorMessage = {"Status": False, "Komunikat": error}
    return errorMessage


def postToWebService(payload, subpage):
    data = json.dumps(payload)
    clen = len(data)
    try:
        f = requests.post(WEBSERVICE_IP + subpage, data=data,
            headers={'Content-Type': 'application/json',
            'Content-Length': clen})
        data = f.json()
    # strftime("%a, %d %b %Y %X +0000", gmtime())
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
            error = e
    except requests.exceptions.ConnectionError:
        error = "Connection Error!"
        app.logger.error(error)
    else:
        return data
    errorMessage = {"Status": False, "Komunikat": error}
    return errorMessage


def putToWebService(payload, subpage):
    data = json.dumps(payload)
    clen = len(data)
    try:
        f = requests.put(WEBSERVICE_IP + subpage, data=data,
            headers={'Content-Type': 'application/json',
            'Content-Length': clen})
        data = f.json()
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
            error = e
    except requests.exceptions.ConnectionError:
        error = "Connection Error!"
        app.logger.error(error)
    else:
        return data
    errorMessage = {"Status": False, "Komunikat": error}
    return errorMessage


def sanitize_html(value):
    soup = BeautifulSoup(value)
    for tag in soup.findAll(True):
        if tag.name not in VALID_TAGS:
            tag.hidden = True
    return soup.renderContents()


def sendFileToWebService(fileData, subpage):
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
                app.logger.error('Value Error has been found.\nReason: '
                    + error)
            elif hasattr(e, 'code'):
                error = e.code
                app.logger.error('Value Error has been found.\nError code:'
                    + error)
        except requests.exceptions.ConnectionError:
            error = "Connection Error!"
            app.logger.error(error)
        else:
            return data
    else:
        error = 'File format not valid!'
        app.logger.error(error)
    errorMessage = {"Status": False, "Komunikat": error}
    return errorMessage

# error pages


def ws_error():
    return render_template('error.html', errorNo=502,
        errorMe="WebService is not responding!")


@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', username=session['username'],
        errorNo=404, errorMe="The page You're looking for isn't here!")

# page methods


def check_ws():
    try:
        r = requests.head(WEBSERVICE_IP)
    except requests.exceptions.ConnectionError:
        return False
    return r.status_code == 200


def check_perm(page):
    pageList = page.split('/')
    print pageList
    if (pageList[0] == 'edit_profile'):
        #response = getFromWebService("/" + session['username'] + "/privacy")
        #if response.get('Status') is True:
        #    print response
        if session['admin_box'] is True:
            return True
        if (pageList[1] == session['username']):
            return True
        return False
    elif (pageList[0] == 'messages'):
        if (pageList[1] == session['username']):
            return True
        return False
    return True


@app.route('/main.js')
def main_js():
    return render_template('main.js')


@app.route('/')
def news():
    news = [{"title": "2013-06-03: Avatars!", "text": "Finally our project"
        + " support avatars. Go to your profile page and edit your data to add"
        + " your wonderfull avatar."},
            {"title": "2013-05-26: Tests launched!", "text": "Tests are"
        + " officially launched. Our team is working on bringing the service"
        + " as soon as possible to the state friendly to users."}]
    if check_ws() is False:
        return ws_error()
    if "username" in session:
        return render_template('news.html', username=session['username'],
            cMessages=check_messages(), news=news)
    else:
        return render_template('news.html', username="", news=news)

# page methods - registration and login


@app.route('/register', methods=['GET', 'POST'])
def register():
    if check_ws() is False:
        return ws_error()
    error = None
    if request.method == 'POST':
        mdpass = md5.new(request.form['password'].encode('utf-8', 'ignore'))
        payload = {
            "Login": sanitize_html(request.form['username']
                .encode('utf-8', 'ignore')),
            "Password": mdpass.hexdigest(),
            "Name": sanitize_html(request.form['name']
                .encode('utf-8', 'ignore')),
            "Surname": sanitize_html(request.form['surname']
                .encode('utf-8', 'ignore')),
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


@app.route('/activation/<webHash>')
def try_to_activate(webHash):
    if check_ws() is False:
        return ws_error()
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


@app.route('/login', methods=['GET', 'POST'])
def login():
    if check_ws() is False:
        return ws_error()
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
            if response.get('Groups') is 1:
                session['admin_box'] = True
            session['username'] = request.form['username']
            response2 = getFromWebService("/" + request.form['username']
                + "/other")
            if response2.get('Status') is True:
                session['pagination'] = response2.get('Pagination')
            flash('You were logged in %s' % session['username'])
            return redirect(url_for('news'))
        else:
            error = response.get('Komunikat')
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', "")
    session.pop('pagination', 25)
    session.pop('admin_box', None)
    flash('You were logged out')
    return redirect(url_for('news'))

# page methods - messages system


def check_messages():
    if check_perm('messages/' + session['username']) is False:
        return render_template('message.html',
            message="You are not permitted to see that page!")
    error = None
    response = getFromWebService("/notice/" + session['username'] + "/new")
    if response.get('Status') is True:
        return response.get('Count')
    else:
        error = "Problem with messages! " + str(response.get('Komunikat'))
    return error


@app.route('/post_box')
def post_box():
    if check_ws() is False:
        return ws_error()
    error = None
    response = getFromWebService("/notice/" + session['username'])
    if response.get('Status') is True:
        messages = []
        for i in range(1, session['pagination']):
            nextOne = response.get(str(i))
            if nextOne is not None:
                messages.append(dict(nextOne))
        return render_template('post_box.html', username=session['username'],
            cMessages=check_messages(), messages=messages)
    else:
        error = "ERROR"
    return render_template('post_box.html', username=session['username'],
            cMessages=check_messages(), error=error)

# page methods - user profile


@app.route('/user')
def user():
    if check_ws() is False:
        return ws_error()
    return show_user_profile(session['username'])


@app.route('/user/<nick>')
def show_user_profile(nick):
    if check_ws() is False:
        return ws_error()
    visibleEmail = False
    response = getFromWebService("/" + sanitize_html(nick) + "/privacy")
    if response.get('Status') is True:
        visibleEmail = response.get('PublicEmail')
    response = getFromWebService("/" + sanitize_html(nick) + "/about")
    if response.get('Status') is True:
        response.update({"nick": nick})
        if visibleEmail is False:
            response.update({'Email': ""})
        canEdit = check_perm('edit_profile/' + nick)
        return render_template('profile.html', cMessages=check_messages(),
            username=session['username'], profile=dict(response),
            canEdit=canEdit)
    else:
        error = response.get('Komunikat')
    return render_template('message.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/edit_profile/<edited>', methods=['GET', 'POST'])
def edit_profile(edited):
    if check_ws() is False:
        return ws_error()
    if check_perm('edit_profile/' + edited) is False:
        return render_template('message.html',
            message="You are not permitted to see that page!")
    error = None
    if request.method == 'POST':
        payload = {
            "Login": sanitize_html(edited),
            "Name": sanitize_html(request.form['name']
                .encode('utf-8', 'ignore')),
            "Surname": sanitize_html(request.form['surname']
                .encode('utf-8', 'ignore')),
            "Email": request.form['e_mail'],
            "Sex": request.form['sex'],
            "Avatar": request.form['avatar']
        }
        response = postToWebService(payload, "/" + payload['Login'] + "/about")
        if response.get('Status') is True:
            return redirect(url_for('user'))
        else:
            error = response.get('Komunikat')
    response = getFromWebService("/" + sanitize_html(edited) + "/about")
    if response.get('Status') is True:
        response.update({"nick": edited})
        return render_template('edit_profile.html',
            username=session['username'], error=error,
            cMessages=check_messages(), edited=edited, profile=dict(response))
    else:
        return render_template('message.html', username=session['username'],
            error=error, cMessages=check_messages())

# page methods - users list


@app.route('/users')
def users():
    return users_p(0)


@app.route('/users/<int:page>')
def users_p(page):
    if check_ws() is False:
        return ws_error()
    error = None
    userRes = getFromWebService("/games/duels/" + session['username']
        + "/" + str(page) + "/list")
    if userRes.get('Status') is True:
        logins = []
        for i in range(1, session['pagination']):
            nextOne = userRes.get(str(i))
            if nextOne is not None:
                logins.append(nextOne)
        nextP = False
        if logins.count == session['pagination']:
            nextP = True
        return render_template('users.html',
            cMessages=check_messages(), username=session['username'],
            users=logins, page=page, next=nextP)
    error = userRes.get('Komunikat')
    return render_template('users.html', username=session['username'],
        error=error, cMessages=check_messages(), page=page, next=False)

# page methods - admin box


@app.route('/admin_tools')
def admin_box():
    if check_ws() is False:
        return ws_error()
    return render_template('admin_tools.html', username=session['username'],
            cMessages=check_messages())

# page methods - battles


@app.route('/battles')
def battles():
    if check_ws() is False:
        return ws_error()
    error = None
    response = getFromWebService("/" + session['username'] + "/duels")
    if response.get('Status') is True:
        battles = []
        for i in range(1, session['pagination']):
            nextOne = response.get(str(i))
            if nextOne is not None:
                battleInfo = getFromWebService("/games/" + str(nextOne)
                    + "/about")
                battleInfo.update({'Nr': nextOne})
                if battleInfo.get('Status') is True:
                    battles.append(dict(battleInfo))
        return render_template('battles.html', username=session['username'],
            battles=battles, cMessages=check_messages())
    else:
        error = response.get('Komunikat')
    return render_template('battles.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/choose_oponent')
def choose_oponent():
    if check_ws() is False:
        return ws_error()
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
    error = userRes.get('Komunikat')
    return render_template('choose_oponent.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/invite', methods=['GET', 'POST'])
def new_inv():
    if check_ws() is False:
        return ws_error()
    return invite_to_battle(sanitize_html(session['username']),
        sanitize_html(request.form['oponent']),
        sanitize_html(request.form['game']))


def invite_to_battle(uFrom, uTo, gameName):
    error = None
    payload = {
        "UserFrom": uFrom,
        "UserTo": uTo,
        "Game": gameName,
        "Type": "Duel"
    }
    response = postToWebService(payload, "/notice/invitation")
    if response.get('Status') is True:
        flash("Successful invitation to the battle.")
        return redirect(url_for('news'))
    else:
        error = str(response.get('Komunikat'))
    userRes = getFromWebService("/games/duels/" + session['username']
        + "/0/list")
    if userRes.get('Status') is True:
        logins = []
        for i in range(1, session['pagination']):
            nextOne = userRes.get(str(i))
            if nextOne is not None:
                logins.append(nextOne)
        return render_template('choose_oponent.html',
            cMessages=check_messages(), username=session['username'],
            users=logins, error=error)
    else:
        error = error + "\n" + userRes.get('Komunikat')
    return render_template('choose_oponent.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/no_duel/<int:invId>', methods=['GET', 'POST'])
def no_duel(invId):
    if check_ws() is False:
        return ws_error()
    return cancel_battle(invId)


def cancel_battle(invId):
    error = None
    payload = {
        "invitationID": invId
    }
    response = putToWebService(payload, "/notice/invitation/decline")
    if response.get('Status') is True:
        flash("You refused that invitation.")
        return redirect(url_for('news'))
    else:
        error = str(response.get('Komunikat'))
    return render_template('news.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/duel/<opponent>/<game>/<int:invId>', methods=['GET', 'POST'])
def new_duel(opponent, game, invId):
    if check_ws() is False:
        return ws_error()
    return register_battle(sanitize_html(session['username']),
        sanitize_html(opponent),
        sanitize_html(game),
        invId)


def register_battle(login1, login2, gameName, invId):
    error = None
    payload = {
        "User1": login1,
        "User2": login2,
        "GameName": gameName,
        "ID": invId
    }
    response = postToWebService(payload, "/games/duels/registry")
    if response.get('Status') is True:
        flash("You accepted this invitation.")
        return redirect(url_for('news'))
    else:
        error = str(response.get('Komunikat'))
    return render_template('news.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/view_battle/<int:number>/<game>')
def view_battle(number, game):
    if check_ws() is False:
        return ws_error()
    error = None
    response = getFromWebService("/games/" + str(number) + "/info")
    if response.get('Status') is True:
        if (response.get('Finished') == 't'):
            return render_template('view_battle.html',
                username=session['username'], cMessages=check_messages(),
                number=number, game=game, winner=response.get('Winner'),
                error=error, message=response.get('Message'))
    else:
        error = response
    return render_template('send_code.html', username=session['username'],
        cMessages=check_messages(), number=number, game=game, error=error,
        winner=response.get('Winner'), message=response.get('Message'))


@app.route('/sendCode/<int:idG>/<game>', methods=['GET', 'POST'])
def send_code(idG, game):
    if check_ws() is False:
        return ws_error()
    error = None
    if request.method == 'POST':
        if request.form['codeForm'] == 'text':
            payload = {
                "From": session['username'],
                "Language": request.form['lang'],
                "GameID": idG,
                "Game": game,
                "Code": request.form['code'],
                "FileName": request.form['fileName']
            }
            response = postToWebService(payload, "/code/upload")
            if response.get('Status') is True:
                return render_template('message.html', message="Code sent!",
                    error=error, cMessages=check_messages())
            else:
                error = response
        #elif request.form['codeForm'] == 'file':
        #    print request.form['file']
        #    response = sendFileToWebService(request.form['file'],
        #        "/code/upload/" + game + "/" + idG + "/" + session['username'])
    return render_template('message.html', message="Something's wrong! :'(",
        error=error, cMessages=check_messages())

# page methods - tournaments


@app.route('/tournaments')
def tournaments():
    if check_ws() is False:
        return ws_error()
    return render_template('tournaments.html', username=session['username'],
        cMessages=check_messages())

# app start

if __name__ == '__main__':
    app.run(host='0.0.0.0')
