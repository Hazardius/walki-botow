# -*- coding: utf-8 -*-

# all the imports
from __future__ import with_statement
from flask import Flask, request, session, redirect, url_for, \
     render_template, flash, send_from_directory
from BeautifulSoup import BeautifulSoup
import json
import md5
import os
import requests
from requests.auth import HTTPDigestAuth
from urllib2 import URLError
from werkzeug import secure_filename
import xml.etree.ElementTree as ET

# configuration
DEBUG = True
SECRET_KEY = '\xc0\xd7O\xb3\'q\\\x19m\xb3uW\x16\xc2\r\x88\x91\xdbIv\x8d\x8f\xe9\x1f'
SECOND_SECRET_KEY = md5.new('Hazardius').hexdigest()

import socket

lastRegistration = 0.0

timeout = 10
socket.setdefaulttimeout(timeout)

# address of WebService server
WEBSERVICE_IP = "http://77.65.54.170:9005"
TESTING = False

# list of allowed extensions
ALLOWED_EXTENSIONS_FILE = set(['java', 'cpp', 'py', 'cs', 'p'])
ALLOWED_EXTENSIONS_DOC = set(['zip'])
UPLOAD_FOLDER = 'temp'

VALID_TAGS = ['strong', 'em', 'p', 'ul', 'li', 'br']

# create our application
app = Flask(__name__)
app.config.from_object(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# methods


def allowed_codeFile(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS_FILE


def getAtomFromWebService(newsID):
    try:
        f = requests.get(WEBSERVICE_IP + "/news/retrieve/" + str(newsID) +
            "?media=atom", auth=HTTPDigestAuth('Flask', SECOND_SECRET_KEY))
        data = ET.fromstring(f.content)
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
    except ET.ParseError:
        error = "XML Parse error!"
    except requests.exceptions.ConnectionError:
        error = "[GetAtom]Connection Error!"
        app.logger.error(error)
    else:
        return data
    errorMessage = {"Status": False, "Message": error}
    return errorMessage


def getFromWebService(subpage):
    try:
        f = requests.get(WEBSERVICE_IP + subpage, auth=HTTPDigestAuth('Flask',
            SECOND_SECRET_KEY))
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
        error = "[Get]Connection Error!"
        app.logger.error(error)
    else:
        return data
    errorMessage = {"Status": False, "Message": error}
    return errorMessage


def postToWebService(payload, subpage):
    data = json.dumps(payload)
    clen = len(data)
    try:
        f = requests.post(WEBSERVICE_IP + subpage, data=data,
            headers={'Content-Type': 'application/json',
            'Content-Length': clen}, auth=HTTPDigestAuth('Flask',
            SECOND_SECRET_KEY))
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
        error = "[Post]Connection Error!"
        app.logger.error(error)
    else:
        return data
    errorMessage = {"Status": False, "Message": error}
    return errorMessage


def putToWebService(payload, subpage):
    data = json.dumps(payload)
    clen = len(data)
    try:
        f = requests.put(WEBSERVICE_IP + subpage, data=data,
            headers={'Content-Type': 'application/json',
            'Content-Length': clen}, auth=HTTPDigestAuth('Flask',
            SECOND_SECRET_KEY))
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
        error = "[Put]Connection Error!"
        app.logger.error(error)
    else:
        return data
    errorMessage = {"Status": False, "Message": error}
    return errorMessage


def sanitize_html(value):
    value = value.replace("'", "")
    value = value.replace('"', "")
    value = value.replace("`", "")
    value = value.replace("$", "")
    value = value.replace("^", "")
    value = value.replace("&", "")
    value = value.replace("*", "")
    soup = BeautifulSoup(value)
    for tag in soup.findAll(True):
        if tag.name not in VALID_TAGS:
            tag.hidden = True
    return soup.renderContents()


def sendFileToWebService(filename, subpage):
    error = None
    data = open(filename, 'rb')
    try:
        response = requests.post(WEBSERVICE_IP + subpage, data,
            headers={'Content-Type': 'application/octet-stream'},
            auth=HTTPDigestAuth('Flask', SECOND_SECRET_KEY))
        data = response.json()
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
    except AttributeError, e:
        error = "No JSON as a response.\nResponse: " + str(response)
    except requests.exceptions.ConnectionError:
        print e
        error = "[SendFile]Connection Error!"
        app.logger.error(error)
    else:
        return data
    errorMessage = {"Status": False, "Message": error}
    return errorMessage

# error pages


def ban_error():
    return render_template('error.html', errorNo=403,
        errorMe="Forbidden!")


def ws_error():
    return render_template('error.html', errorNo=502,
        errorMe="Bad Gateway! WebService is not responding.")


def spam_error():
    return render_template('error.html', errorNo=429,
        errorMe="Too Many Requests! One request per 3 seconds allowed.")


@app.errorhandler(404)
def not_found(error):
    if "username" in session:
        return render_template('error.html', username=session['username'],
            errorNo=404, errorMe="The page You're looking for isn't here!")
    else:
        return render_template('error.html', errorNo=404,
            errorMe="The page You're looking for isn't here!")

# page methods


def check_spam():
    import time
    if 'lastTime' in session:
        lastTime = session['lastTime']
    else:
        lastTime = 0.0
    session['lastTime'] = time.time()
    if lastTime:
        if (session['lastTime'] - lastTime < 0.5):
            return False
    return True


def check_regTime():
    import time
    global lastRegistration
    prevRegistration = lastRegistration
    lastRegistration = time.time()
    if (lastRegistration - prevRegistration < 10.0):
        return False
    return True


def check_ws():
    try:
        r = requests.head(WEBSERVICE_IP, auth=HTTPDigestAuth('Flask',
            SECOND_SECRET_KEY))
    except requests.exceptions.ConnectionError:
        return False
    return r.status_code == 200


def check_perm(page):
    pageList = page.split('/')
    if (pageList[0] == 'edit_profile'):
        if "permissions" in session:
            if 'Change users profile' in session['permissions']:
                return True
        if "username" in session:
            if (pageList[1] == session['username']):
                return True
        return False
    elif (pageList[0] == 'game'):
        if "permissions" in session:
            if 'Change users profile' in session['permissions']:
                return True
        if "username" in session:
            if (pageList[1] == session['username'] or pageList[2] == session[
                'username']):
                return True
        return False
    elif (pageList[0] == 'messages'):
        if "username" in session:
            if (pageList[1] == session['username']):
                return True
        return False
    elif (pageList[0] == 'creTour'):
        if "permissions" in session:
            if 'Create tournaments' in session['permissions']:
                return True
        return False
    elif (pageList[0] == 'creNews'):
        if "permissions" in session:
            if "Adding news's" in session['permissions']:
                return True
        return False
    elif (pageList[0] == 'admin'):
        if "permissions" in session:
            if 'Site settings' in session['permissions']:
                return True
        return False
    return True


def is_ban():
    #print str(request.remote_addr)
    #if (request.remote_addr == BANNEDIP):
        #return True
    return False


@app.route('/help/<gamefile>')
def help(gamefile):
    if check_spam() is False:
        return spam_error()
    locFilePath = os.path.normpath(gamefile)
    direct = os.path.normpath(app.config['UPLOAD_FOLDER'])
    return send_from_directory(direct, locFilePath)

# page methods - news


@app.route('/')
def news():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    if "pagination" in session:
        response = getFromWebService("/news/" + str(0) + "/" + str(session[
            'pagination']) + "/retrieve")
    else:
        response = getFromWebService("/news/" + str(0) + "/" + str(25) +
            "/retrieve")
    if response.get('Status') is True:
        news = []
        for i in range(1, response.get('Count') + 1):
            response2 = getAtomFromWebService(response.get(str(i)))
            if response2.get('Status') is True:
                oneNews = {}
                for field in response2:
                    shortTag = field.tag.split('}')[1]
                    if shortTag == "author":
                        for deepField in field:
                            info = deepField.text
                    elif shortTag == "entry":
                        for deepField in field:
                            shorterTag = deepField.tag.split('}')[1]
                            if shorterTag == "published":
                                shorterText = deepField.text.split('T')[0]
                                oneNews.update({shorterTag: shorterText})
                            elif shorterTag == "summary":
                                oneNews.update({shorterTag: deepField.text})
                            elif shorterTag == "title":
                                info = deepField.text
                    else:
                        info = field.text
                    oneNews.update({shortTag: info})
                news.append(oneNews)
        news = sorted(news, key=lambda art: art['published'], reverse=True)
        if "username" in session:
            return render_template('news.html', username=session['username'],
                cMessages=check_messages(), news=news)
        else:
            return render_template('news.html', news=news)
    error = response.get('Message')
    if "username" in session:
        return render_template('news.html', username=session['username'],
            cMessages=check_messages(), error=error)
    else:
        return render_template('news.html', error=error)


@app.route('/add_news', methods=['GET', 'POST'])
def add_news():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    if check_perm('admin') is False:
        return render_template('message.html', cMessages=check_messages(),
            message="You are not permitted to see that page!")
    error = None
    if request.method == 'POST':
        import time
        dateTime = time.strftime("%Y-%m-%d", time.gmtime())
        try:
            pub = request.form['pubDate'].encode('ascii')
        except KeyError:
            pub = dateTime
        try:
            test = request.form['enaCom']
            test = True
        except KeyError:
            test = False
        payload = {
            "Publish": pub,
            "Created": dateTime,
            "Title": sanitize_html(request.form['title']
                .encode('utf-8', 'ignore')),
            "Description": sanitize_html(request.form['shorDesc']
                .encode('utf-8', 'ignore')),
            "FullDescription": sanitize_html(request.form['longDesc']
                .encode('utf-8', 'ignore')),
            "Type": request.form['newsType'].encode('ascii'),
            "Comments": test,
            "Author": session['username'].encode('ascii')
        }
        response = postToWebService(payload, "/news/create")
        if response.get('Status') is True:
            return render_template('message.html', cMessages=check_messages(),
                message="New news successfully created!", error=error)
        else:
            error = response
    return render_template('add_news.html', username=session['username'],
        cMessages=check_messages(), error=error)

# page methods - registration and login


@app.route('/register', methods=['GET', 'POST'])
def register():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ws_error()
    error = None
    if request.method == 'POST':
        if check_regTime() is True:
            mdpass = md5.new(request.form['password'].encode('utf-8', 'ignore'))
            payload = {
                "Login": sanitize_html(request.form['username']
                    .encode('utf-8', 'ignore')),
                "Password": mdpass.hexdigest(),
                "Name": sanitize_html(request.form['name']
                    .encode('utf-8', 'ignore')),
                "Surname": sanitize_html(request.form['surname']
                    .encode('utf-8', 'ignore')),
                "Email": sanitize_html(request.form['e_mail']),
                "Sex": request.form['sex']
            }
            response = postToWebService(payload, "/user/registration")
            if response.get('Status') is True:
                return render_template('message.html',
                    message="Check your e-mail account!")
            else:
                error = response.get('Message')
        else:
            error = "One registration per 10 seconds allowed."
    return render_template('register.html', error=error)


@app.route('/activation/<webHash>')
def try_to_activate(webHash):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
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
        error = response.get('Message')
    return render_template('message.html', message=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    if "logged_in" in session:
        if session['logged_in'] is True:
            return render_template('message.html', cMessages=check_messages(),
                message="You are already logged in!",
                username=session['username'])
        else:
            return render_template('message.html', cMessages=check_messages(),
                message="Strange! Error no. 1. Let the admin know about it.")
    else:
        error = None
        if request.method == 'POST':
            mdpass = md5.new(request.form['password'])
            payload = {
                "Login": sanitize_html(request.form['username']),
                "Password": mdpass.hexdigest(),
                "IP": request.remote_addr
            }
            response = postToWebService(payload, "/login")
            if response.get('Status') is True:
                perCount = response.get('Count')
                permissions = []
                for i in range(1, perCount + 1):
                    permissions.append(response.get(str(i)))
                session['permissions'] = permissions
                session['logged_in'] = True
                session['username'] = request.form['username']
                session['pagination'] = 10
                flash('You were logged in %s' % session['username'])
                return redirect(url_for('news'))
            else:
                error = response.get('Message')
        return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('pagination', 10)
    session.pop('permissions', None)
    flash('You were logged out')
    return redirect(url_for('news'))

# page methods - messages system


def check_messages():
    if check_perm('messages/' + session['username']) is False:
        return render_template('message.html', cMessages=check_messages(),
            message="You are not permitted to see that page!")
    error = None
    response = getFromWebService("/notice/" + session['username'] + "/new")
    if response.get('Status') is True:
        return response.get('Count')
    else:
        error = "Problem with messages!"
    return error


@app.route('/post_box')
def post_box():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
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
    return show_user_profile(session['username'])


@app.route('/user/<nick>')
def show_user_profile(nick):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    visibleEmail = False
    response = getFromWebService("/" + sanitize_html(nick) + "/privacy")
    if response.get('Status') is True:
        visibleEmail = response.get('PublicEmail')
    response = getFromWebService("/" + sanitize_html(nick) + "/about")
    if response.get('Status') is True:
        response.update({"nick": nick})
        if 'Avatar' in response:
            if response.get('Avatar') == response.get('Email'):
                # Found a Gravatar
                response.update({'Avatar': "http://www.gravatar.com/avatar/" +
                    md5.new(response.get('Email').lower()).hexdigest()
                    + "?s=150&d=retro"})
            if response.get('Avatar') == "":
                # No avatar set - try to get Gravatar
                response.update({'Avatar': "http://www.gravatar.com/avatar/" +
                    md5.new(response.get('Email').lower()).hexdigest()
                    + "?s=150&d=retro"})
        else:
            # No avatar set - try to get Gravatar
            response.update({'Avatar': "http://www.gravatar.com/avatar/" +
                md5.new(response.get('Email').lower()).hexdigest()
                + "?s=150&d=retro"})
        if nick != session['username']:
            if visibleEmail is False:
                response.update({'Email': ""})
        canEdit = check_perm('edit_profile/' + nick)
        return render_template('profile.html', cMessages=check_messages(),
            username=session['username'], profile=dict(response),
            canEdit=canEdit)
    else:
        error = response.get('Message')
    return render_template('message.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/edit_profile/<edited>', methods=['GET', 'POST'])
def edit_profile(edited):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    if check_perm('edit_profile/' + edited) is False:
        if "username" in session:
            return render_template('message.html', cMessages=check_messages(),
                message="You are not permitted to see that page!")
        else:
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
            "Email": sanitize_html(request.form['e_mail']),
            "Sex": request.form['sex'],
            "Avatar": sanitize_html(request.form['avatar']),
            "Editor": session['username']
        }
        response = postToWebService(payload, "/" + payload['Login'] + "/about")
        if response.get('Status') is True:
            if (int(request.form['pagination']) < 5):
                session['pagination'] = 5
            elif (int(request.form['pagination']) > 25):
                session['pagination'] = 25
            else:
                session['pagination'] = int(request.form['pagination'])
            if "eNot" in request.form:
                eNot = True
            else:
                eNot = False
            if "eNotD" in request.form:
                eNotD = True
            else:
                eNotD = False
            if "eNotT" in request.form:
                eNotT = True
            else:
                eNotT = False
            payload2 = {
                "EmailNotice": eNot,
                "EmailDuelNotice": eNotD,
                "EmailTournamentNotice": eNotT,
                "Editor": session['username']
            }
            response2 = postToWebService(payload2, "/" + payload['Login']
                + "/other")
            if response2.get('Status') is True:
                return redirect(url_for('show_user_profile', nick=payload[
                    'Login']))
            else:
                error = response.get('Message') + " Profile partially edited!"
        else:
            error = response.get('Message')
    response = getFromWebService("/" + sanitize_html(edited) + "/about")
    if response.get('Status') is True:
        response.update({"nick": edited})
        response2 = getFromWebService('/' + sanitize_html(edited) + "/other")
        if response2.get('Status') is True:
            response.update(response2)
            response.update({"Pagination": session['pagination']})
            if 'Change users profile' in session['permissions']:
                response3 = getFromWebService('/user/groups')
                if response3.get('Status') is True:
                    print response3
            return render_template('edit_profile.html',
                username=session['username'], error=error, edited=edited,
                cMessages=check_messages(), profile=dict(response))
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
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    userRes = getFromWebService("/games/duels/" + session['username']
        + "/" + str(page) + "/" + str(session['pagination']) + "/list")
    if userRes.get('Status') is True:
        logins = []
        for i in range(1, session['pagination'] + 1):
            nextOne = userRes.get(str(i))
            if nextOne is not None:
                logins.append(nextOne)
        nextP = False
        if len(logins) == session['pagination']:
            nextP = True
        return render_template('users.html',
            cMessages=check_messages(), username=session['username'],
            users=logins, page=page, next=nextP)
    error = userRes.get('Message')
    return render_template('users.html', username=session['username'],
        error=error, cMessages=check_messages(), page=page, next=False)

# page methods - admin box


@app.route('/admin_tools')
def admin_box():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    if check_perm('admin') is False:
        return render_template('message.html', cMessages=check_messages(),
            message="You are not permitted to see that page!")
    return render_template('admin_tools.html', username=session['username'],
            cMessages=check_messages())

# page methods - battles


@app.route('/battles')
def battles():
    return battles_p(0)


@app.route('/battles/<int:page>')
def battles_p(page):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    response = getFromWebService("/" + session['username'] + "/" + str(page) +
        "/" + str(session['pagination']) + "/duels")
    if response.get('Status') is True:
        battles = []
        for i in range(1, session['pagination'] + 1):
            nextOne = response.get(str(i))
            if nextOne is not None:
                battleInfo = getFromWebService("/games/" + str(nextOne)
                    + "/about")
                battleInfo.update({'Nr': nextOne})
                if battleInfo.get('Status') is True:
                    battles.append(dict(battleInfo))
        battles = sorted(battles, key=lambda bat: bat['Nr'])
        nextP = False
        if len(battles) == session['pagination']:
            nextP = True
        return render_template('battles.html', username=session['username'],
            battles=battles, cMessages=check_messages(), page=page, next=nextP)
    else:
        error = response.get('Message')
    return render_template('battles.html', username=session['username'],
        error=error, cMessages=check_messages(), page=page, next=False)


@app.route('/choose_oponent')
def choose_oponent():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
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
    error = userRes.get('Message')
    return render_template('choose_oponent.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/invite', methods=['GET', 'POST'])
def new_inv():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
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
        error = response.get('Message')
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
        error = error + "\n" + userRes.get('Message')
    return render_template('choose_oponent.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/no_duel/<int:invId>', methods=['GET', 'POST'])
def no_duel(invId):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
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
        error = response.get('Message')
    return render_template('news.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/duel/<int:invId>', methods=['GET', 'POST'])
def new_duel(invId):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    return register_battle(invId)


def register_battle(invId):
    error = None
    payload = {
        "ID": invId
    }
    response = postToWebService(payload, "/games/duels/registry")
    if response.get('Status') is True:
        flash("You accepted this invitation.")
        return redirect(url_for('news'))
    else:
        error = response.get('Message')
    return render_template('news.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/view_battle/<int:number>')
def view_battle(number):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    gameName = ""
    response = getFromWebService("/games/" + str(number) + "/about")
    if response.get('Status') is True:
        gameName = response.get('GameName')
        if check_perm('game/' + response.get('Player1') + "/" + response.get(
            'Player2')) is False:
            return render_template('message.html', cMessages=check_messages(),
                message="You are not permitted to see that page!")
    else:
        message = ("Error while checking permissions! " + str(response.get(
            'Message')))
        return render_template('message.html', cMessages=check_messages(),
            message=message)
    response = getFromWebService("/games/" + str(number) + "/info")
    if response.get('Status') is True:
        if "Message" in response:
            if response.get('Message') == "Waiting for compilation":
                return render_template('view_battle.html',
                    username=session['username'], cMessages=check_messages(),
                    number=number, game=gameName, winner=response.get('Winner'),
                    error=error, message=response.get('Message'))
        if response.get('Finished') is True:
            try:
                conError = ""
                r = requests.get(WEBSERVICE_IP + "/code/" +
                    sanitize_html(gameName) + "/" + str(number) + "/log",
                    stream=True, auth=HTTPDigestAuth('Flask',
                    SECOND_SECRET_KEY))
                if r.status_code == 200:
                    #locFilePath = os.path.join(app.config['UPLOAD_FOLDER'],
                        #"log" + session['username'] + ".txt")
                    #locFilePath = os.path.normpath(locFilePath)
                    zmienna = ""
                    for chunk in r.iter_content():
                        zmienna = zmienna + str(chunk)
                    #with open(locFilePath, 'wb') as f:
                        #for chunk in r.iter_content():
                            #f.write(chunk)
                    #with open(locFilePath, 'r') as content_file:
                        #conError = content_file.read()
                    #os.remove(locFilePath)
                    #conError = ("<br />".join(zmienna.split("\n")))
                    conError = zmienna
                    #print conError
                else:
                    conError = "Wrong code of response: " + str(r.status_code)
            except URLError, e:
                if hasattr(e, 'reason'):
                    conError = e.reason
                    app.logger.error('We failed to reach a server.\nReason: '
                        + conError)
                elif hasattr(e, 'code'):
                    conError = e.code
                    app.logger.error('The server couldn\'t fulfill the request.'
                        + '\nError code:' + conError)
            except ValueError, e:
                if hasattr(e, 'reason'):
                    conError = e.reason
                    app.logger.error('Value Error has been found.\nReason: '
                        + conError)
                elif hasattr(e, 'code'):
                    conError = e.code
                    app.logger.error('Value Error has been found.\nError code:'
                        + conError)
                else:
                    conError = e
            except requests.exceptions.ConnectionError:
                conError = "Connection Error!"
                app.logger.error(conError)
            gameLog = conError
            return render_template('view_battle.html',
                username=session['username'], cMessages=check_messages(),
                number=number, game=gameName, winner=response.get('Winner'),
                error=error, message=response.get('Message'), log=gameLog)
    else:
        error = response
    return render_template('send_code.html', username=session['username'],
        cMessages=check_messages(), number=number, game=gameName, error=error,
        winner=response.get('Winner'), message=response.get('Message'))


@app.route('/sendCode/<int:idG>/<game>', methods=['GET', 'POST'])
def send_code(idG, game):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    if request.method == 'POST':
        if request.form['codeForm'] == 'text':
            exten = request.form['lang']
            payload = {
                "From": sanitize_html(session['username']),
                "Language": sanitize_html(exten),
                "GameID": idG,
                "Game": sanitize_html(game),
                "Code": sanitize_html(request.form['code']),
                "FileName": sanitize_html(str(idG) + str(game) + session[
                    'username']) + "." + exten
            }
            response = postToWebService(payload, "/code/upload")
            if response.get('Status') is True:
                return render_template('message.html', message="Code sent!",
                    error=error, cMessages=check_messages(),
                    username=session['username'])
            else:
                error = response
        elif request.form['codeForm'] == 'file':
            codeFile = request.files['file']
            if codeFile and allowed_codeFile(codeFile.filename):
                filename = secure_filename(codeFile.filename)
                locFilePath = os.path.join(app.config['UPLOAD_FOLDER'],
                    filename)
                locFilePath = os.path.normpath(locFilePath)
                codeFile.save(locFilePath)
                response = sendFileToWebService(locFilePath, "/code/upload/" +
                    game + "/" + str(idG) + "/" + session['username'] + "/" +
                    filename)
                if response.get('Status') is True:
                    os.remove(locFilePath)
                    return render_template('message.html',
                        username=session['username'], error=error,
                        message="File uploaded!", cMessages=check_messages())
                else:
                    error = response.get('Message')
                os.remove(locFilePath)
            else:
                error = 'File format not valid!'
                app.logger.error(error)
    return render_template('message.html', username=session['username'],
        error=error, cMessages=check_messages())

# page methods - tournaments


@app.route('/tournaments')
def tournaments():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    response = getFromWebService("/games/" + str(0) + "/" + str(session[
        'pagination']) + "/tournaments")
    if response.get('Status') is True:
        if response.get('Count') != 0:
            tours = []
            for i in range(1, response.get('Count') + 1):
                nextOne = response.get(str(i))
                if nextOne is not None:
                    tours.append(dict(nextOne))
            tours = sorted(tours, key=lambda bat: bat['ID'])
            return render_template('tournaments.html',
                username=session['username'], tours=tours,
                cMessages=check_messages())
    else:
        error = response.get('Message')
    return render_template('tournaments.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/tournament/<int:tourId>')
def tournament(tourId):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    response = getFromWebService("/games/tournaments/" + str(tourId) + "/info")
    if response.get('Status') is True:
        tour = response
        return render_template('tournament.html', tourId=tourId,
            tour=tour, cMessages=check_messages(), username=session[
            'username'], error=error)
    return render_template('tournament.html', tourId=tourId,
        cMessages=check_messages(), username=session['username'], error=error)


@app.route('/new_tournament', methods=['GET', 'POST'])
def new_tournament():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    if check_perm('creTour') is False:
        return render_template('message.html', cMessages=check_messages(),
            message="You are not permitted to see that page!")
    error = None
    if request.method == 'POST':
        payload = {
            "TourName": sanitize_html(request.form['name']),
            "Name": sanitize_html(request.form['game']),
            "Description": sanitize_html(request.form['description']),
            "Rules": sanitize_html(request.form['rules'])
        }
        response = postToWebService(payload, "/games/tournaments/new")
        if response.get('Status') is True:
            tourID = response.get('ID')
            payload = {
                "RegBegin": sanitize_html(request.form['bDate'].replace("T",
                    " ") + ":00"),
                "RegEnd": sanitize_html(request.form['eDate'].replace("T",
                    " ") + ":00"),
                "RegType": sanitize_html(request.form['regType']),
                "MaxPlayers": request.form['maxPl'],
                "Start": sanitize_html(request.form['sDate'].replace("T",
                    " ") + ":00"),
                "TourID": tourID,
                "Type": sanitize_html(request.form['tourType'])
            }
            response2 = postToWebService(payload, "/games/tournaments/"
                + str(tourID) + "/info")
            print response2
            return render_template('message.html', cMessages=check_messages(),
                message="New tournament successfully created!", error=error)
        else:
            error = response
    return render_template('new_tournament.html', username=session['username'],
        cMessages=check_messages(), error=error)

# debug


#@app.route('/secret', methods=['GET', 'POST'])
#def secret():
    #payload = {
        #"Editor": session['username'],
        #"Count": 1,
        #"1": "Super admin"
    #}
    #response = postToWebService(payload, "/Hazardius/groups")
    #if response.get('Status') is True:
        #return render_template('message.html', username=session['username'],
            #message="PRZESLANE!")
    #error = response.get('Message')
    #return render_template('message.html', username=session['username'],
        #message=error)

# app start

if __name__ == '__main__':
    app.run(host='0.0.0.0')
