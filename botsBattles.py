# -*- coding: utf-8 -*-

# all the imports
from __future__ import with_statement
from flask import Flask, request, session, redirect, url_for, \
     render_template, flash, send_from_directory
from BeautifulSoup import BeautifulSoup
from dateutil.tz import *
from datetime import *
import json
import md5
import os
import requests
from requests.auth import HTTPDigestAuth
from urllib2 import URLError
from urlparse import urljoin
from werkzeug import secure_filename
from werkzeug.contrib.atom import AtomFeed
import xml.etree.ElementTree as ET

# configuration
DEBUG = True
SECRET_KEY = '\xc0\xd7O\xb3\'q\\\x19m\xb3uW\x16\xc2\r\x88\x91\xdbIv\x8d\x8f\xe9\x1f'
SECOND_SECRET_KEY = md5.new('Hazardius').hexdigest()
AUTH_DATA = HTTPDigestAuth('Flask', SECOND_SECRET_KEY)

import socket

lastRegistration = 0.0
games = []

TZOFFSETS = {"PL": 7200}
PLTZ = tzoffset("PL", 7200)

timeout = 10
socket.setdefaulttimeout(timeout)

# address of WebService server - McStAp
WEBSERVICE_IP = "http://77.65.54.170:9005"
# address of WebService server - McHo
#WEBSERVICE_IP = "http://89.228.196.221:9005"
# address of WebService server - Localhost
#WEBSERVICE_IP = "http://localhost:9005"
TESTING = False

# list of allowed extensions
ALLOWED_EXTENSIONS_FILE = set(['java', 'cpp', 'py', 'cs', 'p', 'ps'])
ALLOWED_EXTENSIONS_DOC = set(['html'])
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


def allowed_docFile(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS_DOC


@app.route('/delete_file/<filename>')
def delete_file(filename):
    if 'isSU' not in session:
        return ban_error()
    filename = secure_filename(filename)
    filePath = os.path.join(app.config['UPLOAD_FOLDER'],
        filename)
    filePath = os.path.normpath(filePath)
    if os.path.exists(filePath) is True:
        os.remove(filePath)
    flash('File %s was removed!' % filename)
    session['redirected'] = True
    return redirect(url_for('news'))


def make_external(url):
    return urljoin(request.url_root, url)


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


@app.route('/show_file/<filename>')
def show_file(filename):
    if 'isSU' not in session:
        return ban_error()
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


def deleteFromWebService(subpage):
    try:
        f = requests.delete(WEBSERVICE_IP + "/Flask" + subpage, auth=AUTH_DATA)
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


def getAtomFromWebService(newsID):
    try:
        f = requests.get(WEBSERVICE_IP + "/news/retrieve/" + str(newsID) +
            "?media=atom")
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
        f = requests.get(WEBSERVICE_IP + "/Flask" + subpage, auth=AUTH_DATA)
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


def getNSFromWebService(subpage):
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
        f = requests.post(WEBSERVICE_IP + "/Flask" + subpage, data=data,
            headers={'Content-Type': 'application/json',
            'Content-Length': clen}, auth=AUTH_DATA)
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
        f = requests.put(WEBSERVICE_IP + "/Flask" + subpage, data=data,
            headers={'Content-Type': 'application/json',
            'Content-Length': clen}, auth=AUTH_DATA)
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


def sendFileToWebService(filename, subpage):
    error = None
    data = open(filename, 'rb')
    try:
        response = requests.post(WEBSERVICE_IP + "/Flask" + subpage, data,
            headers={'Content-Type': 'application/octet-stream'},
            auth=AUTH_DATA)
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
            app.logger.error('Value Error has been found.\nError code:'
                + error)
        else:
            error = e
    except AttributeError, e:
        error = "No JSON as a response.\nResponse: " + str(response)
    except requests.exceptions.ConnectionError, e:
        error = "[SendFile]Connection Error! " + str(e)
        app.logger.error(error)
    else:
        return data
    errorMessage = {"Status": False, "Message": error}
    return errorMessage

# error pages


def ban_error():
    return render_template('error.html', errorNo=403,
        errorMe="Forbidden!")


@app.route('/error/502')
@app.errorhandler(502)
def ws_error():
    return render_template('error.html', errorNo=502,
        errorMe="Bad Gateway! WebService is not responding.")


@app.route('/error/503')
@app.errorhandler(503)
def ws_error2():
    return render_template('error.html', errorNo=503,
        errorMe="Bad Gateway! WebService is not responding.")


def spam_error():
    return render_template('error.html', errorNo=429,
        errorMe="Too Many Requests! One request per 0.75 second allowed.")


@app.errorhandler(400)
def page_error():
    return render_template('error.html', errorNo=400,
        errorMe="Page error!")


@app.errorhandler(404)
def not_found(error):
    if "username" in session:
        return render_template('error.html', username=session['username'],
            errorNo=404, errorMe="The page You're looking for isn't here!")
    else:
        return render_template('error.html', errorNo=404,
            errorMe="The page You're looking for isn't here!")


@app.route("/message/<mess>")
def message(mess):
    if 'redirected' not in session:
        return ban_error()
    session.pop('redirected', None)
    if 'username' in session:
        return render_template('message.html', message=mess, username=session[
            'username'], cMessages=check_messages())
    else:
        return render_template('message.html', message=mess)

# page methods


@app.route('/clean_messages')
def clean_messages():
    if check_spam() is False:
        return spam_error()
    return render_template('clean_messages.html')


def check_spam():
    import time
    if 'lastTime' in session:
        lastTime = session['lastTime']
    else:
        lastTime = 0.0
    session['lastTime'] = time.time()
    if lastTime:
        if (session['lastTime'] - lastTime < 0.75):
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
        r = requests.head(WEBSERVICE_IP, auth=AUTH_DATA)
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
    return news_p(0)


@app.route('/news/<int:page>')
def news_p(page):
    if 'redirected' not in session:
        if check_spam() is False:
            return spam_error()
    session.pop('redirected', None)
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    if "pagination" in session:
        pagination = session['pagination']
    else:
        pagination = 25
    response = getNSFromWebService("/news/" + str(page) + "/" + str(pagination)
        + "/retrieve")
    nextP = False
    if response.get('Status') is True:
        news = []
        for i in range(1, response.get('Count') + 1):
            newsId = response.get(str(i))
            response2 = getAtomFromWebService(newsId)
            if 'Status' in response2:
                error = response2.get('Message')
            else:
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
                                shorterTextList = (deepField.text.split('T')[0]
                                    .split('-'))
                                day = int(shorterTextList[2]) + 1
                                if day < 10:
                                    day = "0" + str(day)
                                else:
                                    day = str(day)
                                shorterText = (shorterTextList[0] + "-" +
                                    shorterTextList[1] + "-" + day)
                                oneNews.update({shorterTag: shorterText})
                            elif shorterTag == "summary":
                                oneNews.update({shorterTag: deepField.text})
                            elif shorterTag == "title":
                                info = deepField.text
                    else:
                        info = field.text
                    oneNews.update({shortTag: info})
                oneNews.update({'id': newsId})
                news.append(oneNews)
        news = sorted(news, key=lambda art: art['published'], reverse=True)
        if len(news) == pagination:
            nextP = True
        if "username" in session:
            return render_template('news.html', username=session['username'],
                cMessages=check_messages(), news=news, error=error, page=page,
                next=nextP)
        else:
            return render_template('news.html', news=news, error=error,
                page=page, next=nextP)
    error = response.get('Message')
    if "username" in session:
        return render_template('news.html', username=session['username'],
            cMessages=check_messages(), error=error, page=page, next=nextP)
    else:
        return render_template('news.html', error=error, page=page, next=nextP)


@app.route('/news.atom')
def recent_feed():
    error = None
    feed = AtomFeed('Recent News',
                    feed_url=request.url, url=request.url_root)
    if "pagination" in session:
        response = getNSFromWebService("/news/" + str(0) + "/" + str(session[
            'pagination']) + "/retrieve")
    else:
        response = getNSFromWebService("/news/" + str(0) + "/" + str(25) +
            "/retrieve")
    if response.get('Status') is True:
        news = []
        for i in range(1, response.get('Count') + 1):
            newsId = response.get(str(i))
            response2 = getAtomFromWebService(newsId)
            if 'Status' in response2:
                error = response2.get('Message')
            else:
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
                                shorterTextList = (deepField.text.split('T')[0]
                                    .split('-'))
                                day = int(shorterTextList[2]) + 1
                                if day < 10:
                                    day = "0" + str(day)
                                else:
                                    day = str(day)
                                shorterText = (shorterTextList[0] + "-" +
                                    shorterTextList[1] + "-" + day)
                                oneNews.update({shorterTag: shorterText})
                            elif shorterTag == "summary":
                                oneNews.update({shorterTag: deepField.text})
                            elif shorterTag == "title":
                                info = deepField.text
                    else:
                        info = field.text
                    oneNews.update({shortTag: info})
                oneNews.update({'id': newsId})
                news.append(oneNews)
        news = sorted(news, key=lambda art: art['published'], reverse=True)

        someId = 1
        for oneNews in news:
            import datetime
            dateTab = oneNews.get('published').split('-')
            date = datetime.datetime(int(dateTab[0]), int(dateTab[1]), int(
                dateTab[2]))
            feed.add(oneNews.get('title'),
                unicode(oneNews.get('summary') + oneNews.get('entry')),
                id=someId,
                content_type='html',
                url="http://walki-botow.herokuapp.com/news_detail/" + str(
                    oneNews.get('id')),
                author=oneNews.get('author'),
                published=date,
                updated=date)
            someId = someId + 1
        return feed.get_response()
    return page_error()


@app.route('/news_detail/<int:newsId>')
def view_news(newsId):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    oneNews = {}
    response2 = getAtomFromWebService(newsId)
    if 'Status' in response2:
        error = response2.get('Message')
    else:
        for field in response2:
            shortTag = field.tag.split('}')[1]
            if shortTag == "author":
                for deepField in field:
                    info = deepField.text
            elif shortTag == "entry":
                for deepField in field:
                    shorterTag = deepField.tag.split('}')[1]
                    if shorterTag == "published":
                        shorterTextList = (deepField.text.split('T')[0]
                            .split('-'))
                        day = int(shorterTextList[2]) + 1
                        if day < 10:
                            day = "0" + str(day)
                        else:
                            day = str(day)
                        shorterText = (shorterTextList[0] + "-" +
                            shorterTextList[1] + "-" + day)
                        oneNews.update({shorterTag: shorterText})
                    elif shorterTag == "summary":
                        oneNews.update({shorterTag: deepField.text})
                    elif shorterTag == "title":
                        info = deepField.text
            else:
                info = field.text
            oneNews.update({shortTag: info})
        oneNews.update({'id': newsId})
    return render_template('info.html', username=session['username'],
        cMessages=check_messages(), error=error, entry=oneNews)


@app.route('/add_news', methods=['GET', 'POST'])
def add_news():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    if check_perm('admin') is False:
        flash("You are not permitted to see that page!")
        session['redirected'] = True
        return redirect(url_for('news'))
    error = None
    if request.method == 'POST':
        import time
        import datetime
        dateTime = time.strftime("%Y-%m-%d", time.gmtime())
        pub = dateTime
        if 'pubDate' in request.form:
            if not len(request.form['pubDate']) == 0:
                now = datetime.datetime.now()
                pubDate = request.form['pubDate'].split(' ')
                pubSDate = pubDate[0].split('-')
                pubStart = datetime.datetime(int(pubSDate[0]), int(pubSDate[1]),
                    (int(pubSDate[2]) + 1))
                if (pubStart > now):
                    pub = request.form['pubDate']
        if 'enaCom' in request.form:
            test = True
        else:
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
            "Type": sanitize_html(request.form['newsType'].encode('ascii')),
            "Comments": test,
            "Author": session['username'].encode('ascii')
        }
        response = postToWebService(payload, "/news/create")
        if response.get('Status') is True:
            flash("New news successfully created!")
            session['redirected'] = True
            return redirect(url_for('news'))
        else:
            error = response
    return render_template('add_news.html', username=session['username'],
        cMessages=check_messages(), error=error)


@app.route('/edit_news/<int:newsId>', methods=['GET', 'POST'])
def edit_news(newsId):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    if check_perm('admin') is False:
        flash("You are not permitted to see that page!")
        session['redirected'] = True
        return redirect(url_for('news'))
    error = None
    if request.method == 'POST':
        import time
        import datetime
        dateTime = time.strftime("%Y-%m-%d", time.gmtime())
        pub = dateTime
        if 'pubDate' in request.form:
            now = datetime.datetime.now()
            pubDate = request.form['pubDate'].split(' ')
            pubSDate = pubDate[0].split('-')
            pubStart = datetime.datetime(int(pubSDate[0]), int(pubSDate[1]),
                (int(pubSDate[2]) + 1))
            if (pubStart > now):
                pub = request.form['pubDate']
        if 'enaCom' in request.form:
            test = True
        else:
            test = False
        payload = {
            "Publish": pub,
            "Title": sanitize_html(request.form['title']
                .encode('utf-8', 'ignore')),
            "Description": sanitize_html(request.form['shorDesc']
                .encode('utf-8', 'ignore')),
            "FullDescription": sanitize_html(request.form['longDesc']
                .encode('utf-8', 'ignore')),
            "Type": sanitize_html(request.form['newsType'].encode('ascii')),
            "Comments": test,
            "ID": newsId
        }
        response = putToWebService(payload, "/news/update")
        if response.get('Status') is True:
            flash("New news successfully created!")
            session['redirected'] = True
            return redirect(url_for('news'))
        else:
            error = response

    oneNews = {}
    response2 = getAtomFromWebService(newsId)
    if 'Status' in response2:
        error = response2.get('Message')
    else:
        for field in response2:
            shortTag = field.tag.split('}')[1]
            if shortTag == "author":
                for deepField in field:
                    info = deepField.text
            elif shortTag == "entry":
                for deepField in field:
                    shorterTag = deepField.tag.split('}')[1]
                    if shorterTag == "published":
                        shorterTextList = (deepField.text.split('T')[0]
                            .split('-'))
                        day = int(shorterTextList[2]) + 1
                        if day < 10:
                            day = "0" + str(day)
                        else:
                            day = str(day)
                        shorterText = (shorterTextList[0] + "-" +
                            shorterTextList[1] + "-" + day)
                        oneNews.update({shorterTag: shorterText})
                    elif shorterTag == "summary":
                        oneNews.update({shorterTag: deepField.text})
                    elif shorterTag == "title":
                        info = deepField.text
            else:
                info = field.text
            oneNews.update({shortTag: info})
        oneNews.update({'id': newsId})
    return render_template('edit_news.html', username=session['username'],
        cMessages=check_messages(), error=error, entry=oneNews)

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
                flash("Check your e-mail account!")
                session['redirected'] = True
                return redirect(url_for('news'))
            else:
                error = response.get('Message')
        else:
            error = "One registration per 10 seconds allowed."
    return render_template('register.html', error=error)


@app.route('/remind', methods=['GET', 'POST'])
def remind_act_code():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ws_error()
    error = None
    if request.method == 'POST':
        payload = {
            "Email": sanitize_html(request.form['e_mail'])
        }
        response = postToWebService(payload, "/reactivate")
        if response.get('Status') is True:
            flash("Activation link successfully re-sent!")
            session['redirected'] = True
            return redirect(url_for('news'))
        else:
            error = response.get('Message')
        flash(error)
        session['redirected'] = True
        return redirect(url_for('news'))
    return render_template('remind.html', error=error)


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
        flash("Account successfully activated!")
        session['redirected'] = True
        return redirect(url_for('news'))
    else:
        error = response.get('Message')
    flash(error)
    session['redirected'] = True
    return redirect(url_for('news'))


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
                filename = "usersPag.jsoninf"
                pagFilePath = os.path.join(app.config['UPLOAD_FOLDER'],
                    filename)
                pagFilePath = os.path.normpath(pagFilePath)
                pags = {}
                if os.path.exists(pagFilePath) is True:
                    pagFile = open(pagFilePath, 'r+')
                    pags = json.loads(pagFile.read())
                    pagFile.close()
                if request.form['username'] in pags:
                    session['pagination'] = int(pags.get(request.form[
                        'username']))
                else:
                    session['pagination'] = 10
                response2 = getFromWebService("/" + sanitize_html(request.form[
                    'username']) + "/retrieve")
                if response2.get('Status') is True:
                    perCount = response2.get('Count')
                    for i in range(1, perCount + 1):
                        if response2.get(str(i)) == "Super admin":
                            session['isSU'] = True
                perCount = response.get('Count')
                permissions = []
                for i in range(1, perCount + 1):
                    permissions.append(response.get(str(i)))
                session['permissions'] = permissions
                session['logged_in'] = True
                session['username'] = request.form['username']
                flash('You were logged in %s' % session['username'])
                session['redirected'] = True
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
    session.pop('isSU', None)
    flash('You were logged out')
    return redirect(url_for('news'))

# page methods - messages system


def check_messages():
    if 'username' in session:
        if check_perm('messages/' + session['username']) is False:
            return render_template('message.html', cMessages=check_messages(),
                message="You are not permitted to see that page!")
        response = getFromWebService("/notice/" + session['username'] + "/new")
        if response.get('Status') is True:
            return response.get('Count')
        return -1
    else:
        return -1


@app.route('/post_box')
def post_box():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    response = getFromWebService("/notice/" + session['username'] + "/0/50")
    if response.get('Status') is True:
        messages = []
        for i in range(1, response.get('Count') + 1):
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
    if 'redirected' not in session:
        if check_spam() is False:
            return spam_error()
    session.pop('redirected', None)
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
        response2 = getFromWebService("/" + sanitize_html(nick) + "/retrieve")
        allG = []
        if response2.get('Status') is True:
            perCount = response2.get('Count')
            for i in range(1, perCount + 1):
                allG.append(response2.get(str(i)))
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
                if 'isSU' not in session:
                    response.update({'Email': ""})
        canEdit = check_perm('edit_profile/' + nick)
        return render_template('profile.html', cMessages=check_messages(),
            username=session['username'], profile=dict(response),
            canEdit=canEdit, groups=allG)
    else:
        error = response.get('Message')
    return render_template('message.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/edit_privacy/<edited>', methods=['GET', 'POST'])
def edit_privacy(edited):
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
        ADI = False
        if 'allowDI' in request.form:
            if request.form['allowDI'] == 'true':
                ADI = True
        APM = False
        if 'allowPM' in request.form:
            if request.form['allowPM'] == 'true':
                APM = True
        ATI = False
        if 'allowTI' in request.form:
            if request.form['allowTI'] == 'true':
                ATI = True
        AEV = False
        if 'allowEV' in request.form:
            if request.form['allowEV'] == 'true':
                AEV = True
        payload = {
            "AllowDuelInv": ADI,
            "AllowPrivMessage": APM,
            "AllowTourInv": ATI,
            "PublicEmail": AEV,
            "Editor": session['username']
        }
        response = postToWebService(payload, "/" + sanitize_html(edited) +
            "/privacy")
        if response.get('Status') is True:
            session['redirected'] = True
            return redirect(url_for('show_user_profile', nick=sanitize_html(
                edited)))
        else:
            error = response.get('Message')
    response = getFromWebService("/" + sanitize_html(edited) + "/privacy")
    if response.get('Status') is True:
        response.update({"nick": edited})
        return render_template('edit_privacy.html', username=session[
            'username'], error=error, cMessages=check_messages(),
            profile=dict(response))
    else:
        flash(error)
        session['redirected'] = True
        return redirect(url_for('news'))


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
        if (edited == session['username']):
            try:
                pagination = int(request.form['pagination'])
            except:
                pagination = session['pagination']
            if (pagination < 4):
                session['pagination'] = 4
            elif (pagination > 25):
                session['pagination'] = 25
            else:
                session['pagination'] = int(request.form['pagination'])
        filename = "usersPag.jsoninf"
        pagFilePath = os.path.join(app.config['UPLOAD_FOLDER'],
            filename)
        pagFilePath = os.path.normpath(pagFilePath)
        pags = {}
        if os.path.exists(pagFilePath) is True:
            pagFile = open(pagFilePath, 'r+')
            pags = json.loads(pagFile.read())
            pagFile.close()
        pags.update({session['username']: str(session['pagination'])})
        pagFile = open(pagFilePath, 'w+')
        pagFile.write(json.dumps(pags))
        pagFile.close()
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
                payload3 = {
                    "Editor": session['username']
                }
                groups = request.form.getlist("group")
                num = 1
                for group in groups:
                        payload3.update({str(num): sanitize_html(group)})
                        num = num + 1
                payload3.update({"Count": (num - 1)})
                response3 = postToWebService(payload3, "/" + payload['Login'] +
                    "/retrieve")
                if response3.get('Status') is True:
                    session['redirected'] = True
                    return redirect(url_for('show_user_profile', nick=payload[
                        'Login']))
                else:
                    error = (response3.get('Message') + " Profile partially " +
                        "edited! Only groups remain unchanged!")
            else:
                error = response2.get('Message') + " Profile partially edited!"
        else:
            error = response.get('Message')
    response = getFromWebService("/" + sanitize_html(edited) + "/about")
    if response.get('Status') is True:
        response.update({"nick": edited})
        response.update({"pag": session['pagination']})
        tmzns = []
        #print datetime.now(tzlocal())
        #tmzns = tzwin.list()
        response2 = getFromWebService('/' + sanitize_html(edited) + "/other")
        if response2.get('Status') is True:
            response.update(response2)
            if 'Change users profile' in session['permissions']:
                response3 = getFromWebService('/user/groups')
                if response3.get('Status') is True:
                    groCount = response3.get('Count')
                    allG = []
                    for i in range(1, groCount + 1):
                        group = response3.get(str(i)).get('Name')
                        if group == "Super admin":
                            if 'isSU' in session:
                                allG.append(group)
                        else:
                            allG.append(group)
                    response4 = getFromWebService('/' + sanitize_html(edited) +
                        '/retrieve')
                    if response4.get('Status') is True:
                        ugrCount = response4.get('Count')
                        usrG = []
                        for i in range(1, ugrCount + 1):
                            group = response4.get(str(i))
                            usrG.append(group)
                        return render_template('edit_profile.html', tmzns=tmzns,
                            username=session['username'], error=error,
                            edited=edited, cMessages=check_messages(),
                            profile=dict(response), allG=allG, usrG=usrG)
                    return render_template('edit_profile.html',
                        username=session['username'], error=error,
                        edited=edited, cMessages=check_messages(), tmzns=tmzns,
                        profile=dict(response))
            return render_template('edit_profile.html', tmzns=tmzns,
                username=session['username'], error=error, edited=edited,
                cMessages=check_messages(), profile=dict(response))
        return render_template('edit_profile.html',
            username=session['username'], error=error, tmzns=tmzns,
            cMessages=check_messages(), edited=edited, profile=dict(response))
    else:
        flash(error)
        session['redirected'] = True
        return redirect(url_for('news'))

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
        logins = sorted(logins, key=lambda x: x.lower())
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
    global games
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
            battles=battles, cMessages=check_messages(), page=page, next=nextP,
            games=games)
    else:
        error = response.get('Message')
    return render_template('battles.html', username=session['username'],
        error=error, cMessages=check_messages(), page=page, next=False,
        games=games)


@app.route('/choose_oponent')
def choose_oponent():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    userRes = getFromWebService("/games/duels/" + session['username']
        + "/0/100/list")
    global games
    if userRes.get('Status') is True:
        logins = []
        for i in range(1, userRes.get('Count') + 1):
            nextOne = userRes.get(str(i))
            if nextOne is not None:
                logins.append(nextOne)
        logins = sorted(logins, key=lambda x: x.lower())
        return render_template('choose_oponent.html',
            cMessages=check_messages(), username=session['username'],
            users=logins, games=games)
    error = userRes.get('Message')
    return render_template('choose_oponent.html', username=session['username'],
        error=error, cMessages=check_messages(), games=games)


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
        session['redirected'] = True
        return redirect(url_for('news'))
    else:
        error = response.get('Message')
    userRes = getFromWebService("/games/duels/" + session['username']
        + "/0/list")
    global games
    if userRes.get('Status') is True:
        logins = []
        for i in range(1, session['pagination']):
            nextOne = userRes.get(str(i))
            if nextOne is not None:
                logins.append(nextOne)
        return render_template('choose_oponent.html',
            cMessages=check_messages(), username=session['username'],
            users=logins, error=error, games=games)
    else:
        error = error + "\n" + userRes.get('Message')
    return render_template('choose_oponent.html', username=session['username'],
        error=error, cMessages=check_messages(), games=games)


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
        session['redirected'] = True
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
        session['redirected'] = True
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
    isPlayer = False
    if (session['username'] == response.get('Player1') or session['username']
        == response.get('Player2')):
        isPlayer = True
    response = getFromWebService("/games/" + str(number) + "/info")
    if response.get('Status') is True:
        if "Message" in response:
            if response.get('Message') == "Waiting for compilation":
                return render_template('view_battle.html',
                    username=session['username'], cMessages=check_messages(),
                    number=number, game=gameName, winner=response.get('Winner'),
                    error=error, message=response.get('Message'))
            if response.get('Message') == "Waiting for files":
                return render_template('send_code.html', username=session[
                    'username'], cMessages=check_messages(), number=number,
                    game=gameName, error=error, winner=response.get('Winner'),
                    message=response.get('Message'), isP=isPlayer)
        if response.get('Finished') is True:
            try:
                conError = ""
                r = requests.get(WEBSERVICE_IP + "/Flask/code/" +
                    sanitize_html(gameName) + "/" + str(number) + "/duel/log",
                    stream=True, auth=AUTH_DATA)
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
    if error is not None:
        flash("Error! " + error)
    session['redirected'] = True
    return redirect(url_for('news'))


@app.route('/sendCode/<int:idG>/<game>', methods=['GET', 'POST'])
def send_code(idG, game):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    error = None
    if request.method == 'POST':
        if request.form['codeForm'] == 'text':
            exten = request.form['lang']
            fileName = sanitize_html(request.form['fileName'].replace(' ', ''))
            if allowed_codeFile(fileName):
                payload = {
                    "From": sanitize_html(session['username']),
                    "Language": sanitize_html(exten),
                    "GameID": idG,
                    "Game": sanitize_html(game),
                    "Code": request.form['code'],
                    "FileName": sanitize_html(request.form['fileName']
                        .replace(" ", ""))
                }
                response = postToWebService(payload, "/code/duel/upload")
                if response.get('Status') is True:
                    flash("Code sent!")
                    session['redirected'] = True
                    return redirect(url_for('news'))
                else:
                    error = response
            else:
                error = "File name wrong!"
        elif request.form['codeForm'] == 'file':
            codeFile = request.files['file']
            if codeFile and allowed_codeFile(codeFile.filename):
                filename = secure_filename(codeFile.filename)
                locFilePath = os.path.join(app.config['UPLOAD_FOLDER'],
                    filename)
                locFilePath = os.path.normpath(locFilePath)
                codeFile.save(locFilePath)
                response = sendFileToWebService(locFilePath, "/code/duel/upl" +
                    "oad/" + game + "/" + str(idG) + "/" + session['username']
                    + "/" + filename)
                if response.get('Status') is True:
                    os.remove(locFilePath)
                    flash("File uploaded!")
                    session['redirected'] = True
                    return redirect(url_for('news'))
                else:
                    error = response.get('Message')
                os.remove(locFilePath)
            else:
                error = 'File format not valid!'
    return render_template('message.html', username=session['username'],
        error=error, cMessages=check_messages(), message="")

# page methods - tournaments


@app.route('/tournaments')
def tournaments():
    return tournaments_p(0)


@app.route('/tournaments/<int:page>')
def tournaments_p(page):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    response = getFromWebService("/games/" + str(page) + "/" + str(session[
        'pagination']) + "/tournaments")
    if response.get('Status') is True:
        if response.get('Count') != 0:
            tours = []
            for i in range(1, response.get('Count') + 1):
                nextOne = response.get(str(i))
                if nextOne is not None:
                    tours.append(dict(nextOne))
            tours = sorted(tours, key=lambda bat: bat['Name'].lower())
            nextP = False
            if len(tours) == session['pagination']:
                nextP = True
            return render_template('tournaments.html',
                username=session['username'], tours=tours,
                cMessages=check_messages(), page=page, next=nextP)
    else:
        error = response.get('Message')
    return render_template('tournaments.html', username=session['username'],
        error=error, cMessages=check_messages())


@app.route('/tournament/<int:tourId>')
def tournament(tourId):
    if 'redirected' not in session:
        if check_spam() is False:
            return spam_error()
    session.pop('redirected', None)
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    response = getFromWebService("/games/tournaments/" + str(tourId) + "/info")
    if response.get('Status') is True:
        tour = response
        import datetime
        now = datetime.datetime.now()
        rDate = tour.get('Begin').split(' ')
        regDate = rDate[0].split('-')
        regTime = rDate[1].split(':')
        regStart = datetime.datetime(int(regDate[0]), int(regDate[1]), int(
            regDate[2]), int(regTime[0]), int(regTime[1]))
        if (regStart < now):
            regState = True
        else:
            regState = False
        from_zone = tzutc()
        to_zone = PLTZ
        regStart = regStart.replace(tzinfo=from_zone)
        regStart = regStart.astimezone(to_zone)
        tour.update({'Begin': str(regStart).split('+')[0]})

        rDate = tour.get('End').split(' ')
        regDate = rDate[0].split('-')
        regTime = rDate[1].split(':')
        regStart = datetime.datetime(int(regDate[0]), int(regDate[1]), int(
            regDate[2]), int(regTime[0]), int(regTime[1]))
        if (regStart < now):
            regState = False
            playState = True
        else:
            playState = False
        from_zone = tzutc()
        to_zone = PLTZ
        regStart = regStart.replace(tzinfo=from_zone)
        regStart = regStart.astimezone(to_zone)
        tour.update({'End': str(regStart).split('+')[0]})

        rDate = tour.get('Start').split(' ')
        regDate = rDate[0].split('-')
        regTime = rDate[1].split(':')
        regStart = datetime.datetime(int(regDate[0]), int(regDate[1]), int(
            regDate[2]), int(regTime[0]), int(regTime[1]))
        if (regStart < now):
            playState = False
        from_zone = tzutc()
        to_zone = PLTZ
        regStart = regStart.replace(tzinfo=from_zone)
        regStart = regStart.astimezone(to_zone)
        tour.update({'Start': str(regStart).split('+')[0]})

        cATA = False
        if 'isSU' in session:
            cATA = True
        else:
            admList = getFromWebService("/games/tournaments/" + str(tourId) +
                "/admins")
            for i in range(1, admList.get('Count') + 1):
                if admList.get(str(i)) == session['username']:
                    cATA = True
        playersScoresRes = getFromWebService("/games/tournaments/" + str(tourId)
            + "/scores")
        if playersScoresRes.get('Status') is True:
            players = []
            isPlay = False
            for i in range(1, playersScoresRes.get('Count') + 1):
                nextOne = playersScoresRes.get(str(i))
                if nextOne is not None:
                    players.append(nextOne)
                    if nextOne.get('Login') == session['username']:
                        isPlay = True
            if isPlay is False:
                playState = False
            return render_template('tournament.html', tourId=tourId, cATA=cATA,
                tour=tour, cMessages=check_messages(), username=session[
                'username'], error=error, regState=regState, plList=players,
                playState=playState, isPlay=isPlay)
        return render_template('tournament.html', tourId=tourId, cATA=cATA,
            tour=tour, cMessages=check_messages(), username=session[
            'username'], error=error, regState=regState, playState=playState)
    error = response.get('Message')
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
        import datetime
        from_zone = PLTZ
        to_zone = tzutc()
        now = datetime.datetime.now()
        now = now.replace(tzinfo=from_zone)
        now = now.astimezone(to_zone)
        bDateTimeO = ""
        if 'bDate' in request.form:
            bDateTime = request.form['bDate'].split('T')
            bDate = bDateTime[0].split('-')
            bTime = bDateTime[1].split(':')
            bDateTimeO = datetime.datetime(int(bDate[0]), int(bDate[1]), int(
                bDate[2]), int(bTime[0]), int(bTime[1]))
        else:
            error = "Error 2. No date(bDate) sent!"
        eDateTimeO = ""
        if 'eDate' in request.form:
            eDateTime = request.form['eDate'].split('T')
            eDate = eDateTime[0].split('-')
            eTime = eDateTime[1].split(':')
            eDateTimeO = datetime.datetime(int(eDate[0]), int(eDate[1]), int(
                eDate[2]), int(eTime[0]), int(eTime[1]))
        else:
            error = "Error 2. No date(eDate) sent!"
        sDateTimeO = ""
        if 'sDate' in request.form:
            sDateTime = request.form['sDate'].split('T')
            sDate = sDateTime[0].split('-')
            sTime = sDateTime[1].split(':')
            sDateTimeO = datetime.datetime(int(sDate[0]), int(sDate[1]), int(
                sDate[2]), int(sTime[0]), int(sTime[1]))
        else:
            error = "Error 2. No date(sDate) sent!"
        if error is None:
            bDateTimeO = bDateTimeO.replace(tzinfo=from_zone)
            bDateTimeO = bDateTimeO.astimezone(to_zone)
            eDateTimeO = eDateTimeO.replace(tzinfo=from_zone)
            eDateTimeO = eDateTimeO.astimezone(to_zone)
            sDateTimeO = sDateTimeO.replace(tzinfo=from_zone)
            sDateTimeO = sDateTimeO.astimezone(to_zone)
            if (bDateTimeO <= now):
                error = ("Registration date wrong! Beginning of registration " +
                    "before now!")
            if (eDateTimeO <= bDateTimeO):
                error = ("Registration date wrong! End of registration before" +
                    " beginning!")
            if (sDateTimeO <= eDateTimeO):
                error = ("Registration date wrong! Start of tournament before" +
                    " end of registration!")
            if error is None:
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
                        "RegBegin": str(bDateTimeO).split('+')[0],
                        "RegEnd": str(eDateTimeO).split('+')[0],
                        "RegType": sanitize_html(request.form['regType']),
                        "MaxPlayers": request.form['maxPl'],
                        "Start": str(sDateTimeO).split('+')[0],
                        "TourID": tourID,
                        "Type": sanitize_html(request.form['tourType'])
                    }
                    response2 = postToWebService(payload, "/games/tournaments/"
                        + str(tourID) + "/info")
                    if response2.get('Status') is True:
                        flash("New tournament successfully created!")
                        session['redirected'] = True
                        return redirect(url_for('news'))
                    else:
                        flash("Error: " + response2.get('Message'))
                        session['redirected'] = True
                        return redirect(url_for('news'))
                else:
                    error = response.get('Message')
    global games
    return render_template('new_tournament.html', username=session['username'],
        cMessages=check_messages(), error=error, games=games)


@app.route('/delete_tour/<int:tourId>', methods=['GET', 'POST'])
def delete_t(tourId):
    if check_spam() is False:
        return spam_error()
    if 'isSU' not in session:
        return ban_error()
    if check_ws() is False:
        return ws_error()
    error = None
    if request.method == 'POST':
        if 'iamsure' in request.form:
            if request.form['iamsure'] == 'true':
                response = deleteFromWebService('/games/tournaments/' +
                    str(tourId) + '/delete')
                if response.get('Status') is True:
                    flash("Tournament deleted!")
                    session['redirected'] = True
                    return redirect(url_for('news'))
                else:
                    flash("Something went wrong!")
                    session['redirected'] = True
                    return redirect(url_for('news'))
        error = "If You're not sure about that, maybe leave this page?"
    return render_template('are_you_sure.html', username=session['username'],
        cMessages=check_messages(), tourId=tourId, error=error)


@app.route('/ata/<int:tourId>', methods=['GET'])
def add_tour_admin(tourId):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    userRes = getFromWebService("/games/duels/" + session['username']
        + "/0/100/list")
    if userRes.get('Status') is True:
        logins = []
        for i in range(1, userRes.get('Count') + 1):
            nextOne = userRes.get(str(i))
            if nextOne is not None:
                logins.append(nextOne)
        logins = sorted(logins, key=lambda x: x.lower())
        return render_template('choose_user.html', nextF="tAdmin",
            cMessages=check_messages(), username=session['username'],
            users=logins, cuMes="Add New Admin", id=tourId)
    return render_template('message.html', username=session['username'],
        message=error)


@app.route('/ata', methods=['POST'])
def tAdmin():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = ""
    tourId = request.form['id']
    player = sanitize_html(request.form['chosenOne'])
    payload = {
        "Count": 1,
        "1": player
    }
    response = postToWebService(payload, "/games/tournaments/" + tourId +
        "/admins")
    if response.get('Status') is True:
        flash("User is now an admin in this tournament.")
        session['redirected'] = True
        return redirect(url_for('news'))
    return render_template('message.html', username=session['username'],
        message=error + " " + str(tourId) + ".")


@app.route('/sft/<int:tourId>', methods=['GET'])
def sign_f_tournament(tourId):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    response = getFromWebService("/games/tournaments/" + str(tourId) + "/info")
    if response.get('Status') is True:
        if response.get('RegType') == 'Free':
            payload = {
                "User": sanitize_html(session['username'])
            }
            response2 = postToWebService(payload, "/games/tournaments/" +
                str(tourId) + "/registry")
            if response2.get('Status') is True:
                flash("You signed in!")
                session['redirected'] = True
                return redirect(url_for('news'))
            error = response2.get('Message')
        else:
            error = "Wrong type of Tournament Registration Type in a response!"
    else:
        error = response.get('Message')
    return render_template('message.html', username=session['username'],
        message=error)


@app.route('/sit/<int:tourId>', methods=['GET'])
def sign_i_tournament(tourId):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    response = getFromWebService("/games/tournaments/" + str(tourId) + "/info")
    if response.get('Status') is True:
        if response.get('RegType') == 'Invitation':
            userRes = getFromWebService("/games/duels/" + session['username']
                + "/0/100/list")
            if userRes.get('Status') is True:
                logins = []
                for i in range(1, userRes.get('Count') + 1):
                    nextOne = userRes.get(str(i))
                    if nextOne is not None:
                        logins.append(nextOne)
                return render_template('choose_user.html', users=logins,
                    nextF="sign_ip_tournament", cMessages=check_messages(),
                    username=session['username'], cuMes="Invite User",
                    id=tourId)
            error = "Error downloading users. " + userRes.get('Message')
        else:
            error = "Wrong type of Tournament Registration Type in a response!"
    else:
        error = response.get('Message')
    return render_template('message.html', cMessages=check_messages(),
        message=error)


@app.route('/sit', methods=['POST'])
def sign_ip_tournament():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    tourId = request.form['id']
    player = sanitize_html(request.form['chosenOne'])
    response = getFromWebService("/games/tournaments/" + str(tourId) + "/info")
    if response.get('Status') is True:
        if response.get('RegType') == 'Invitation':
            error = None
            payload = {
                "UserFrom": sanitize_html(session['username']),
                "UserTo": player,
                "TourName": sanitize_html(response.get('TourName')),
                "Type": "Tournament"
            }
            response2 = postToWebService(payload, "/notice/invitation")
            if response2.get('Status') is True:
                flash("You signed " + player + " in!")
                session['redirected'] = True
                return redirect(url_for('tournament', tourId=tourId))
            error = response2.get('Message')
        else:
            error = "Wrong type of Tournament Registration Type in a response!"
    else:
        error = response.get('Message')
    return render_template('message.html', username=session['username'],
        message=error)


@app.route('/tour<int:tourID>/sendCode', methods=['GET', 'POST'])
def send_code_t(tourID):
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    error = None

    isPlayer = False
    response = getFromWebService("/games/tournaments/" + str(tourID)
        + "/scores")
    if response.get('Status') is True:
        for i in range(1, response.get('Count') + 1):
            nextOne = response.get(str(i))
            if nextOne is not None:
                if nextOne.get('Login') == session['username']:
                    isPlayer = True
        if isPlayer is False:
            return render_template('message.html', cMessages=check_messages(),
                message="You are not permitted to see that page!")
    if request.method == 'POST':
        if request.form['codeForm'] == 'text':
            exten = request.form['lang']
            payload = {
                "From": sanitize_html(session['username']),
                "Language": sanitize_html(exten),
                "TourID": tourID,
                "Code": request.form['code'],
                "FileName": sanitize_html(request.form['fileName'].replace(" ",
                    ""))
            }
            response = postToWebService(payload, "/code/tournament/upload")
            if response.get('Status') is True:
                flash("Code sent for tournament " + str(tourID) + "!")
                session['redirected'] = True
                return redirect(url_for('news'))
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
                response = sendFileToWebService(locFilePath, "/code/tourname" +
                    "nt/upload/" + str(tourID) + "/" + session['username'] + "/"
                    + filename)
                if response.get('Status') is True:
                    os.remove(locFilePath)
                    flash("File uploaded for tournament " + str(tourID) + "!")
                    session['redirected'] = True
                    return redirect(url_for('news'))
                else:
                    error = response.get('Message')
                os.remove(locFilePath)
            else:
                error = 'File format not valid!'
    return render_template('send_codeT.html', username=session[
        'username'], cMessages=check_messages(), error=error,
        message=response.get('Message'), isP=isPlayer, tourID=tourID)

# add games


@app.route('/aGame', methods=['GET', 'POST'])
def add_game():
    if check_spam() is False:
        return spam_error()
    if check_ws() is False:
        return ws_error()
    if is_ban() is True:
        return ban_error()
    error = None
    #if request.method == 'POST':
        #newGame = {}
        #newGame.update({"codeOfGame": sanitize_html(request.form[
            #'codeOfGame'])})
        #newGame.update({"gameName": sanitize_html(request.form['gameName'])})
        #docFile = request.files['instruction']
        #if docFile and allowed_docFile(docFile.filename):
            #filename = newGame.get('codeOfGame') + ".html"
            #filename = secure_filename(filename)
            #locFilePath = os.path.join(app.config['UPLOAD_FOLDER'],
                #filename)
            #locFilePath = os.path.normpath(locFilePath)
            #docFile.save(locFilePath)
            #flash("Game added!")
            #session['redirected'] = True
            #return redirect(url_for('news'))
        #flash("Problem adding game!")
        #session['redirected'] = True
        #return redirect(url_for('news'))
    return render_template('add_game.html', cMessages=check_messages(),
        username=session['username'], error=error)

# main help - groups and permissions


@app.route('/helpGP')
def helpGP():
    error = None
    response = getFromWebService('/user/groups')
    groups = []
    if response.get('Status') is True:
        for i in range(1, response.get('Count') + 1):
            groups.append(response.get(str(i)))
    response = getFromWebService('/user/permissions')
    perms = []
    if response.get('Status') is True:
        for i in range(1, response.get('Count') + 1):
            perms.append(response.get(str(i)))
    return render_template('help.html', cMessages=check_messages(),
        username=session['username'], error=error, groups=groups, perms=perms)

# debug


#@app.route('/secret', methods=['GET', 'POST'])
#def secret():
    #request = getFromWebService("/games/list")
    #print request
    #return render_template('message.html', username=session['username'],
        #message=request, cMessages=check_messages())

# app start

if __name__ == '__main__':
    app.run(host='0.0.0.0')
