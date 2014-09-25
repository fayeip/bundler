#!/usr/bin/env python

#beginning of project part 1
import shelve
from subprocess import check_output
import flask
from flask import request
from flask import session
from flaskext.bcrypt import Bcrypt
import os
from os import environ
import string
import random
import sqlite3 as lite
from urlparse import urljoin

app = flask.Flask(__name__)
bcrypt = Bcrypt(app)
app.debug = True

dbfile = "project.db"
# Kathryn's problem
urlpath = None

dbpass = shelve.open("pass.db")
#dbpass has {key, value} = {email, password}

def id_gen(size=8, chars=string.ascii_uppercase+string.digits): #this function gives
                                      #an auto generated shortpath of 8 randomly selected characters/digits.
    return ''.join(random.choice(chars) for x in range(size))


##project part1(1)
#@app.route('/home', methods=['GET'])
#def home():
#    """Display home.html responding to a GET request."""
#    return flask.render_template(
#            'home.html')

## part1(2-3)  #We comment out this part for the following function of extra credit.
#@app.route('/shorts', methods=['POST'])
#def shorts_post():
#    """Set the long URL to which this shortpath redirects to. Display a confirmation message"""
#    long_url = request.form.get('longurl')
#    shortpath = request.form.get('shortpath')
#    db[str(shortpath)]=long_url
#    return "We saved-> " + str(long_url) + " as " + str(shortpath)


def write_to_database(user_id, long_url, short_path, bundle):
    con = lite.connect(dbfile)
    
    with con:
        cur = con.cursor()
        
        #insert into 'urls' table
        cur.execute("INSERT INTO urls (longURL, shortpath) VALUES(?,?)", (long_url, short_path))
        cur.execute("SELECT itemID FROM urls WHERE longURL=? AND shortpath=?", (long_url, short_path))
        item_id = cur.fetchone()
        app.logger.debug(str(item_id[0]))

        ##insert into 'bundles' table
        #cur.execute("SELECT bundleName FROM bundles WHERE userID=?", (user_id,))
        #all_existing_bundles = cur.fetchall()
        #existing_bundles_formatted = []   #to get items out of tuples
        #for bundle in all_existing_bundles:
        #    existing_bundles_formatted.append(str(bundle[0]))
        #new_bundles_names = []
        #old_bundles_names = []
        #for bundle in bundles_names_list:
        #    if bundle not in existing_bundles_formatted:
        #        new_bundles_names.append(bundle)
        #    else:
        #        old_bundles_names.append(bundle)
        #new_bundles_ids = []
        #for bundle in new_bundles_names:
        #    cur.execute("INSERT INTO bundles (userID, bundleName) VALUES(?,?)", (user_id, bundle))
        #    cur.execute("SELECT bundleID FROM bundles WHERE userID=? AND bundleName=?", (user_id, bundle))
        #    new_id = cur.fetchone()
        #    new_bundles_ids.append(new_id)
        #old_bundles_ids = []
        #for bundle in old_bundles_names:
        #    cur.execute("SELECT bundleID FROM bundles WHERE userID=? AND bundleName=?", (user_id, bundle))
        #    new_id = cur.fetchone()
        #    old_bundles_ids.append(new_id)

        #find bundleID for bundle
        cur.execute("SELECT bundleID FROM bundles WHERE bundleName=?",(bundle,))
        bundleID = cur.fetchone()        
        app.logger.debug(bundle)
        app.logger.debug(bundleID)

        #insert into 'items' table
        cur.execute("INSERT INTO items VALUES(?,?,?,?)",(user_id, int(item_id[0]), bundleID[0], 0))
        con.commit() 
        #for i in range(len(new_bundles_ids)):
        #    app.logger.debug('hello')
        #    cur.execute("INSERT INTO items VALUES(?,?,?,?)", (user_id, item_id[0], new_bundles_ids[i][0], 0))
        #for j in range(len(old_bundles_ids)):
        #    app.logger.debug('hello2')
        #    cur.execute("INSERT INTO items VALUES(?,?,?,?)", (user_id, item_id[0], old_bundles_ids[j][0], 0))
 


@app.route('/shorts', methods=['GET','POST'])
def shorts_post():
    """Set the long URL to which this shortpath redirects to. In case that users don't specify the short path,
    we assign auto generated short path"""
    message =None
    if 'username' in session: 
        if request.method == 'POST':
            long_url = request.form.get('longurl')
            shortpath = request.form.get('shortpath')
            bundle = request.form.get('bundle')
            path = request.form.get('path')
            app.logger.debug(path)
            app.logger.debug('bundle passed in is ' + str(bundle))
            frompage = request.form.get('frompage') ### need to get absolute path, redirect to the absolute path after this function
            username = session['username'] 

            if long_url[0:4] != 'http':
                long_url = 'http://' + long_url 

            if str(bundle) == "" or bundle == None:
                bundle = ""  


            con = lite.connect(dbfile)
            with con:
                cur = con.cursor()
                cur.execute("SELECT id FROM user_pass WHERE email=?", (username,))
                userid_tuple = cur.fetchone()
                userid = userid_tuple[0] 
                app.logger.debug(userid)
                cur.execute("SELECT bundleID, shortpath FROM urls JOIN items ON urls.itemID=items.itemID WHERE longURL=? AND userID=? GROUP BY shortpath", (long_url, userid))
                shortpath_found_for_longurl = cur.fetchall()
                cur.execute("SELECT shortpath FROM urls")
                all_shortpaths_found = cur.fetchall()
                cur.execute("SELECT bundleID FROM bundles WHERE bundleName=?",(bundle,))
                associated_bundleID = cur.fetchall()
                app.logger.debug(shortpath_found_for_longurl)
                app.logger.debug(all_shortpaths_found)

            # Case 1: long_url already in database
            if len(shortpath_found_for_longurl) > 0:
                # Overwrite bundle or shortpath in db if stored value is different
                app.logger.debug('associated_bundleID is')
                app.logger.debug(associated_bundleID) 
                if shortpath_found_for_longurl[0][0] != associated_bundleID[0] or shortpath_found_for_longurl[0][1] != shortpath:
                    con = lite.connect(dbfile)
                    with con:
                        cur = con.cursor()
                        cur.execute("SELECT itemID FROM urls WHERE shortpath=?",(shortpath_found_for_longurl[0][1],))
                        associated_itemID = cur.fetchone()
                        cur.execute("UPDATE items SET bundleID=? WHERE itemID=?", (associated_bundleID[0], associated_itemID[0])) 
                        con.commit()
                        cur.execute("UPDATE urls SET shortpath=? WHERE itemID=?", (shortpath, associated_itemID[0]))
                        con.commit() 
                    message= "We have "+str(long_url)+" stored for you as " + str(shortpath) + " and we updated your bundle to " + str(bundle) #send user back to frompage
                message= "We already have "+str(long_url)+" stored for you as " + str(shortpath_found_for_longurl[0][1]) #send user back to frompage
            # Case 2: long_url not in db, and user enters both long_url and shortpath
            elif shortpath != "":
                # check whether user's choice of shortpath is already taken
                shortpath_taken = False
                for i in range(len(all_shortpaths_found)):
                    if shortpath == all_shortpaths_found[i][0]:
                        shortpath_taken = True
                if shortpath_taken == False:
                    write_to_database(int(userid), str(long_url), str(shortpath), bundle)
                    message= "We saved -> "+str(long_url)+" as " + str(shortpath)  #send user back to frompage
                else:
                    # if user's choice of shortpath is taken, auto-generate random path
                    new_id=id_gen()
                    new_id_taken = True
                    while new_id_taken == True:
                        new_id_taken = False
                        for i in range(len(all_shortpaths_found)):
                            if new_id == all_shortpaths_found[i][0]:
                                new_id_taken = True
                                continue
                    write_to_database(int(userid), str(long_url), str(new_id), bundle)
                    message= "The shortpath "+str(shortpath)+" is already taken, "+"\nSo we saved-> " + str(long_url) + " as " + str(new_id)  #send user back to frompage
            # Case 3: long_url not in db, and user enters only a long_url
            else:
                new_id=id_gen()
                new_id_taken = True
                while new_id_taken == True:
                    new_id_taken = False
                    for i in range(len(all_shortpaths_found)):
                        if new_id == all_shortpaths_found[i][0]:
                            new_id=id_gen()
                            new_id_taken = True
                            continue
                write_to_database(int(userid), str(long_url), str(new_id), bundle)
                message= "We saved-> " + str(long_url) + " as " + str(new_id)  #send user back to frompage
            
            return flask.redirect(path)
            
        else:
            return flask.abort(404)
    else: 
        return flask.render_template('index.html') 


## part1(4-5)
@app.route('/short/<name>', methods=['GET'])
def shorts_get(name):
    """If shortpath is registered, it redirects to longurl. If shortpath is not registered, it raise 404 error message."""
    con = lite.connect(dbfile)
    with con:
        cur = con.cursor()
        cur.execute("SELECT itemID, longURL FROM urls WHERE shortpath=?", (name,))
        longurl_tuple = cur.fetchall()
        cur.execute("SELECT numClicks FROM items WHERE itemID=?", (longurl_tuple[0][0],))
        numclicks = cur.fetchone()

    incremented_numclicks = int(numclicks[0]) + 1
    app.logger.debug('incremented_numclicks is ' + str(incremented_numclicks))

    if len(longurl_tuple) > 0:
        app.logger.debug(longurl_tuple)
        destination = longurl_tuple[0][1]
        app.logger.debug(destination)
        # Increment numClicks by one
        con = lite.connect(dbfile)
        with con:
            cur = con.cursor()
            cur.execute("UPDATE items SET numClicks=? WHERE itemID=?", (incremented_numclicks, longurl_tuple[0][0]))
            con.commit()
        return flask.redirect(destination)
    else: #This is the case that the short path is not registered in the db file, therefore display 404 error message.
        return flask.abort(404)


@app.route('/category', methods = ['GET', 'POST'])
def category():
    if 'username' in session:
        if request.method=='GET':
            con = lite.connect(dbfile)
            with con:
                app.logger.debug('category')
                cur = con.cursor()
                cur.execute("SELECT id FROM user_pass WHERE email=?",(session['username'],))
                userid = cur.fetchone()
                app.logger.debug(userid)
                cur.execute("SELECT bundleName FROM bundles")
                bundles_tuples = cur.fetchall()
                allbundles = []
                for item in bundles_tuples:
                    allbundles.append(item[0])
                app.logger.debug(allbundles)
                cur.execute("SELECT longURL, shortpath, numClicks, bundleID FROM urls JOIN items ON urls.itemID=items.itemID WHERE userID=? GROUP BY longURL", (userid[0],))
                pre_wholelist = cur.fetchall()
                pre_wholelist = sorted(pre_wholelist, key=lambda item: item[2], reverse=True)
                app.logger.debug(pre_wholelist)
                wholelist=[]
                for item in pre_wholelist:
                    if item[3]==0:
                        wholelist.append((item[0],item[1],item[2]))
               
            return flask.render_template('category.html', allbundles=allbundles, wholelist=wholelist)
        elif request.method=='POST':
            value=request.data
            app.logger.debug(value)
            cleaned_value=value.split(',')
            app.logger.debug(cleaned_value[0])#this is short path
            app.logger.debug(cleaned_value[1])#this is category
            if cleaned_value[1]=="delete":
                app.logger.debug('cleaned_value[0] is ' + str(cleaned_value[0]))
                stripped_shortpath = cleaned_value[0][1:]
                app.logger.debug('stripped_shortpath is ' + str(stripped_shortpath))
                con = lite.connect(dbfile)
                with con:
                    cur = con.cursor() 
                    cur.execute("SELECT itemID FROM urls WHERE shortpath=?", (stripped_shortpath,))
                    itemid = cur.fetchone()
                    app.logger.debug(itemid)
                    cur.execute("DELETE FROM urls WHERE shortpath=?", (stripped_shortpath,))
                    cur.execute("DELETE FROM items WHERE itemID=?", (itemid[0],))
                    con.commit() 
            else:#category change
                con = lite.connect(dbfile)
                with con:
                    cur = con.cursor()
                    cur.execute("SELECT bundleID FROM bundles WHERE bundleName=?", (cleaned_value[1],))
                    bundleid = cur.fetchone()
                    app.logger.debug("bundleid queried is")
                    app.logger.debug(bundleid)
                    cur.execute("SELECT itemID FROM urls WHERE shortpath=?", (cleaned_value[0],))
                    itemid = cur.fetchone()
                    cur.execute("UPDATE items SET bundleID=? WHERE itemID=?", (bundleid[0], itemid[0]))
                    con.commit()
            

        #     con = lite.connect(dbfile)
        # with con:
        #     cur = con.cursor()
        #     cur.execute("SELECT id FROM user_pass WHERE email=?",(session['username'],))
        #     userid = cur.fetchone()
        #     cur.execute("SELECT longURL FROM urls JOIN items ON urls.itemID=items.itemID WHERE bundleID IS NULL AND userID=? GROUP BY longURL", (userid[0],))
        #     longurls_list = cur.fetchall()
        #     longurls_list_formatted = []
        #     app.logger.debug(longurls_list)
        #     for item in longurls_list:
        #         longurls_list_formatted.append(item[0])
        #     app.logger.debug(longurls_list_formatted)
        # return flask.render_template('category.html', longurls_list=longurls_list_formatted)
    else:
        return flask.render_template('index.html')

# each_category page
@app.route('/category/<name>', methods = ['GET', 'POST'])
def each_category(name):
    if 'username' in session:
        if request.method=='GET':
            con = lite.connect(dbfile)
            with con:
                cur = con.cursor()
                cur.execute("SELECT id FROM user_pass WHERE email=?",(session['username'],))
                userid = cur.fetchone()
                cur.execute("SELECT bundleName FROM bundles")
                bundles_tuples = cur.fetchall()
                app.logger.debug(bundles_tuples)
                if len(bundles_tuples)<1:
                    flask.abort(404)
                else:

                    allbundles = []
                    for item in bundles_tuples:
                        allbundles.append(item[0])
                    app.logger.debug(name)
                    cur.execute("SELECT bundleID FROM bundles WHERE bundleName=?",(str(name),))
                    bundleID=cur.fetchall()
                    app.logger.debug(bundleID)

                    cur.execute("SELECT longURL, shortpath, numClicks, bundleID FROM items JOIN urls ON items.itemID=urls.itemID WHERE userID=?", (userid[0],))
                    pre_wholelist = cur.fetchall()
                    pre_wholelist = sorted(pre_wholelist, key=lambda item: item[2], reverse=True)
                    app.logger.debug(pre_wholelist)
                    wholelist=[]

                    for item in pre_wholelist:
                        if item[3]==bundleID[0][0]:
                            wholelist.append((item[0],item[1],item[2]))
                    app.logger.debug(wholelist)



            return flask.render_template('each_category.html', allbundles = allbundles, wholelist=wholelist)
        elif request.method=='POST':
            value=request.data
            app.logger.debug(value)
            cleaned_value=value.split(',')
            app.logger.debug(cleaned_value[0])#this is short path
            app.logger.debug(cleaned_value[1])#this is category
            if cleaned_value[1]=="delete":
                app.logger.debug('cleaned_value[0] is ' + str(cleaned_value[0]))
                stripped_shortpath = cleaned_value[0][1:]
                app.logger.debug('stripped_shortpath is ' + str(stripped_shortpath))
                con = lite.connect(dbfile)
                with con:
                    cur = con.cursor() 
                    cur.execute("SELECT itemID FROM urls WHERE shortpath=?", (stripped_shortpath,))
                    itemid = cur.fetchone()
                    app.logger.debug(itemid)
                    cur.execute("DELETE FROM urls WHERE shortpath=?", (stripped_shortpath,))
                    cur.execute("DELETE FROM items WHERE itemID=?", (itemid[0],))
                    con.commit() 
            else:#category change
                con = lite.connect(dbfile)
                with con:
                    cur = con.cursor()
                    cur.execute("SELECT bundleID FROM bundles WHERE bundleName=?", (cleaned_value[1],))
                    bundleid = cur.fetchone()
                    app.logger.debug("bundleid queried is")
                    app.logger.debug(bundleid)
                    cur.execute("SELECT itemID FROM urls WHERE shortpath=?", (cleaned_value[0],))
                    itemid = cur.fetchone()
                    cur.execute("UPDATE items SET bundleID=? WHERE itemID=?", (bundleid[0], itemid[0]))
                    con.commit()
            return 



    else:
        app.logger.debug("elsecase")
        return flask.abort(404)




## part2
#(sign up)

@app.route('/home', methods=['GET','POST'])
def home(): #checking whether the user is already in session.
    if 'username' in session:
        flask.flash('Signed in as %s' % flask.escape(session['username']))

        # Query database to get user's long urls
        app.logger.debug('hello1')
        if request.method=='GET':
            con = lite.connect(dbfile)
            with con:
                app.logger.debug('hello2')
                cur = con.cursor()
                cur.execute("SELECT id FROM user_pass WHERE email=?",(session['username'],))
                userid = cur.fetchone()
                app.logger.debug(userid)
                cur.execute("SELECT bundleName FROM bundles")
                bundles_tuples = cur.fetchall()
                allbundles = []
                for item in bundles_tuples:
                    allbundles.append(item[0])
                app.logger.debug(allbundles)
                cur.execute("SELECT longURL, shortpath, numClicks, bundleID FROM urls JOIN items ON urls.itemID=items.itemID WHERE userID=? GROUP BY longURL", (userid[0],))
                pre_wholelist = cur.fetchall()
                pre_wholelist = sorted(pre_wholelist, key=lambda item: item[2], reverse=True)
                wholelist=[]

                for item in pre_wholelist:
                    item=list(item)
                    app.logger.debug(item)
                    if item[3]==1:
                        item[3]="News"
                        wholelist.append(item)
                    elif item[3]==2:
                        item[3]="Food"
                        wholelist.append(item)
                    elif item[3]==3:
                        item[3]="Health"
                        wholelist.append(item)
                    elif item[3]==4:
                        item[3]="Sports"
                        wholelist.append(item)
                    else:
                        item[3]="Uncategorized"
                        wholelist.append(item)
                app.logger.debug(wholelist)
               
            return flask.render_template('test-home.html', allbundles=allbundles, wholelist=wholelist)

        elif request.method=='POST':
            value=request.data
            app.logger.debug(value)
            cleaned_value=value.split(',')
            app.logger.debug(cleaned_value[0])#this is short path
            app.logger.debug(cleaned_value[1])#this is category
            if cleaned_value[1]=="delete":
                app.logger.debug('cleaned_value[0] is ' + str(cleaned_value[0]))
                stripped_shortpath = cleaned_value[0][1:]
                app.logger.debug('stripped_shortpath is ' + str(stripped_shortpath))
                con = lite.connect(dbfile)
                with con:
                    cur = con.cursor() 
                    cur.execute("SELECT itemID FROM urls WHERE shortpath=?", (stripped_shortpath,))
                    itemid = cur.fetchone()
                    app.logger.debug(itemid)
                    cur.execute("DELETE FROM urls WHERE shortpath=?", (stripped_shortpath,))
                    cur.execute("DELETE FROM items WHERE itemID=?", (itemid[0],))
                    con.commit() 
            else:#category change
                con = lite.connect(dbfile)
                with con:
                    cur = con.cursor()
                    cur.execute("SELECT bundleID FROM bundles WHERE bundleName=?", (cleaned_value[1],))
                    bundleid = cur.fetchone()
                    app.logger.debug("bundleid queried is")
                    app.logger.debug(bundleid)
                    cur.execute("SELECT itemID FROM urls WHERE shortpath=?", (cleaned_value[0],))
                    itemid = cur.fetchone()
                    cur.execute("UPDATE items SET bundleID=? WHERE itemID=?", (bundleid[0], itemid[0]))
                    con.commit()

    return flask.render_template('index.html') #need to redirect to signin

@app.route('/register', methods = ['GET', 'POST'])
def register():
    error = None
    global urlpath
    if 'username' in session:
        app.logger.debug('hello')
        error = "you are already signed in"
        destination = urljoin(urlpath, 'home')
        return flask.redirect(destination)
    else:
        if request.method=='POST':
            
            urlpath = str(request.form.get('path'))
            destination = urljoin(urlpath, 'register')
            user_email = str(request.form.get('email'))
            user_pw = str(request.form.get('password'))
            app.logger.debug(user_pw)
            if user_email in dbpass:
                error = "You have already registered, please sign in"
                return flask.render_template('index.html', error=error)
            else:
                pw_hash = bcrypt.generate_password_hash(user_pw) #generate hashed passoword via bcrypt
                app.logger.debug(pw_hash)
                dbpass[user_email]=pw_hash
                con = lite.connect(dbfile) #initiating qulite3
                with con:
                    cur = con.cursor() #creating cursor
                    cur.execute('INSERT INTO user_pass(email) values (?);',(user_email,)) #put the hashed password to database
                    con.commit()
                session['username']=user_email
                app.logger.debug(urlpath)
                destination = urljoin(urlpath, 'home')
                return flask.redirect(destination)
        
    return flask.render_template('registration.html') # For the case of GET request


        
#(login validation)
def validate_login(input_email, input_password):
    if input_email not in dbpass:
        return "need register"
    else:
        if bcrypt.check_password_hash(dbpass[input_email], input_password) == True:
            return True
        else:
            return False


#(sign_in)
@app.route('/', methods = ['GET', 'POST'])
def sign_in():
    error = None #contents of error message
    global urlpath
    if 'username' in session:
        error = "you are already signed in"
        destination = urljoin(urlpath, 'home')
        return flask.redirect(destination)
    else:
        urlpath = str(request.form.get('path'))
        user_email=str(request.form.get('email'))
        user_pass=str(request.form.get('password'))
        status = validate_login(user_email, user_pass )
        if request.method == 'POST':
            # Case 1: successfully validated (-> session starts)
            if status == True:
                session['username']=request.form.get('email')
                destination = urljoin(urlpath, 'home')
                #app.logger.debug(flask.url_for('.home'))
                return flask.redirect(destination)
            # Case 2: the user is not registred yet (-> render registration page)
            elif status =='need register':
                destination = urljoin(urlpath, 'register')
                return flask.redirect(destination)
            # Case 3: the user is registred but put wrong password (-> render sign_in page with error message)
            else:
                error = 'Invalid username/password'
        return flask.render_template('index.html', error=error)

#(sign_out)
@app.route('/sign_out', methods = ['GET', 'POST'])
def sign_out():
        session.pop('username', None) #finish session
        error="Thank you!"
        return flask.render_template('sign_out.html', error=error)



if __name__ == "__main__":
    app.secret_key = os.urandom(24) #for starting session, setting secret_key
    app.run(port=int(environ['FLASK_PORT']))
