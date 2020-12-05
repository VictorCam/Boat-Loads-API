const express = require('express');
var url = require('url');
const querystring = require('querystring')
const axios = require("axios")
const jwt = require("jsonwebtoken")
const app = express();
const {Datastore} = require('@google-cloud/datastore');
const bodyParser = require('body-parser');
const { parse } = require('path');
let http = require('http');
const {google} = require('googleapis')
const cookie = require("cookie");
const ver_tok = require('./verify_token');
const datastore = new Datastore();

const BOATS = "BOATS_V5"; const LOADS = "LOADS_V5"; const USERS = "USERS_V5"; const base_url = "http://localhost:8080"

const router = express.Router();
app.use(bodyParser.json());
function fromDatastore(item){ item.id = item[Datastore.KEY].id; return item; }
const oauth2Client = new google.auth.OAuth2( "48740089759-9n5kiuc6ohhobrhnj6hns9qjshhgf9vl.apps.googleusercontent.com", "z4j-KU3U0iqvsNoMGQVwYWfa", "http://localhost:8080/welcome" );
const scopes = ['https://www.googleapis.com/auth/userinfo.profile'];
var g_url = oauth2Client.generateAuthUrl({ access_type: 'offline', scope: scopes });

function put_load(bid, lid) {
    //first query (check if boat id exists)
    const q = datastore.createQuery(BOATS).filter("__key__", "=", datastore.key([BOATS, parseInt(bid,10)]));
	return datastore.runQuery(q).then( (entities) => {
            if(!Array.isArray(entities[0]) || !entities[0].length) { return "n_bid" }
            d_bid = entities[0].map(fromDatastore)

            //second query (check if load id exists)
            const q = datastore.createQuery(LOADS).filter("__key__", "=", datastore.key([LOADS, parseInt(lid,10)]));
            return datastore.runQuery(q).then( (entities) => {
                if(!Array.isArray(entities[0]) || !entities[0].length) { return "n_lid" }
                d_lid = entities[0].map(fromDatastore)

                //check if duplicate exists if it does then we give an error
                for(let i = 0; i < Object.keys(d_lid[0]["carrier"]).length; i++) {
                    if(d_lid[0]["carrier"][i].id == parseInt(bid,10)) { return "exists" }
                }

                var key_b = datastore.key([BOATS, parseInt(bid,10)]);
                var key_l = datastore.key([LOADS, parseInt(lid,10)]);
            
                d_bid[0]["loads"].push({"id": d_lid[0].id, "self": d_lid[0].self});
                d_lid[0]["carrier"].push({"id": d_bid[0].id, "name": d_bid[0].name, "self": d_bid[0].self});

                datastore.save({"key":key_b, "data":d_bid[0]}); //boat
                datastore.save({"key":key_l, "data":d_lid[0]}); //load
                return "success"
            })
    })
}

function delete_load(id, username) { //dont forget to check if the user is allowed to remove it
    const q = datastore.createQuery(LOADS).filter("__key__", "=", datastore.key([LOADS, parseInt(id,10)]));
	return datastore.runQuery(q).then( (entities) => {
        if(!Array.isArray(entities[0]) || !entities[0].length) { return "n_lid" }
        d_lid = entities[0].map(fromDatastore)

        //disassociate loads from boats
        for(let i = 0; i < Object.keys(d_lid[0]["carrier"]).length; i++) {
            const q = datastore.createQuery(BOATS).filter("username", "=", username).filter("__key__", "=", datastore.key([BOATS, parseInt(d_lid[0]["carrier"][i].id,10)]));
            datastore.runQuery(q).then( (entities) => {
                if(!Array.isArray(entities[0]) || !entities[0].length) { return "n_user" } //boat should exsits which means that the username odes not exist
                result2 = entities[0]
                result2[0]["loads"].pop()
                var key_b = datastore.key([BOATS, parseInt(result2[0].id,10)]);
                datastore.save({"key":key_b, "data":result2[0]})
            })
        }

        //delete the boat since we passed our checks
        const key_l = datastore.key([LOADS, parseInt(id,10)]);
        return datastore.delete(key_l);
    })
}

function post_loads(weight, content, date) {
    var key = datastore.key(LOADS);
    const json_load = {"weight": weight, "carrier": [], "content": content, "date": date};
	return datastore.save({"key":key, "data":json_load}).then(() => {
        json_load["self"] = base_url + "/loads/" + key.id;
        datastore.save({"key":key, "data":json_load}) //resaving with self url
        json_load["id"] = key.id;
        return json_load
    });
}

function get_loads() { //get all loads
    const q = datastore.createQuery(LOADS);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore);
    })
}

function get_load(id) { //get a specific load
    const q = datastore.createQuery(LOADS).filter("__key__", "=", datastore.key([LOADS, parseInt(id,10)]));
	return datastore.runQuery(q).then( (entities) => {
        if(!Array.isArray(entities[0]) || !entities[0].length) { return "n_lid" }
		return entities[0].map(fromDatastore);
    })
}

function get_priv_boat(username, id) {
    const q = datastore.createQuery(BOATS).filter("__key__", "=", datastore.key([BOATS, parseInt(id,10)]));
	return datastore.runQuery(q).then( (entities) => {
            results = entities[0].map(fromDatastore)
            if(!Array.isArray(entities[0]) || !entities[0].length) { return "n_bid" }
            if(results[0].username != username) { return "n_user" }
			return entities[0].map(fromDatastore);
		})
}

function get_pub_boat(id) {
    const q = datastore.createQuery(BOATS).filter("__key__", "=", datastore.key([BOATS, parseInt(id,10)]));
	return datastore.runQuery(q).then( (entities) => {
            result = entities[0].map(fromDatastore);
            if(!Array.isArray(entities[0]) || !entities[0].length) { return "n_bid" }
            if(result[0].public != true) { return "n_public" }
			return entities[0].map(fromDatastore);
		})
}

function post_boats(name, type, length, public, username){
    var key = datastore.key(BOATS);
    const json_boat = {"name": name, "type": type, "length": length, "loads": [], "public": public, "username": username};
    return datastore.save({"key":key, "data":json_boat}).then(() => {
        json_boat["self"] = base_url + "/boats/" + key.id;
        json_boat["id"] = key.id;
        datastore.save({"key":key, "data":json_boat}) //resaving with self url
        return json_boat
    });
}

function get_boats_nauth(){
    const q = datastore.createQuery(BOATS).filter('public', '=', true);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore);
		})
}

function get_boats_auth(username){
    const q = datastore.createQuery(BOATS).filter('username', "=", username);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore);
		})
}

function get_owner_id(username) {
    const q = datastore.createQuery(BOATS).filter('username', "=", username).filter('public', '=', false);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore);
	});
}

function delete_boat(id, username) {
    //first query
    const q = datastore.createQuery(BOATS).filter("__key__", "=", datastore.key([BOATS, parseInt(id,10)]));
	return datastore.runQuery(q).then( (entities) => {
        if(!Array.isArray(entities[0]) || !entities[0].length) { return "n_bid" }
        result = entities[0].map(fromDatastore)
        if(result[0].username != username) { return "n_owned" }

        //check if loads exists if so then we can remove them
        for(let i = 0; i < Object.keys(result[0]["loads"]).length; i++) {
            const q = datastore.createQuery(LOADS).filter("__key__", "=", datastore.key([LOADS, parseInt(result[0]["loads"][i].id,10)]));
            datastore.runQuery(q).then( (entities) => {
                result2 = entities[0]
                result2[0]["carrier"].pop()
                var key_l = datastore.key([LOADS, parseInt(result2[0].id,10)]);
                datastore.save({"key":key_l, "data":result2[0]})
            })
        }

        //delete the boat since we passed our checks
        const key_b = datastore.key([BOATS, parseInt(id,10)]);
        return datastore.delete(key_b);
    })
}

function get_users() {
    const q = datastore.createQuery(USERS);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore);
		})
}

/* ------------- Begin Controller Functions ------------- */

router.get('/boats',ver_tok, function(req, res){ //view all the boats (must be public:true)
    if(req.username != undefined) { //with auth
        get_boats_auth(req.username)
        .then( (results) => {

            if(req.query.page != undefined || req.query.limit != undefined) {
                const page = req.query.page
                const limit = req.query.limit
    
                const startIndex = (page - 1) * limit
                const endIndex = page * limit
    
                s_res = results.slice(startIndex, endIndex)
            }
            else {
                s_res = results
            }

            res.status(200).json(s_res);
        });
    }
    else {
        get_boats_nauth() //no auth
        .then( (results) => {
            res.status(200).json(results);
        });
    }
});


router.get('/owners/:username/boats',ver_tok, function(req, res){ //get all restricted boats from user (if jwt exists)
    if(req.params.username == undefined) {
        return res.status(400).send({"Error": "no username id specified"})
    }

    if(req.username != undefined) {
        get_owner_id(req.params.username)
        .then( (results) => {
            return res.status(200).json(results);
        });
    }
    else {
        return res.status(401).json({"Error": "unauthorized"})
    }
})

router.get('/boats/:id',ver_tok, function(req, res){ //get one boat either restrict (if jwt exists) or public (if not logged in)
    if(req.params.id == undefined) {
        return res.status(400).send({"Error": "no boat id specified"})
    }

    console.log(req.username)
    if(req.username != undefined) { //if user is logged in allow user to see their boats
        get_priv_boat(req.username, req.params.id)
        .then( (results) => {
            if(results == "n_bid") {
                return res.status(404).json({"Error": "boat id does not exist"})
            }
            if(results == "n_user") {
                return res.status(404).json({"Error": "you do not have permission to view this boat"})
            }
            return res.status(200).json(results);
        });
    }
    else {
        get_pub_boat(req.params.id)
        .then( (results) => {
            if(results == "n_bid") {
                return res.status(404).json({"Error": "boat id does not exist"})
            }
            if(results == "n_public") {
                return res.status(404).json({"Error": "you do not have permission to view this boat"})
            }
            return res.status(200).json(results);
        })
    }
})

router.post('/boats',ver_tok, function(req, res){ //add a post (jwt MUST exist)
    if (!req.is('application/json')) {
        return res.status(406).send({"Error": "please send valid json data"});
    }

    if(req.username != undefined) {
        post_boats(req.body.name, req.body.type, req.body.length, req.body.public, req.username)
        .then( result => {
            res.status(201).send(result);
        });
    }
    else {
        return res.status(401).json({"Error": "Unauthorized"});
    }
})

router.delete('/boats/:id',ver_tok, function(req, res) { //delete a boat (must be same user and valid id)
    if(req.params.id == undefined) {
        return res.status(400).send({"Error": "no boat id specified"})
    }

    if(req.username != undefined) {
        delete_boat(req.params.id, req.username)
        .then( (result) => {
            if(result == "n_owned") {
                return res.status(403).send({"Error": "unable to delete because it is owned by someone else"})
            }
            else if(result == "n_bid") {
                return res.status(404).send({"Error": "unable to delete boat because it does not exist"})
            }
            else {
                return res.status(204).end()
            }
        })
    }
    else {
        return res.status(401).json({"Error": "unauthorized"})
    }
})

router.post('/loads',ver_tok, function(req, res) { //post a load (just have jwt)
    if (!req.is('application/json')) {
        return res.status(406).send({"Error": "please send valid json data"});
    }

    if(req.username != undefined) {
        post_loads(req.body.weight, req.body.content, req.body.date)
        .then( result => {
            res.status(201).send(result);
        });
    }
    else {
        return res.status(401).json({"Error": "unauthorized"});
    }
})

router.get('/loads', function(req, res){ //show all loads regardless
    get_loads()
    .then( (results) => {

        if(req.query.page != undefined || req.query.limit != undefined) {
            const page = req.query.page
            const limit = req.query.limit

            const startIndex = (page - 1) * limit
            const endIndex = page * limit

            s_res = results.slice(startIndex, endIndex)
        }
        else {
            s_res = results
        }
        


        res.status(200).json(s_res);
    });
});

router.get('/loads/:id', function(req, res) { //show all public loads (if no jwt) // show all public and private boats of user (with jwt)
    if(req.params.id == undefined) {
        return res.status(400).send({"Error": "no load id specified"})
    }

    get_load(req.params.id)
    .then( (results) => {
        if(results == "n_lid") {
            return res.status(404).send({"Error": "the load id does not exist"})
        }
        else {
            return res.status(200).json(results);
        }
    });
});

router.delete('/loads/:id',ver_tok, function(req, res){ //delete a specific load but must be the right user with right id
    if(req.params.id == undefined) {
        return res.status(400).send({"Error": "no load id specified"})
    }

    if(req.username != undefined) {
        delete_load(req.params.id, req.username)
        .then( (result) => {
            console.log(result)
            if(result == "n_lid") {
                res.status(404).send({"Error": "no load with this load_id exists"});
            }
            else if(result == "n_user") {
                res.status(404).send({"Error": "you do not have permission to delete this load because the load is on someone elses boat"})
            }
            else {
                res.status(204).end()
            }
        })
    }
    else {
        return res.status(401).json({"Error": "unauthorized"})
    }
});

router.get('/users', function(req, res){ //show all public loads (if no jwt) // show all public and private boats of user (with jwt)
    get_users()
    .then( (results) => {
        res.status(200).json(results);
    });
});

router.put('/boats/:bid/loads/:lid', function(req, res){ //assign a load to a boat
    if(req.params.bid == undefined || req.params.lid == undefined) {
        return res.status(400).send({"Error": "invalid slip id or boat id"})
    }

    put_load(req.params.bid, req.params.lid)
    .then( (result) => {
        console.log("DATA", result)
        if(result == "n_lid" || result == "n_bid") {
            return res.status(404).send({"Error": "the specified boat and/or load does not exist"});
        }
        else if(result == "exists") {
            return res.status(403).send({"Error": "the load is already assigned"})
        }
        else {
            return res.status(204).end()
        }
    });
});

router.get('/welcome', function(req, res){ //sign up using google api (can sign up with multiple accounts)
    let p_url = url.parse(req.url);
    let pq_url = querystring.parse(p_url.query);
    g_code = pq_url.code;
  
    oauth2Client.getToken(g_code, (err, token) => {
        if (err) return res.redirect("/")
        oauth2Client.setCredentials(token);
  
        const getapi = async () => {
            try {
                const config = {headers: { Authorization: `Bearer ${token.access_token}`}}
                const api = "https://people.googleapis.com/v1/people/me?personFields=names"
                return await axios.get(api, config)
            } catch (err) {
                console.log(err)
            }
        }
        
        const g_request = async () => {
            const g_people = await getapi()
            username = g_people.data.names[0].displayName


            const q = datastore.createQuery(USERS).filter('username', "=", username);
            datastore.runQuery(q).then( (entities) => {
                results = entities[0].map(fromDatastore)
                if(!Array.isArray(entities[0]) || !entities[0].length) { 
                    //if user does not exist then we create one
                    var key = datastore.key(USERS);
                    const json_load = {"username": username};
                    datastore.save({"key":key, "data":json_load})
                }
                else {
                    //if there are results we do nothing
                }
            })

            const jtok = jwt.sign({"user": username}, "secret", {expiresIn: "24h"});
            res.setHeader('Set-Cookie', cookie.serialize('Authorization', `Bearer ${jtok}`, { httpOnly: true, /*maxAge: now,*/ sameSite: "strict"}));
            res.status(200).send(
              `
              <!DOCTYPE html>
              <html>
              <head>
              <title>You have authenticated!</title>
              </head>
              <body>
              <h3>USER_ID: ` + username + `</h3>` +
              `<h2>Authorization: Bearer ${jtok}</h2>` +
              `
              </body>
              </html>
              `
            )
        }
  
        g_request()
    })
})

router.get('/*', function(req, res){ //
    res.status(405).send({"Error": "Method is not allowed"})
})

router.get('/', function(req, res){ //url to login
    res.send(`<a href="` + g_url + `">Login to Google!</a>`)
})

app.use('/', router);

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});