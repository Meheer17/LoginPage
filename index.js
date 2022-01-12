    'use strict';
require('dotenv').config();
const express = require('express');
const myDB = require('./connections');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const bcrypt = require('bcrypt');
const ObjectID = require('mongodb').ObjectID;
const app = express();
const path = require('path')
const cookieParser = require('cookie-parser');
const URI = process.env.MONGO_URI;

app.set('view engine', 'pug');

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: true,
//   store: store,
  cookie: { secure: false },
  key: 'express.sid'
}));

app.use(passport.initialize());
app.use(passport.session());


myDB(async (client) => {
  const adn = await client.db('WEB').collection('LS');

    app.route('/').get((req, res) => {
    // Change the response to render the Pug template
    res.render('index');
  });
  app.route('/login').post(passport.authenticate('local', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/he');
  });

  app.route('/sign-up').get((req, res) => {
    res.render('2');
  });

    app.route('/he').get(ensureAuthenticated, (req,res) => {
        res.render('he')
    })

  app.route('/logout').get((req, res) => {
    req.logout();
    res.redirect('/');
  });
  app.route('/register').post(
    (req, res, next) => {
      const hash = bcrypt.hashSync(req.body.password, 12);
      adn.findOne({ username: req.body.username }, function (err, user) {
        if (err) {
          next(err);
        } else if (user) {
          res.redirect('/');
        } else {
          adn.insertOne({ username: req.body.username, password: hash }, (err, doc) => {
            if (err) {
              res.redirect('/');
            } else {
              next();
            }
          });
        }
      });
    },
    passport.authenticate('local', { failureRedirect: '/' }),
    (req, res, next) => {
      res.redirect('/he');
    }
  );

  app.use((req, res, next) => {
    res.status(404).type('text').send('Not Found');
  });
  
    passport.serializeUser((user, done) => {
        done(null, user._id);
    });

    passport.deserializeUser((id, done) => {
        adn.findOne({ _id: new ObjectID(id) }, (err, doc) => {
            done(null, doc);
        });
    });   

    passport.use(new LocalStrategy(
        (username, password, done) => {
            adn.findOne({username: username}, (err, user) => {
                console.log("User " + username + " attempted to login");
                if (err) {return done(err); }
                if (!user) {return done(null, false);}
                if (!bcrypt.compareSync(password, user.password)) {return done(null, false);}
                return done(null, user)
            });
        }
    ));


}).catch((e) => {
  app.route('/').get((req, res) => {
    res.render('index');
  });
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
}

app.listen(3000, () => {
  console.log('Listening on port 3000');
});