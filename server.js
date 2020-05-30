const express = require('express');
const http = require('http');
const util = require('util');
const path = require('path');
const oauth = require('oauth');
const fs = require('fs');
const https = require('https');
const querystring = require('querystring');

const favicon = require('serve-favicon');
const logger = require('morgan');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const csrf = require('csurf');
// errorHandler = require('errorhandler');

const hs = require(path.join(__dirname, 'lib', 'hackhall-sendgrid'));
const c = require(path.join(__dirname, 'lib', 'colors'));
require(path.join(__dirname, 'lib', 'env-vars'));

const GitHubStrategy = require('passport-github').Strategy;
const passport = require('passport');

const app = express();

app.set('port', process.env.PORT || 3000);
app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(methodOverride());
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    key: 'sid',
    cookie: {
      secret: true,
      expires: false,
    },
    resave: true,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());
// app.use(csrf());
// app.use(function(req, res, next) {
// res.locals.csrf = req.csrfToken();
// return next();
// });

app.use(express.static(`${__dirname}/public`));

function logErrors(err, req, res, next) {
  if (typeof err === 'string') err = new Error(err);
  console.error('logErrors', err.toString());
  next(err);
}

function clientErrorHandler(err, req, res, next) {
  if (req.xhr) {
    console.error('clientErrors response');
    res.status(500).json({ error: err.toString() });
  } else {
    next(err);
  }
}

function errorHandler(err, req, res, next) {
  console.error('lastErrors response');
  res.status(500).send(err.toString());
}

const dbUrl = process.env.MONGOHQ_URL || 'mongodb://@127.0.0.1:27017/hackhall';
const mongoose = require('mongoose');
const routes = require('./routes');

const connection = mongoose.createConnection(dbUrl);
connection.on('error', console.error.bind(console, 'connection error:'));
connection.once('open', function () {
  console.info('Connected to database');
});

const models = require('./models');

function db(req, res, next) {
  req.db = {
    User: connection.model('User', models.User, 'users'),
    Post: connection.model('Post', models.Post, 'posts'),
  };
  return next();
}

const { checkUser } = routes.main;
const { checkAdmin } = routes.main;
const { checkApplicant } = routes.main;

app.get('/auth/angellist', routes.auth.angelList);
app.get(
  '/auth/angellist/callback',
  routes.auth.angelListCallback,
  routes.auth.angelListLogin,
  db,
  routes.users.findOrAddUser
);

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (obj, done) {
  done(null, obj);
});

if (process.env.NODE_ENV === 'production') {
  var gitHubOptions = {
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: 'http://hackhall.com/auth/github/callback',
  };
  app.set('stripePub', process.env.STRIPE_PUB);
  app.set('stripeSecret', process.env.STRIPE_SECRET);
} else {
  var gitHubOptions = {
    clientID: process.env.GITHUB_CLIENT_ID_LOCAL,
    clientSecret: process.env.GITHUB_CLIENT_SECRET_LOCAL,
    callbackURL: `http://localhost:${app.get('port')}/auth/github/callback`,
  };
  app.set('stripePub', process.env.STRIPE_PUB_LOCAL);
  app.set('stripeSecret', process.env.STRIPE_SECRET_LOCAL);
}
//ALWAYS TEST BEFORE RELEASING!
// app.set('stripePub', process.env.STRIPE_PUB_LOCAL);
// app.set('stripeSecret', process.env.STRIPE_SECRET_LOCAL);

app.use(function (req, res, next) {
  req.conf = {
    stripeSecret: app.get('stripeSecret'),
    stripePub: app.get('stripePub'),
  };
  return next();
});
passport.use(
  new GitHubStrategy(gitHubOptions, function (
    accessToken,
    refreshToken,
    profile,
    done
  ) {
    // console.log(profile)
    if (!profile._json.name)
      return done(
        new Error(
          'No first name and last name set on GitHub. We need both names please. You can fill it at https://github.com/settings/profile'
        )
      );
    let firstName = profile._json.name;
    let lastName = '';
    const spaceIndex = profile._json.name.indexOf(' ');
    if (spaceIndex > -1) {
      firstName = profile._json.name.substr(0, spaceIndex);
      lastName = profile._json.name.substr(spaceIndex);
    } else {
      return done(
        new Error(
          'We need both names please. No last name set on GitHub. You can fill it at https://github.com/settings/profile'
        )
      );
    }
    connection.model('User', models.User, 'users').findOrCreate(
      {
        email: profile._json.email,
      },
      {
        githubId: profile.id,
        displayName: profile.displayName,
        email: profile._json.email,
        lastName: lastName,
        firstName: firstName,
        githubProfile: profile._json,
        githubToken: accessToken,
        githubUrl: profile.profileUrl,
        photoUrl: profile._json.avatar_url,
      },
      function (err, user, created) {
        if (user.approved || !created) return done(err, user);
        hs.notifyNewApplication(user, function (error_hs, data) {
          if (error_hs) return done(error_hs);
          done(err, user);
        });
      }
    );
  })
);

app.get('/auth/github', passport.authenticate('github'), function (req, res) {
  // The request will be redirected to GitHub for authentication, so this
  // function will not be called.
});

app.get(
  '/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/#login' }),
  function (req, res) {
    if (req.isAuthenticated()) {
      req.session.auth = true;
      req.session.userId = req.user._id;
      req.session.user = req.user;
      req.session.admin = req.user.admin;
    }
    if (req.user.approved) {
      res.redirect('/#posts');
    } else {
      res.redirect('/#application');
    }
    // res.redirect('/');
  }
);

//MAIN
app.get('/api/profile', checkUser, db, routes.main.profile);
app.delete('/api/profile', checkUser, db, routes.main.delProfile);
app.post('/api/login', db, routes.main.login);
app.post('/api/logout', routes.main.logout);

//POSTS
app.get('/api/posts', checkUser, db, routes.posts.getPosts);
app.post('/api/posts', checkUser, db, routes.posts.add);
app.get('/api/posts/:id', checkUser, db, routes.posts.getPost);
app.put('/api/posts/:id', checkUser, db, routes.posts.updatePost);
app.delete('/api/posts/:id', checkUser, db, routes.posts.del);

//USERS
app.get('/api/users', checkUser, db, routes.users.getUsers);
app.get('/api/users/:id', checkUser, db, routes.users.getUser);
app.post('/api/users', checkAdmin, db, routes.users.add);
app.put('/api/users/:id', checkAdmin, db, routes.users.update);
app.delete('/api/users/:id', checkAdmin, db, routes.users.del);
app.get('/api/users.csv', checkAdmin, db, routes.users.getUsersCsv);

//APPLICATION

app.post('/api/application', checkAdmin, db, routes.application.add);
app.put('/api/application', checkApplicant, db, routes.application.update);
app.get('/api/application', checkApplicant, db, routes.application.get);

app.get('/api/vars', checkUser, function (req, res) {
  const FirebaseTokenGenerator = require('firebase-token-generator');
  const tokenGenerator = new FirebaseTokenGenerator(process.env.FIREBASE);
  const token = tokenGenerator.createToken({
    uid: req.session.user._id,
    name: req.session.user.displayName,
  });
  res
    .set('Content-type', 'text/javascript')
    .send(`var FIREBASE_TOKEN="${token}";`);
});

app.get('*', function (req, res) {
  res.status(404).send();
});

app.use(logErrors);
app.use(clientErrorHandler);
app.use(errorHandler);

// var ops = {
// key: fs.readFileSync('host.key'),
// cert: fs.readFileSync('server.crt') ,
// passphrase: ''
// };
// console.log (ops)
if (require.main === module) {
  const server = http.createServer(app);
  const io = require('socket.io')(server);
  io.on('connection', function (socket) {
    console.log('a user connected');
    socket.on('chat message', function (msg) {
      console.log(`message: ${msg}`);
    });
    socket.on('disconnect', function () {
      console.log('user disconnected');
    });
  });
  server.listen(app.get('port'), function () {
    console.info(
      `${c.blue}Express server listening on port ${app.get('port')}${c.reset}`
    );
  });
  // https.createServer(ops, app).listen(app.get('port'), function(){
  // console.info('HTTPS is running!')
  // });
} else {
  console.info(`${c.blue}Running app as a module${c.reset}`);
  exports.app = app;
}
