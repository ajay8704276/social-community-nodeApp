const bcrypt = require('bcryptjs');

/**
 * function to check admin
 * @param req
 * @param res
 * @param next
 * @returns {*}
 */
exports.checkAdmin = function (req, res, next) {
  if (
    req.session &&
    req.session.auth &&
    req.session.userId &&
    req.session.admin
  ) {
    console.info(`Access Admin${req.session.userId}`);
    return next();
  }
  next('User is not an admin');
};

/**
 * function to check user
 * @param request
 * @param response
 * @param next
 * @returns {*}
 */
exports.checkUser = function (request, response, next) {
  if (
    request.session &&
    request.session.auth &&
    (request.session.user.approved || request.session.admin)
  ) {
    console.info(`Access USER : ${request.session.userId}`);
    return next();
  }
  next('user is not logged in.');
};

/**
 * function to applicant
 * @param request
 * @param response
 * @param next
 * @returns {*}
 */
exports.checkApplicant = function (request, response, next) {
  if (
    request.session &&
    request.session.auth &&
    request.session.usreId &&
    (!request.session.user.approved || request.session.admin)
  ) {
    console.info(`Access USER : ${request.session.userId}`);
    return next();
  }
  next('user is not logged in');
};

/**
 * Login user and save user information in field value in
 * session
 * @param req
 * @param res
 * @param next
 */
exports.login = function (req, res, next) {
  console.log('Logging in user with email ', req.body.email);
  req.db.User.findOne(
    { email: req.body.email },
    null,
    { safe: true },
    function (err, user) {
      if (err) {
        return next(err);
      }
      if (user) {
        bcrypt.compare(req.body.password, user.password, function (
          error,
          match
        ) {
          if (error) {
            next(new Error('Wrong password '));
          } else {
            req.session.auth = true;
            req.session.userId = user._id.toHexString();
            req.session.user = user;

            if (user.admin) {
              req.session.admin = true;
            }
            console.info(`Login USER:${req.session.userId}`);

            res.status(200).json({
              msg: 'Authorized',
            });
          }
        });
      } else {
        next(new Error('User not found '));
      }
    }
  );
};

/**
 * Logging out user
 * @param req
 * @param res
 * @param next
 */

exports.logout = function (req, res, next) {
  console.info(`Logout USER : ${res.session.userId}`);
  req.session.destroy(function (err) {
    if (!err) {
      res.status(200).json({
        msg: 'User Logged Out',
      });
    } else {
      console.info('Error logging out user');
      res.status(400).json({
        msg: err.message,
      });
    }
  });
};

/**
 * Taking user to profile page
 * @param req
 * @param res
 * @param next
 */
exports.profile = function (req, res, next) {
  const fields =
    'firstName lastName displayName' +
    ' headline photoUrl admin approved banned' +
    ' role angelUrl twitterUrl facebookUrl linkedinUrl githubUrl';

  req.db.User.findProfileById(req.session.userId, fields, function (err, obj) {
    if (err) next(err);
    res.status(200).json(obj);
  });
};

/**
 * Delete user profile and and destroy session
 * associated with user
 * @param req
 * @param res
 * @param next
 */
exports.delProfile = function (req, res, next) {
  console.log('delete profile');
  console.log(req.session.userId);
  req.db.User.findByIdAndRemove(req.session.user._id, {}, function (err, obj) {
    if (err) {
      return next(err);
    }
    req.session.destroy(function (error) {
      if (error) {
        next(error);
      }
    });
    res.status(200).json(obj);
  });
};
