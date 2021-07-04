//jshint esversion:6
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
var GoogleStrategy = require('passport-google-oauth2').Strategy;
var FacebookStrategy = require('passport-facebook');
const findOrCreate = require("mongoose-findorcreate");

const app = express();
const port = 3000;

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
    useNewUrlParser: true, useUnifiedTopology: true
});

mongoose.set("useCreateIndex", true);
mongoose.set('useFindAndModify', false);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: Array
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback: true
},
    function (request, accessToken, refreshToken, profile, done) {
        console.log(profile);

        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return done(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets" //needs to be modified
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

// Check FB login status
// FB.getLoginStatus(function (response) {
//     statusChangeCallback(response);
// });

// function checkLoginState() {
//     FB.getLoginStatus(function (response) {
//         statusChangeCallback(response);
//     });
// }

app.get("/", function (req, res) {
    res.render("home");
});

app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/' }),
    function (req, res) {
        res.redirect('/secrets');
    });

app.get("/auth/google",
    passport.authenticate("google", {
        scope:
            ["email", "profile"]
    }));

app.get("/auth/google/secrets",
    passport.authenticate('google', {
        successRedirect: '/secrets',
        failureRedirect: '/'
    }));

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {

    if (req.isAuthenticated()) {
        User.find({ "secret": { $ne: null } }, function (err, foundUsers) {
            if (err) {
                console.log(err);
            } else {
                if (foundUsers) {
                    res.render("secrets", { userWithSecrets: foundUsers });
                }
            }
        });
    } else {
        res.redirect("/login");
    }
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", async (req, res) => {
    // const submittedSecret = req.body.secret;
    try {
        await User.findOneAndUpdate({ _id: req.user.id }, { $push: { secret: req.body.secret } });
        res.redirect("/secrets");
    } catch (error) {
        console.log(error);
    }
});

// *** Previous way I did this is below. Above method allows me to give the user multiple secrets though (in addition to adding Array to secret in Schema rather than String) ***
//     if (err) {
//         console.log(err)
//     } else {
//         if (foundUser) {
//             foundUser.secret = submittedSecret;
//             foundUser.save(function () {
//                 res.redirect("/secrets");


app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
});

app.post("/register", function (req, res) {

    User.register({ username: req.body.username, active: false }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function (req, res) {

    User.findOne({ username: req.body.username }, function (err, foundUser) {

        if (foundUser) {
            const user = new User({
                username: req.body.username,
                password: req.body.password
            });

            passport.authenticate("local", function (err, user) {
                if (err) {
                    console.log(err);
                } else {
                    if (user) {
                        req.login(user, function (err) {
                            res.redirect("/secrets");
                        });
                    } else {
                        res.redirect("/login");
                    }
                }
            })

                (req, res);
        } else {
            res.redirect("/login")
        }
    });
});

app.listen(port, function () {
    console.log(`Server started on port:${port}`);
});