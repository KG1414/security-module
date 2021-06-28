//jshint esversion:6
// const bodyParser = require('body-parser');

const express = require('express');
const ejs = require('ejs');

const app = express();
const port = 3000;

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');


app.get("/", function (req, res) {
    res.render("home");
});

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});






app.listen(port, function () {
    console.log(`Server started on port:${port}`);
});