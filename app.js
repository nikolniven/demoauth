const path = require("path");
const express = require("express");
const session = require("express-session");
const mongodbStore = require("connect-mongodb-session");
const { ObjectId } = require("mongodb"); // Import ObjectId for MongoDB

const db = require("./data/database");
const demoRoutes = require("./routes/demo");

const MongoDBStore = mongodbStore(session);

const app = express();

const sessionStore = new MongoDBStore({
  uri: "mongodb://localhost:27017",
  databaseName: "auth-demo",
  collection: "sessions",
});

// Set EJS as the templating engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Middleware for serving static files and parsing request bodies
app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));

// Configure session handling
app.use(
  session({
    secret: "gheimnisvoll-secret",
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    // cookie: {
    //   maxAge: 30 * 24 * 60 * 60 * 1000, // Optional: set cookie expiration
    // },
  }),
);

// Middleware to handle authentication state and user information
app.use(function (req, res, next) {
  const user = req.session.user;
  const isAuth = req.session.isAuthenticated;

  if (!user || !isAuth) {
    res.locals.isAuth = false;
    res.locals.isAdmin = false;
    return next();
  }

  // Convert user ID to ObjectId for MongoDB query
  const userId = ObjectId.isValid(user.id) ? new ObjectId(user.id) : null;

  if (!userId) {
    console.error("Invalid user ID format.");
    res.locals.isAuth = false;
    res.locals.isAdmin = false;
    return next();
  }

  db.getDb()
    .collection("users")
    .findOne({ _id: userId })
    .then(function (userDoc) {
      if (!userDoc) {
        console.error("User document not found in the database.");
        res.locals.isAuth = false;
        res.locals.isAdmin = false;
        return next();
      }

      res.locals.isAuth = true;
      res.locals.isAdmin = userDoc.isAdmin;
      next();
    })
    .catch(function (err) {
      console.error("Error fetching user document:", err);
      res.locals.isAuth = false;
      res.locals.isAdmin = false;
      next();
    });
});

// Route handling
app.use(demoRoutes);

// Error handling middleware
app.use(function (error, req, res, next) {
  console.error("Unhandled error:", error);
  res.render("500");
});

// Start the server after connecting to the database
db.connectToDatabase().then(function () {
  app.listen(3000, function () {
    console.log("Server is running on http://localhost:3000");
  });
});
