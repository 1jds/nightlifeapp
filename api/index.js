const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;
const bcrypt = require("bcrypt");
const nodeFetch = require("node-fetch");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
const pgSession = require("connect-pg-simple")(session);
const path = require("path");

// --------------------------------------------- //
// -------------  GENERAL SETUP  --------------- //
// --------------------------------------------- //
require("dotenv").config();
const app = express();
const PORT = process.env.PORT || 3001;
const API_KEY = process.env.YELP_API_KEY;

// -------- CORS -------- //
const acceptedOrigins = [
  /^https:\/\/nightlife-8ddy\.onrender\.com.*/,
  /^https:\/\/nightlifeapp\.vercel\.app/,
  /^https:\/\/github\.com.*/,
];
app.use(
  cors({
    origin: acceptedOrigins,
    credentials: true,
    methods: ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"],
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: false })); // Probably won't use this...
app.use(cookieParser());
// ----- TO SERVE THE REACT FRONT-END ----- //
// app.use(express.static("dist"));

// --------------------------------------------- //
// -----------  DATABASE CONNECTION  ----------- //
// --------------------------------------------- //

// Create a PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.ELEPHANTSQL_CONNECTION_URL,
  max: 5,
});

// Test the database connection
pool.connect((err, client, done) => {
  if (err) {
    console.error("Error connecting to the database", err);
  } else {
    console.log("Connected to the database");
  }
});

// --------------------------------------------- //
// -----------  PASSPORT STRATEGIES  ----------- //
// --------------------------------------------- //

// ---------- Local Strategy ---------- //
passport.use(
  "local",
  new LocalStrategy((username, password, done) => {
    // Query the PostgreSQL database to find a user by username
    pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username],
      (err, result) => {
        if (err) {
          return done(err);
        }
        // Check if the user exists
        const user = result.rows[0];
        if (!user) {
          return done(null, false);
        }
        // Check if the password is correct
        if (!bcrypt.compareSync(password, user.password_hash)) {
          return done(null, false);
        }
        // If the username and password are correct, return the user
        return done(null, user);
      }
    );
  })
);

// ---------- GitHub Strategy ---------- //
passport.use(
  "github",
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL:
        "https://nightlife-8ddy.onrender.com/api/login/github/callback",
    },
    async function (accessToken, refreshToken, profile, done) {
      // Query the PostgreSQL database to find a user by username.
      // Of course, this will not link to an already existing user account in the
      // database, unless the user has used the same username in both places.
      const userDbObj = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [profile.username]
      );
      if (!userDbObj.rows[0]) {
        const dbUser = await insertNewUserIntoDb(
          profile.username,
          profile.username
        );
        return done(null, dbUser);
      }
      return done(null, userDbObj);
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});

// --------------------------------------------- //
// -------------  EXPRESS SESSION  ------------- //
// --------------------------------------------- //

app.use(
  session({
    store: new pgSession({
      pool,
      tableName: "session", // Name of the session table in PostgreSQL
    }),
    secret: process.env.EXPRESS_SESSION_SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 14 * 24 * 60 * 60 * 1000, // 14 days session timeout
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// --------------------------------------------- //
// -----------------  ROUTING  ----------------- //
// --------------------------------------------- //

app.get("/", express.static(path.join(__dirname, "dist")));

app.get("/api/current-session", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.json({ currentlyLoggedIn: false });
  } else {
    // Call our helper function for getting a list of venues the user is attending
    getVenuesAttendingIds(req.user.user_id, (err, venuesAttendingIds) => {
      if (err) {
        return res.json({ err });
      } else {
        return res.json({
          currentlyLoggedIn: true,
          userId: req.user.user_id || req.user.rows[0].user_id,
          username: req.user.username || req.user.rows[0].username,
          venuesAttendingIds,
        });
      }
    });
  }
});

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Both username and password are required" });
  }
  const result = await pool.query("SELECT * FROM users WHERE username = $1;", [
    username,
  ]);
  if (result.rows[0]) {
    return res.json({ error: "Please select another username" });
  }
  const dbUser = await insertNewUserIntoDb(username, password);
  console.log(dbUser);
  if (dbUser) {
    return res.status(201).json({ message: "User created successfully" });
  } else {
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/login", passport.authenticate("local"), (req, res) => {
  if (!req.isAuthenticated()) {
    return res.json({ currentlyLoggedIn: false });
  } else {
    // Call our helper function for getting a list of venues the user is attending
    getVenuesAttendingIds(req.user.user_id, (err, venuesAttendingIds) => {
      if (err) {
        return res.json({ err });
      } else {
        return res.json({
          loginSuccessful: true,
          userId: req.user.user_id,
          username: req.user.username,
          venuesAttendingIds,
        });
      }
    });
  }
});

app.get(
  "/api/login/github",
  passport.authenticate("github", { scope: ["read:user"] })
);

app.get(
  "/api/login/github/callback",
  passport.authenticate("github", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/");
  }
);

app.get("/api/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    } else {
      res.json({ logoutSuccessful: true });
    }
  });
});

app.post("/api/venues-attending", async (req, res) => {
  if (!req.isAuthenticated()) {
    res.json({
      message: "Please login before attempting to access this route.",
    });
  }

  const receivedVenueYelpId = req.body.venueYelpId;
  const receivedUserId = req.body.userId;
  if (!receivedVenueYelpId || !receivedUserId) {
    res.json({
      error:
        "Error adding venue to plans. Venue and/or user data not received correctly. Try refreshing the page and searching again, or else log in again.",
    });
  }
  const client = await pool.connect();
  let venue_id = null;
  try {
    await client.query("BEGIN");
    const receivedVenueDbId = await client.query(
      "SELECT venue_id FROM venues WHERE venue_yelp_id = $1;",
      [receivedVenueYelpId]
    );
    if (receivedVenueDbId.rowCount === 1) {
      venue_id = receivedVenueDbId.rows[0].venue_id;
    } else {
      const insertNewVenue = await client.query(
        "INSERT INTO venues (venue_yelp_id) VALUES ($1) RETURNING venue_id;",
        [receivedVenueYelpId]
      );
      venue_id = insertNewVenue.rows[0].venue_id;
    }
    let result = await client.query(
      "INSERT INTO users_venues (user_id, venue_id) VALUES ($1, $2);",
      [receivedUserId, venue_id]
    );
    await client.query("COMMIT");
    return res.json({
      insertSuccessful: true,
      message: `Successfully inserted venue with id ${receivedVenueYelpId} into database`,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(
      "Error finding venue_id from venues at /api/venues-attending... :",
      error.message
    );
    return res.json({
      insertSuccessful: false,
      error,
    });
  } finally {
    client.release();
  }
});

app.post("/api/venue-remove", async (req, res) => {
  if (!req.isAuthenticated()) {
    res.json({
      message: "Please login before attempting to access this route.",
    });
  }

  const receivedVenueYelpId = req.body.venueYelpId;
  const receivedUserId = req.body.userId;
  if (!receivedVenueYelpId || !receivedUserId) {
    return res.json({
      error:
        "Error adding venue to plans. Venue and/or user data not received correctly. Try refreshing the page and searching again, or else log in again.",
    });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const receivedVenueDbId = await client.query(
      "SELECT venue_id FROM venues WHERE venue_yelp_id = $1;",
      [receivedVenueYelpId]
    );
    const resultOfRemove = await client.query(
      "DELETE FROM users_venues WHERE user_id = $1 AND venue_id = $2;",
      [receivedUserId, receivedVenueDbId.rows[0].venue_id]
    );
    await client.query("COMMIT");
    return res.json({
      removeSuccessful: true,
      message: `Successfully removed venue with id ${receivedVenueYelpId} from database`,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(
      "Error finding venue_id from venues at /api/venues-attending/remove... :",
      error.message
    );
    return res.json({
      removeSuccessful: false,
      error,
    });
  } finally {
    client.release();
  }
});

app.get("/api/number-attending/:yelpId", async (req, res) => {
  if (!req.isAuthenticated()) {
    res.json({
      message: "Please login before attempting to access this route.",
    });
  }
  const yelpId = req.params.yelpId;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      "SELECT venue_id FROM venues WHERE venue_yelp_id = $1;",
      [yelpId]
    );
    const attendingCount = await client.query(
      "SELECT COUNT(*) FROM users_venues WHERE venue_id = $1;",
      [result.rows[0].venue_id]
    );
    await client.query("COMMIT");
    return res.json({
      countAttendeesSuccessful: true,
      attendingCount: attendingCount.rows[0].count || 0,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(
      "Error counting venue attendees at /api/number-attending... :",
      error.message
    );
    return res.json({
      countAttendeesSuccessful: false,
      error: error,
    });
  } finally {
    client.release();
  }
});

// ------ Yelp API calls ------ //
app.get("/api/get-venues-attending/:venueYelpId", async (req, res) => {
  const url = `https://api.yelp.com/v3/businesses/${req.params.venueYelpId}`;
  const options = {
    method: "GET",
    headers: {
      accept: "application/json",
      Authorization: `Bearer ${API_KEY}`,
    },
  };
  try {
    const response = await nodeFetch(url, options);
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    const data = await response.json();
    return res.json(data);
  } catch (error) {
    console.error("Error fetching data:", error);
    return res.json({ error });
  }
});

app.post("/api/yelp-data/:location", async (req, res) => {
  let locationSearchTerm = req.params.location;
  const { searchOffset, searchIsOpenNow, searchSortBy, searchPrice } = req.body;
  let updatedSearchPrice;
  switch (searchPrice) {
    case 1:
      updatedSearchPrice = "&price=1";
      break;
    case 2:
      updatedSearchPrice = "&price=1&price=2";
      break;
    case 3:
      updatedSearchPrice = "&price=1&price=2&price=3";
      break;
    default:
      updatedSearchPrice = "&price=1&price=2&price=3&price=4";
  }

  const url = `https://api.yelp.com/v3/businesses/search?location=${locationSearchTerm}${updatedSearchPrice}&open_now=${searchIsOpenNow}&sort_by=${searchSortBy}&limit=5&offset=${searchOffset}`;
  const options = {
    method: "GET",
    headers: {
      accept: "application/json",
      Authorization: `Bearer ${API_KEY}`,
    },
  };
  try {
    const response = await nodeFetch(url, options);
    if (response.status === 400) {
      return res.status(400).json({
        locationFound: false,
        message:
          "No venue information was found for that location, please try searching another locality.",
      });
    }
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    const data = await response.json();
    return res.json(data);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

// --------------------------------------------- //
// -------------  HELPER FUNCTIONS  ------------ //
// --------------------------------------------- //

// Helper function to insert a new user into the database
async function insertNewUserIntoDb(username, password) {
  const hashed_password = bcrypt.hashSync(password, 12);
  try {
    const result = await pool.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING *",
      [username, hashed_password]
    );
    return result.rows[0];
  } catch (error) {
    console.error("Error inserting user into the database", error);
  }
}

// Helper function to get a list of all of the venues a given user is attending
function getVenuesAttendingIds(userId, callback) {
  pool.query(
    "SELECT venue_yelp_id FROM venues JOIN users_venues ON venues.venue_id = users_venues.venue_id WHERE users_venues.user_id = $1",
    [userId],
    (err, result) => {
      if (err) {
        callback(err, null);
      } else {
        const venuesAttendingStrArr = result?.rows.map(
          (item) => item.venue_yelp_id
        );
        callback(null, venuesAttendingStrArr);
      }
    }
  );
}

// --------------------------------------------- //
// ------------------  SERVER  ----------------- //
// --------------------------------------------- //

const server = app.listen(PORT, () =>
  console.log(`Server is listening on port ${PORT}`)
);

server.keepAliveTimeout = 120 * 1000;
server.headersTimeout = 120 * 1000;
