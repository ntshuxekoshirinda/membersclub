import path from 'node:path';
import { Pool } from 'pg';
import express from 'express';
import type {Request, Response, NextFunction  } from "express";
import session from 'express-session';
import passport from 'passport';
import  {Strategy as LocalStrategy} from 'passport-local';
import { fileURLToPath} from "node:url";
import bcrypt from "bcryptjs";
import { body, validationResult} from 'express-validator';


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const pool = new Pool({
 connectionString: "postgresql://postgres:Admin@localhost:5432/lg"
});

 const app = express();
 
 //views
 app.set("views", path.join(__dirname, "views"));
 app.set("view engine", "ejs");

//Middleware

 app.use(session({ secret: "cats", resave: false, saveUninitialized: false}));
 app.use(passport.initialize());
 app.use(passport.session());
 app.use(express.urlencoded({ extended:false }));
 
 // passport strategy config

 passport.use(
    new LocalStrategy( async (username, password, done) =>{
        try {
            const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
            const user = rows[0]; 

            if (!user) {
                return done(null, false, { message: "Incorrect username"});
            }

            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return  done(null, false, { message: "incorrect password"});
            }
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    })
 );
passport.serializeUser((user: any, done) => done(null, user.id));
 passport.deserializeUser(async (id, done) => {
    try {
        const { rows } = await pool.query("SELECT * FROM users WHERE id =$1", [id]);
        const user = rows[0];

        done(null, user);
    } catch(err) {
        done(err);
    }
 });

 
 
 app.get("/", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT messages.*, users.firstname, users.lastname 
      FROM messages 
      LEFT JOIN users ON messages.author_id = users.id 
      ORDER BY timestamp DESC
    `);
    res.render("index", { user: req.user, messages: rows });
  } catch (err: any) {
    console.error("DETAILED DATABASE ERROR:", err.message);
    
    // This will show you the exact error in the browser so you don't have to guess
    res.status(500).send(`SQL Error: ${err.message}`);
  }
});


 app.get("/sign-up", (req, res) => res.render("sign-up-form", { errors: null }));
app.post("/sign-up", [
  body("firstname").trim().notEmpty().escape(),
  body("lastname").trim().notEmpty().escape(),
  body("username").isEmail().normalizeEmail(),
  body("password").isLength({ min: 8 }),
  body("confirmPassword").custom((val, { req }) => {
    if (val !== req.body.password) throw new Error("Passwords match fail");
    return true;
  })
], async (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.render("sign-up-form", { errors: errors.array() });
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    // Note: Admin checkbox or hidden field could be added here
    const isAdmin = req.body.admin_code === "SUPERSERVER" ? true : false; 
    
    await pool.query(
      "INSERT INTO users (username, password, firstname, lastname, memberstatus, admin) VALUES($1, $2, $3, $4, $5, $6)",
      [req.body.username, hashedPassword, req.body.firstname, req.body.lastname, false, isAdmin]
    );
    res.redirect("/log-in");
  } catch (err) { return next(err); }
});


app.get("/log-in", (req, res) => res.render("log-in"));
app.post("/log-in", 
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/log-in"
    })
 );


app.get("/log-out", (req, res, next) =>{
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});


app.get("/create-message", (req, res) => {
  if (!req.user) return res.redirect("/log-in");
  res.render("create-message-form", { errors: null });
});
app.post("/create-message", async (req, res) => {
  if (!req.user) return res.status(401).send("Unauthorized");
  await pool.query("INSERT INTO messages (title, text, author_id) VALUES ($1, $2, $3)", 
    [req.body.title, req.body.text, (req.user as any).id]);
  res.redirect("/");
});
 

app.get("/join-club", (req, res) => {
  if (!req.user) return res.redirect("/log-in");
  res.render("join-club", { error: null });
});
app.post("/join-club", async (req, res) => {
  const SECRET_PASSCODE = "odin";
  if (req.body.passcode === SECRET_PASSCODE) {
    await pool.query("UPDATE users SET membership_status = true WHERE id = $1", [(req.user as any).id]);
    res.redirect("/");
  } else {
    res.render("join-club", { error: "Incorrect Passcode!" });
  }
});


app.post("/delete-message/:id", async (req, res) => {
  if (req.user && (req.user as any).is_admin) {
    await pool.query("DELETE FROM messages WHERE id = $1", [req.params.id]);
    res.redirect("/");
  } else {
    res.status(403).send("Forbidden");
  }
});


 app.listen(3000, (error) => {
    if (error) {
        throw error;
    }
    console.log("app listening on port 3000!");
 });