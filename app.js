const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const SECRET_KEY = "merhabad";
const { createClient } = require("@supabase/supabase-js");
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

const supabase = createClient(
  "https://*************.supabase.co",
  "*********************"
);
app.post("/auth/signup", async (req, res) => {
  supabase
    .from("vue_users")
    .insert([
      {
        email: req.body.email,
        name: req.body.name,
        password: bcrypt.hashSync(req.body.password, 10),
      },
    ])
    .then((response) => {
      res.json([
        {
          error: response.error,
          data: response.data,
          status: response.status,
          statusText: response.statusText,
        },
      ]);
    })
    .catch((err) => {
      res.json(err);
    });
});
app.post("/auth/login", async (req, res) => {
  supabase
    .from("vue_users")
    .select("*")
    .match({
      email: req.body.email,
    })
    .then((response) => {
      if (response.data != null) {
        if (!bcrypt.compareSync(req.body.password, response.data[0].password)) {
          return res.status(401).json({
            login: "false",
          });
        } else {
          let token = jwt.sign(
            {
              userId: response.data[0].id,
              pass_12: bcrypt.hashSync(
                response.data[0].password.substr(0, 12),
                10
              ),
            },
            SECRET_KEY,
            {
              expiresIn: "1h",
            }
          );
          res.status(200).json({
            login: "true",
            token: token,
          });
        }
      } else {
        res.json({
          error: "email not",
        });
      }
    })
    .catch((err) => {
      res.json({
        dbError: "email not",
        error: err,
      });
    });
});
app.get("/auth/info", verifyToken, (req, res) => {
  jwt.verify(req.token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({
        token_status: "unauthorized",
      });
    } else if (decoded.pass_12 && decoded.userId) {
      supabase
        .from("vue_users")
        .select("*")
        .match({
          id: decoded.userId,
        })
        .then((response) => {
          if (
            !bcrypt.compareSync(
              response.data[0].password.substr(0, 12),
              decoded.pass_12
            )
          ) {
            return res.status(401).json({
              login: "false",
            });
          } else {
            res.json({
              error: response.error,
              data: {
                email: response.data[0].email,
                name: response.data[0].name,
              },
              status: response.status,
              statusText: response.statusText,
            });
          }
        })
        .catch((err) => {
          res.json({
            dbError: "id not",
            error: err,
          });
        });
    } else {
      return res.status(401).json({
        token_status: "unauthorized",
      });
    }
  });
});
app.get("/auth/logout", (req, res) => {
  res.json({});
});

function verifyToken(req, res, next) {
  const bearerHeader = req.headers["authorization"];
  if (typeof bearerHeader !== "undefined") {
    const bearer = bearerHeader.split(" ");
    const bearerToken = bearer[1];
    req.token = bearerToken;
    next();
  } else {
    res.sendStatus(403);
  }
}

const port = process.env.PORT || 3000;

app.listen(port, (err) => {
  if (err) return console.log(err);
  console.log("http://localhost:" + port);
});
