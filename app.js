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
app.post("/signup", async (req, res) => {
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
app.post("/login", async (req, res) => {
  supabase
    .from("vue_users")
    .select("*")
    .match({
      email: req.body.email,
    })
    .then((response) => {
      if (response.data != null) {
        if (!bcrypt.compareSync(req.body.password, response.data[0].password)) {
          return res.status(401).json({ login: "false" });
        } else {
          let token = jwt.sign({ userId: response.data[0].id }, SECRET_KEY);
          res.status(200).json({ login: "true", token: token });
        }
      }
    })
    .catch((err) => {
      res.json(err);
    });
});
app.get("/info", (req, res) => {
  let token = req.headers.token;
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({
        token_status: "unauthorized",
      });
    } else {
      supabase
        .from("vue_users")
        .select("*")
        .match({
          id: decoded.userId,
        })
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
    }
  });
});

const port = process.env.PORT || 8086;

app.listen(port, (err) => {
  if (err) return console.log(err);
  console.log("http://localhost:" + port);
});
