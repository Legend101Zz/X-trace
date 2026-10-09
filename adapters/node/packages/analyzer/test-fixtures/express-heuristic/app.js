const express = require("express");
const app = express();
const api = makeHttpClient();

app.get("/real", (req, res) => res.send("ok"));
api.get("/users", { timeout: 5 });

module.exports = app;
