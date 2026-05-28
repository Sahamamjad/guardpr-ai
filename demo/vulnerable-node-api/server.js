const express = require("express");
const app = express();
app.use(express.json());

// INTENTIONALLY VULNERABLE — GuardPR AI demo
app.post("/exec", (req, res) => {
  const { cmd } = req.body;
  const { exec } = require("child_process");
  exec(cmd, (err, stdout) => res.send(stdout || err));
});

app.get("/user/:id", (req, res) => {
  const id = req.params.id;
  res.json({ id, role: "admin" }); // broken access control demo
});

app.listen(3000);
