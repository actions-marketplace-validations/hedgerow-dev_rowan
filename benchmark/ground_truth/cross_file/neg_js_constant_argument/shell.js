const child_process = require("child_process");

function runFixed(cmd) {
  child_process.exec(cmd);
  eval(cmd);
}

module.exports = { runFixed };
