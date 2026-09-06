const fs = require("node:fs");
const path = require("node:path");
const nunjucks = require("nunjucks");

const frontendDir = __dirname;

nunjucks.configure([
  frontendDir,
  path.join(frontendDir, "node_modules/govuk-frontend/dist")
], {
  autoescape: false
});

const html = nunjucks.render("template.njk", {
  themeColor: "#006d77"
});
fs.writeFileSync(path.join(frontendDir, "template.html"), html);
