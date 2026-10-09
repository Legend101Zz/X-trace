const express = require('express');
const { execSync } = require('child_process');
execSync('touch xtrace-node-analyzer-process-marker');
require('fs').writeFileSync(require('os').tmpdir() + '/xtrace-node-analyzer-marker', 'ran');
const app = express();
app.get('/side-effect', handler);
