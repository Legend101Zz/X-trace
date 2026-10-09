const express = require('express');
const axios = require('axios');
const usersRouter = require('./routes/users');
const { adminRouter } = require('./routes/admin');
const { PREFIX } = require('./constants');

const app = express();
const API = '/api';

app.get('/health', (req, res) => res.send('ok'));
app.use(API + '/users', usersRouter);
app.use('/admin', adminRouter);
app.use(PREFIX, require('./routes/versioned'));
app.post('/items/:itemId', createItem);
app.all('/any', anyHandler);
app.get(computePath(), dynamicHandler);
axios.get('/remote', {});
app.get('env');

module.exports = app;
