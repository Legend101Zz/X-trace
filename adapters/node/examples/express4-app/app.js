'use strict';
// Fixture served by `xtrace run -- node app.js`; the same routes run on Express 4 and 5.
const express = require('express');

const app = express();

function requestLogger(_request, _response, next) {
  next();
}
app.use(requestLogger);

app.get('/owners/:id', function showOwner(request, response) {
  response.status(200).json({ id: request.params.id });
});

const api = express.Router();
api.get('/pets/:petId', function showPet(request, response) {
  response.status(200).json({ pet: request.params.petId });
});
app.use('/api', api);

const clinic = express.Router();
clinic.get('/vets/:vetId', function showVet(request, response) {
  response.status(200).json({ vet: request.params.vetId });
});
app.use('/clinics/:clinicId', clinic);

const sub = express();
sub.get('/ping', function pingSub(_request, response) {
  response.status(200).send('pong');
});
app.use('/sub', sub);

app.get('/boom', function explode() {
  throw new Error('fixture failure with SECRET_CANARY');
});

app.get('/done', function finish(_request, response) {
  response.status(200).send('bye');
  response.on('finish', () => server.close(() => console.log('EXPRESS_SERVER_CLOSED')));
});

// Express error handlers are recognized by their four-argument arity.
// eslint-disable-next-line no-unused-vars
app.use(function appErrorHandler(_error, _request, response, _next) {
  response.status(500).send('failed');
});

const server = app.listen(Number(process.env.APP_PORT), '127.0.0.1', () => console.log('EXPRESS_READY'));
