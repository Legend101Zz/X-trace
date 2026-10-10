const fastify = require('fastify')({ logger: true });

fastify.get('/ping', async () => 'pong');
fastify.register(require('./routes/users'), { prefix: '/v1' });
fastify.route({ method: ['GET', 'HEAD'], url: '/multi', handler: multi });

module.exports = fastify;
