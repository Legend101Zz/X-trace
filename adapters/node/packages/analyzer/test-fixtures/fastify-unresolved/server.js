const fastify = require('fastify')({ logger: true });
const plugins = require('./plugins');

fastify.get('/ping', async () => 'pong');
// The plugin is chosen at run time; the analyzer cannot know which routes it registers.
fastify.register(plugins[process.env.PLUGIN], { prefix: '/dyn' });

module.exports = fastify;
