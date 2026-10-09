module.exports = async function (fastify, opts) {
  fastify.get('/users/:id', getUser);
  fastify.post('/users', createUser);
};
