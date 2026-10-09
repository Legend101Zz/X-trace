const { Router } = require('express');
const adminRouter = Router();

adminRouter.delete('/users/:id', remove);

exports.adminRouter = adminRouter;
