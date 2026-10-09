const express = require('express');
const router = express.Router();

router.get('/', list);
router.get('/:id', show);
router.route('/:id/posts').get(listPosts).post(createPost);

module.exports = router;
