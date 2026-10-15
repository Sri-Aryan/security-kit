const router = require('express').Router();
router.get('/', listUsers);
router.get('/:id', getUser);
router.delete('/:id', isAdmin, deleteUser);
module.exports = router;
