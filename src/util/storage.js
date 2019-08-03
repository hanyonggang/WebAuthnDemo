
const { cloneDeep, find, filter } = require('lodash');

const users = [];

module.exports = {
  set(userInfo) {
    users.push(userInfo);
  },
  get(username) {
    return find(users, user => user.username === username);
  },
  getUsers(username) {
    if (username) return filter(users, user => user.username === username);
    return cloneDeep(users);
  }
};
