const Base = require('./base.js');
const fido2 = require('./../util/fido2');
const { getUsers } = require('./../util/storage');

let num = 0;

module.exports = class extends Base {
  getChallengeAction() {
    const challenge = `${Date.now()}${Math.floor(Math.random() * 10000000)}${num++}`;
    this.ctx.body = {
      errno: 0,
      errmsg: 'ok',
      data: challenge
    };
  }

  getUsersAction() {
    const users = getUsers();
    this.ctx.body = {
      errno: 0,
      errmsg: 'ok',
      data: users
    };
  }

  getCredentialIdBase64ListAction() {
    const username = this.ctx.param('username');
    try {
      const users = getUsers(username);
      if (users.length === 0) throw new Error('用户不存在，请先注册');
      const credentialIdBase64List = users.map(userInfo => userInfo.credentialIdBase64);
      this.ctx.body = {
        errno: 0,
        errmsg: 'ok',
        data: credentialIdBase64List
      };
    } catch (err) {
      this.ctx.body = {
        errno: 1,
        errmsg: err.message
      };
    }
  }

  async makeCredentialAction() {
    const authenticatorAttestationResponse = this.ctx.post('authenticatorAttestationResponse');
    const username = this.ctx.post('username');
    const alias = this.ctx.post('alias');

    // 服务器接收到公钥信息后制作凭据
    try {
      const userInfo = await fido2.makeCredential(authenticatorAttestationResponse, { username, alias });
      this.ctx.body = {
        errno: 0,
        errmsg: '注册成功',
        data: {
          userInfo
        }
      };
    } catch (err) {
      this.ctx.body = {
        errno: 1,
        errmsg: err.message
      };
    }
  }

  async loginAction() {
    const authenticatorAssertionResponse = this.ctx.post('authenticatorAssertionResponse');
    const username = this.ctx.post('username');
    const alias = this.ctx.post('alias');

    try {
      const userInfo = await fido2.verifyAssertion(authenticatorAssertionResponse, { username, alias });
      this.ctx.body = {
        errno: 0,
        errmsg: '登陆成功',
        data: {
          userInfo
        }
      };
    } catch (err) {
      this.ctx.body = {
        errno: 1,
        errmsg: err.message
      };
    }
  }
};
