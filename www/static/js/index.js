
const eInputAlias = document.querySelector('#alias');
const eInputUsername = document.querySelector('#username');
const eBtnRegister = document.querySelector('#register');
const eSpanCredentialId = document.querySelector('#credentialId');
const eBtnLogin = document.querySelector('#login');
const eDivUsers = document.querySelector('#users');
const ePUser = document.querySelector('#user');

async function getUsers() {
  let users;
  try {
    const res = await axios.get('/api/getUsers');
    users = res.data.data;
  } catch (err) {
    return alert(err.message);
  }

  const fragment = document.createDocumentFragment();
  users.forEach(user => {
    const { username, alias, credentialIdBase64 } = user;

    const h5 = document.createElement('h5');
    h5.innerHTML = username;
    fragment.appendChild(h5);

    const ul = document.createElement('ul');
    fragment.appendChild(ul);

    const li1 = document.createElement('li');
    li1.innerHTML = `用户名: ${username}`;
    ul.appendChild(li1);

    const li2 = document.createElement('li');
    li2.innerHTML = `昵称: ${alias}`;
    ul.appendChild(li2);

    const li3 = document.createElement('li');
    li3.innerHTML = `证书id: ${credentialIdBase64}`;
    ul.appendChild(li3);
  });
  eDivUsers.innerHTML = '';
  eDivUsers.appendChild(fragment);
}

getUsers();

eBtnRegister.addEventListener('click', async function() {
  if (!window.PublicKeyCredential) return alert('该环境不支持WebAuthn验证方式');
  const username = eInputUsername.value;
  const alias = eInputAlias.value || username;
  if (!username) return alert('请填写用户名');

  // 获取挑战
  // WebAuthn依赖随机challenge来避免重放攻击，
  // challenge必须在信任的环境中随机生成并返回给客户端，
  // 而后客户端返回的值必须与服务端生成的值相匹配
  let challenge;
  try {
    const { data: { data } } = await axios.get('/api/getChallenge');
    challenge = data;
  } catch (err) {
    return alert('获取挑战失败');
  }

  const publicKeyCredentialCreationOptions = {
    challenge: Uint8Array.from(challenge, str => str.codePointAt(0)).buffer, // 随机字符串
    rp: { // 填写与站点提供方组织信息
      icon: 'http://p2.ssl.qhimg.com/t01d91636862957f76e.png', // 组织logo
      name: 'qiwoo', // 组织名称
      id: 'hagan.ml' // 组织域名，必须与页面域名一致，否则会报错
    },
    user: { // 用户账号信息
      displayName: alias, // 昵称，可重复
      name: username, // 用户名，比如邮箱地址，全局唯一
      id: Uint8Array.from(username, str => str.codePointAt(0)).buffer, // 验证器会将user.id与user.name和证书进行关联
      icon: 'https://p1.ssl.qhimg.com/t01c45194dca3cb2569.jpg' // 用户头像
    },
    pubKeyCredParams: [ // 定义凭证的预期特性列表，定义公钥类型以及加密算法
      { // 按照优先级的降序排列
        type: 'public-key', // 目前公钥类型只能为'public-key'
        alg: -7 // 用于生成密钥对的算法描述符，-7为带有SHA-256的椭圆曲线算法ECHSA
      },
      {
        type: 'public-key',
        alg: -37 // -37代表RSA算法
      }
    ],
    authenticatorSelection: { // 挑选验证器
      authenticatorAttachment: 'platform', // 使用不可跨平台的认证器, 'cross-platform'
      requireResidentKey: true, // 证书私钥是否必须储存在认证器客户端
      userVerification: 'required' // 用于在认证过程中如何验证用户, 'preferred', 'discouraged'
    },
    timeout: 60000 // 等待用户进行身份验证的时间，超时将返回失败
    // attestation: 'none' // 在验证器的客户端与依赖方之间传输证书时选择一个偏好，'none'表示依赖方对此证明不感兴趣
  };

  // 调用create()方法后浏览器会把参数传给身份验证器，开始进行身份验证，(指纹、PIN码、usb等)
  // 验证通过时身份验证器会创建非对称密钥对，验证器将使用私钥进行签名，公钥将成为验证的一部分
  // 最后验证器将公钥证书返回给浏览器
  // 公钥证书包含鉴定数据，证书id
  const publicKeyCredential = await navigator.credentials.create({ publicKey: publicKeyCredentialCreationOptions });

  /**
   * 浏览器将公钥证书提交给服务器进行注册
   */
  const body = {
    username,
    alias,
    authenticatorAttestationResponse: {
      clientDataString: util.arrayBufferToString(publicKeyCredential.response.clientDataJSON),
      attestationObjectBase64: util.arrayBufferToBase64(publicKeyCredential.response.attestationObject)
    }
  };
  const resMakeCredential = await axios.post('/api/makeCredential', body);
  alert(resMakeCredential.data.errmsg);
  if (resMakeCredential.data.errno !== 0) return;
  const credentialIdBase64 = resMakeCredential.data.data.userInfo.credentialIdBase64;
  // window.localStorage.setItem('credentialId', credentialId);
  getUsers();
});

eBtnLogin.addEventListener('click', async function() {
  if (!window.PublicKeyCredential) return alert('该环境不支持WebAuthn验证方式');
  const username = eInputUsername.value;
  const alias = eInputAlias.value || username;
  if (!username) return alert('请填写用户名');

  let credentialIdBase64List;
  try {
    const params = { username };
    const res = await axios.get('/api/getCredentialIdBase64List', { params });
    if (res.data.errno !== 0) return alert(res.data.errmsg);
    credentialIdBase64List = res.data.data;
  } catch (err) {
    return alert('获取CredentialId失败');
  }

  // 获取挑战
  let challenge;
  try {
    const { data: { data } } = await axios.get('/api/getChallenge');
    challenge = data;
  } catch (err) {
    return alert('获取challenge失败');
  }

  // const credentialId = window.localStorage.getItem('credentialId');
  const allowCredentials = credentialIdBase64List.map(credentialIdBase64 => ({
    type: 'public-key',
    id: Uint8Array.from(window.atob(credentialIdBase64), str => str.codePointAt(0)).buffer
  }));
  const publicKeyCredentialRequestOptions = {
    allowCredentials: allowCredentials,
    challenge: Uint8Array.from(challenge, str => str.codePointAt(0)).buffer,
    timeout: 60000
  };

  const publicKeyCredential = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });
  const body = {
    username,
    alias,
    authenticatorAssertionResponse: {
      clientDataString: util.arrayBufferToString(publicKeyCredential.response.clientDataJSON),
      authenticatorDataBase64: util.arrayBufferToBase64(publicKeyCredential.response.authenticatorData),
      signatureBase64: util.arrayBufferToBase64(publicKeyCredential.response.signature)
    }
  };
  const resLogin = await axios.post('/api/login', body);
  alert(resLogin.data.errmsg);
  if (resLogin.data.errno !== 0) return;
  ePUser.innerHTML = resLogin.data.data.userInfo.username;
  eSpanCredentialId.innerHTML = resLogin.data.data.userInfo.credentialIdBase64;
});
