
const url = require('url')
const atob = require('atob')
const crypto = require('crypto');
const hostname = 'hagan.ml';
const cbor = require('cbor');
const jwkToPem = require('jwk-to-pem');
const uuid = require('uuid-parse');
const { set, get } = require('./storage');

function sha256(data) {
  const hash = crypto.createHash('sha256');
  hash.update(data);
  return hash.digest();
}

function validateClientData(clientDataJson, type) {
  if (clientDataJson.type !== type) throw new Error(`返回的clientDataJSON.type为${clientDataJson.type}，不等于${type}`);

  let origin;
  try {
    origin = url.parse(clientDataJson.origin);
  } catch (err) {
    throw new Error('返回的clientDataJSON.origin解析错误');
  }

  if (origin.hostname !== hostname) throw new Error('clientDataJson.origin错误');
  if (origin.protocol !== 'https:') throw new Error('不为https');

  let decodedChallenge;
  try {
    decodedChallenge = atob(clientDataJson.challenge);
  } catch (err) {
    throw new Error('base64转字符串失败');
  }
}
function coseToJwk(cose) {
  try {
    let publicKeyJwk = {};
    const publicKeyCbor = cbor.decodeFirstSync(cose);

    if (publicKeyCbor.get(3) === -7) {
      publicKeyJwk = {
        kty: 'EC',
        crv: 'P-256',
        x: publicKeyCbor.get(-2).toString('base64'),
        y: publicKeyCbor.get(-3).toString('base64')
      }
    } else if (publicKeyCbor.get(3) === -257) {
      publicKeyJwk = {
        kty: 'RSA',
        n: publicKeyCbor.get(-1).toString('base64'),
        e: publicKeyCbor.get(-2).toString('base64')
      }
    } else {
      throw new Error('Unknown public key algorithm');
    }

    return publicKeyJwk;
  } catch (e) {
    throw new Error('Could not decode COSE Key');
  }
}

function parseAuthenticatorData(authDataBuffer) {
  try {
    const authenticatorData = {};

    authenticatorData.rpIdHash = authDataBuffer.slice(0, 32);
    authenticatorData.flags = authDataBuffer[32];
    authenticatorData.signCount = (authDataBuffer[33] << 24) | (authDataBuffer[34] << 16) | (authDataBuffer[35] << 8) | (authDataBuffer[36]);

    if (authenticatorData.flags & 64) {
      const attestedCredentialData = {};
      attestedCredentialData.aaguid = uuid.unparse(authDataBuffer.slice(37, 53)).toUpperCase();
      attestedCredentialData.credentialIdLength = (authDataBuffer[53] << 8) | authDataBuffer[54];
      attestedCredentialData.credentialId = authDataBuffer.slice(55, 55 + attestedCredentialData.credentialIdLength);
      // Public key is the first CBOR element of the remaining buffer
      const publicKeyCoseBuffer = authDataBuffer.slice(55 + attestedCredentialData.credentialIdLength, authDataBuffer.length);

      // convert public key to JWK for storage
      attestedCredentialData.publicKeyJwk = coseToJwk(publicKeyCoseBuffer);

      authenticatorData.attestedCredentialData = attestedCredentialData;
    }

    if (authenticatorData.flags & 128) {
      // has extension data

      let extensionDataCbor;

      if (authenticatorData.attestedCredentialData) {
        // if we have attesttestedCredentialData, then extension data is
        // the second element
        extensionDataCbor = cbor.decodeAllSync(authDataBuffer.slice(55 + authenticatorData.attestedCredentialData.credentialIdLength, authDataBuffer.length));
        extensionDataCbor = extensionDataCbor[1];
      } else {
        // Else it's the first element
        extensionDataCbor = cbor.decodeFirstSync(authDataBuffer.slice(37, authDataBuffer.length));
      }

      authenticatorData.extensionData = cbor.encode(extensionDataCbor).toString('base64');
    }

    return authenticatorData;
  } catch (e) {
    throw new Error('Authenticator Data could not be parsed');
  }
}

module.exports = {
  async makeCredential(authenticatorAttestationResponse, { username, alias }) {
    // 0.基础校验
    if (!authenticatorAttestationResponse.attestationObjectBase64) throw new Error('attestationObjectBase64 不存在');
    if (!authenticatorAttestationResponse.clientDataString) throw new Error('clientDataString 不存在');

    // 1-2.将字符串clientDataJSON解析成json
    let clientDataJson;
    try {
      clientDataJson = JSON.parse(authenticatorAttestationResponse.clientDataString);
    } catch (err) {
      throw new Error('clientDataString 解析失败');
    }

    // 3-6.验证clientDataJSON数据
    validateClientData(clientDataJson, 'webauthn.create');

    // 7.使用SHA-256计算出publicKeyCredential.clientDataJSON的hash
    const clientDataHash = sha256(authenticatorAttestationResponse.clientDataString);

    // 8.对attestationObject执行CBOR解码
    let attestationObjectCbor;
    try {
      const buffer = Buffer.from(authenticatorAttestationResponse.attestationObjectBase64, 'base64');
      attestationObjectCbor = cbor.decodeFirstSync(buffer); // ???
    } catch (err) {
      throw new Error('attestationObjectBase64转attestationObjectCbor 解析失败');
    }

    // 8.1.解析attestationObject.authData数据
    const authenticatorData = parseAuthenticatorData(attestationObjectCbor.authData);

    // 8.2.authenticatorData中应该包含attestedCredentialData属性
    if (!authenticatorData.attestedCredentialData) throw new Error('authenticatorData.attestedCredentialData 不存在');

    // 9.验证authenticatorData中的rpIdHash是否是期望的rpIdHash
    if (!authenticatorData.rpIdHash.equals(sha256(hostname))) throw new Error('authenticatorData.rpIdHash与预期不符');

    // 10.验证authenticatorData是否设置了User Present标记位
    if ((authenticatorData.flags & 0b00000001) === 0) throw new Error('未设置User Present标记位');

    // 11.验证authenticatorData是否设置了User Verified标记位
    if ((authenticatorData.flags & 0b00000100) === 0) throw new Error('未设置User Verified标记位');

    // 验证通过，储存证书
    const userInfo = {
      credentialIdBase64: authenticatorData.attestedCredentialData.credentialId.toString('base64'),
      publicKeyJwk: authenticatorData.attestedCredentialData.publicKeyJwk,
      signCount: authenticatorData.signCount,
      username,
      alias
    };
    try {
      set(userInfo);
    } catch (err) {
      throw new Error(err.message);
    }
    return userInfo;
  },

  async verifyAssertion(authenticatorAssertionResponse, { username, alias }) {
    // 3.使用凭据的id属性查找相应的凭据公钥。
    const userInfo = get(username);
    if (!userInfo) throw new Error('用户不存在，请先注册');

    const publicKey = userInfo.publicKeyJwk;
    if (!publicKey) throw new Error('没找到publicKey');

    // 4.赋值
    const clientDataString = authenticatorAssertionResponse.clientDataString;
    const authDataBuffer = Buffer.from(authenticatorAssertionResponse.authenticatorDataBase64, 'base64');
    const signatureBuffer = Buffer.from(authenticatorAssertionResponse.signatureBase64, 'base64');

    // 5-6.clientDataJSON转json
    let clientDataJson;
    try {
      clientDataJson = JSON.parse(clientDataString);
    } catch (e) {
      throw new Error('clientDataJSON转json失败');
    }

    // 7-10.验证客户端数据
    validateClientData(clientDataJson, 'webauthn.get');

    // 解析用于接下来几个步骤的验证器数据
    const authenticatorData = parseAuthenticatorData(authDataBuffer);

    // 11.验证身份验证数据中的身份验证哈希是依赖方期望的身份验证哈希的SHA-256哈希。
    if (!authenticatorData.rpIdHash.equals(sha256(hostname))) throw new Error('authenticatorData.rpIdHash与预期不符');

    // 12.验证authenticatorData是否设置了User Present标记位
    if ((authenticatorData.flags & 0b00000001) === 0) throw new Error('未设置User Present标记位');

    // 13.验证authenticatorData是否设置了User Verified标记位
    if ((authenticatorData.flags & 0b00000100) === 0) throw new Error('未设置User Verified标记位');

    // 14.验证客户机扩展结果中的客户机扩展输出值和验证数据中的扩展中的验证器扩展输出值是否符合预期
    if (authenticatorData.extensionData) throw new Error('authenticatorData.extensionData不存在');

    // 15.让散列成为使用SHA-256在cData上计算散列的结果。
    const hash = sha256(clientDataString);

    // 16.使用在步骤3中查找的凭证公钥，验证签名是验证数据和散列的二进制连接上的有效签名。
    const verify = (publicKey.kty === 'RSA') ? crypto.createVerify('RSA-SHA256') : crypto.createVerify('sha256');
    verify.update(authDataBuffer);
    verify.update(hash);
    if (!verify.verify(jwkToPem(publicKey), signatureBuffer)) throw new Error('无法验证签名');

    // 17.验证签名计数
    if (authenticatorData.signCount !== 0 && authenticatorData.signCount < userInfo.signCount) {
      throw new Error('Received signCount of ' + authenticatorData.signCount +
          ' expected signCount > ' + userInfo.signCount);
    }

    // 返回已验证的凭据对象
    return userInfo;
  }
};
