
window.util = {
  arrayBufferToBase64(arrayBuffer) {
    const resultUint8Array = new Uint8Array(arrayBuffer);
    const resultStr = String.fromCodePoint(...resultUint8Array);

    /**
    * btoa() 将ASCII字符串编码为base64
    * atob() 将base64解码为ASCII字符串
    */
    const resultBase64 = window.btoa(resultStr);
    return resultBase64;
  },

  arrayBufferToString(arrayBuffer) {
    /**
    * ArrayBuffer是储存二进制数据的一段内存
    * js不能直接读取这段二进制数据，可以使用两种方式读取
    * 1.new DateView(arrayBuffer)
    * 2.new [Typed]Array(arrayBuffer)
    */
    const resultUint8Array = new Uint8Array(arrayBuffer);

    /**
    * fromCodePoint将Unicode解码为字符串
    */
    const resultStr = String.fromCodePoint(...resultUint8Array);

    return resultStr;
  }
};
