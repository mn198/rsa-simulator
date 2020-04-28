import bigInt from 'big-integer';
import SecureRandom from './rng';

class RSA {
  static randomPrime(bits) {
    const min = bigInt.one.shiftLeft(bits - 1);
    const max = bigInt.one.shiftLeft(bits).prev();
    
    while (true) {
      let p = bigInt.randBetween(min, max);
      if (p.isProbablePrime(256)) {
        return p;
      } 
    }
  }

  static generate(keysize) {
    const e = bigInt(65537);
    let p;
    let q;
    let totient;
  
    do {
      p = this.randomPrime(keysize / 2);
      q = this.randomPrime(keysize / 2);
      totient = bigInt.lcm(
        p.prev(),
        q.prev()
      );
    } while (bigInt.gcd(e, totient).notEquals(1) || p.minus(q).abs().shiftRight(keysize / 2 - 100).isZero());

    return {
      keysize,
      totient,
      p,
      q,
      e, 
      n: p.multiply(q),
      d: e.modInv(totient),
    };
  }

  static encrypt(encodedMsg, n, e) {
    return bigInt(encodedMsg).modPow(e, n);
  }

  static decrypt(encryptedMsg, d, n) {
    return bigInt(encryptedMsg).modPow(d, n); 
  }

  static linebrk(s,n) {
    var ret = "";
    var i = 0;
    while(i + n < s.length) {
      ret += s.substring(i,i+n) + "\n";
      i += n;
    }
    return ret + s.substring(i,s.length)
    
  }

  static pkcs1pad2(s,n) {
    if(n < s.length + 11) { // TODO: fix for utf-8
      alert("Message too long for RSA");
      return null;
    }
    var ba = [];
    var i = s.length - 1;
    while(i >= 0 && n > 0) {
      var c = s.charCodeAt(i--);
      if(c < 128) { // encode using utf-8
        ba[--n] = c;
      }
      else if((c > 127) && (c < 2048)) {
        ba[--n] = (c & 63) | 128;
        ba[--n] = (c >> 6) | 192;
      }
      else {
        ba[--n] = (c & 63) | 128;
        ba[--n] = ((c >> 6) & 63) | 128;
        ba[--n] = (c >> 12) | 224;
      }
    }
    ba[--n] = 0;
    var rng = new SecureRandom();
    var x = [];
    while(n > 2) { // random non-zero pad
      x[0] = 0;
      while(x[0] === 0) rng.nextBytes(x);
      ba[--n] = x[0];
    }
    ba[--n] = 2;
    ba[--n] = 0;


    return bigInt.fromArray(ba, 256);
  }
  
  static pkcs1unpad2(d,n) {
    var b = d.toArray(256).value;
    var i = 0;
    while(i < b.length && b[i] === 0) ++i;
    if(b.length-i !== n-1 || b[i] !== 2)
      return null;
    ++i;
    while(b[i] !== 0)
      if(++i >= b.length) return null;
    var ret = "";
    while(++i < b.length) {
      var c = b[i] & 255;
      if(c < 128) { // utf-8 decode
        ret += String.fromCharCode(c);
      }
      else if((c > 191) && (c < 224)) {
        ret += String.fromCharCode(((c & 31) << 6) | (b[i+1] & 63));
        ++i;
      }
      else {
        ret += String.fromCharCode(((c & 15) << 12) | ((b[i+1] & 63) << 6) | (b[i+2] & 63));
        i += 2;
      }
    }
    return ret;
  }

}

export default RSA;