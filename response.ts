import { randomBytes, createHmac, createHash } from "node:crypto";
import {
  statSync,
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  unlinkSync,
} from "node:fs";
import { sign, verify } from "jsonwebtoken";

// Types -----------------------
export interface dict<T> {
  [Key: string]: T;
}

type sessionConfig = {
  COOKIE_NAME: string;
  COOKIE_DOMAIN: string;
  COOKIE_PATH: null;
  COOKIE_HTTPONLY: boolean;
  COOKIE_SECURE: boolean;
  REFRESH_EACH_REQUEST: boolean;
  COOKIE_SAMESITE: string;
  KEY_PREFIX: string;
  PERMANENT: boolean;
  USE_SIGNER: boolean;
  ID_LENGTH: number;
  FILE_THRESHOLD: number;
  LIFETIME: number;
  MAX_COOKIE_SIZE: number;
  INTERFACE: string;
  STORAGE: string;
  JWT_STORAGE: string;
};
type V = string | number | boolean;
// -----------------------------

class callBack {
  data: dict<string>;
  modified: boolean;
  accessed: boolean;
  new: boolean = true;
  length = 0;
  constructor(initial: dict<string> = {}) {
    this.modified = true;
    this.accessed = true;
    this.data = {};
    if (Object.entries(initial).length) {
      this.new = false;
    }
    Object.assign(this.data, initial);
  }
  set(target: any, prop: string, val: string) {
    if (target.data[prop] != val) {
      this.modified = true;
      target.data[prop] = val;
      this.length++;
    }
    return target;
  }
  get(target: any, prop: string) {
    if (prop in target) {
      return target[prop];
    }
    return target.data[prop];
  }
  has(target: any, prop: string) {
    if (prop in target.data) {
      return true;
    }
    return false;
  }
  deleteProperty(target: any, val: string) {
    if (val in target.data) {
      this.modified = true;
      delete target.data[val];
    }
    return true;
  }
}
// --------------
export class serverSide extends callBack {
  modified: boolean;
  sid: string;
  permanent: boolean;
  constructor(
    sid: string = "",
    permanent: boolean = false,
    initial: dict<string> = {},
  ) {
    super(initial);
    this.modified = false;
    this.sid = sid;
    this.permanent = permanent;
  }
  get session() {
    return new Proxy(this, this);
  }
}

// --------------
export class fSession extends serverSide {}

// --------------
function str2Buffer(str: string): Buffer {
  const encoder = new TextEncoder();

  return Buffer.from(str);
}
function buff2Str(str: Uint8Array): string {
  const decoder = new TextDecoder();
  return decoder.decode(str);
}
function getSignature(key: Uint8Array, vals: Buffer) {
  const hmac = createHmac("sha1", key, vals);
  return hmac.digest();
}
export function timeDelta(date1: number, date2: number | null = null) {
  if (date2) {
    let diff = Math.abs(date2 - date1);
    return new Date(diff);
  } else {
    const now = new Date();
    const later = new Date();
    later.setDate(now.getDate() + date1);
    let diff = Math.abs(later.getTime() - now.getTime());
    return new Date(now.getTime() + diff);
  }
}
export function cookieDump(
  key: string,
  value: string = "",
  //
  {
    maxAge,
    expires,
    path = "/",
    domain,
    secure,
    httpOnly,
    sameSite,
  }: {
    maxAge?: Date | number;
    expires?: Date | string | number;
    path?: string | null;
    domain?: string;
    secure?: boolean;
    httpOnly?: boolean;
    sameSite?: string | null;
    sync_expires?: boolean;
    max_size?: number;
  },
) {
  if (maxAge instanceof Date) {
    maxAge = maxAge.getSeconds();
  }

  if (expires instanceof Date) {
    expires = expires.toUTCString();
  } else if (expires === 0) {
    expires = new Date().toUTCString();
  }

  const buf = [`${key}=${value}`];
  const cprops = [
    ["Domain", domain],
    ["Expires", expires],
    ["Max-Age", maxAge],
    ["Secure", secure],
    ["HttpOnly", httpOnly],
    ["Path", path],
    ["SameSite", sameSite],
  ];

  Object.entries(cprops).forEach(([k, [kk, v]]) => {
    if (v) {
      buf.push(`${kk}=${v}`);
    }
  });

  return buf.join("; ");
}

// --------------

class signer {
  secret: string;
  salt: string;
  constructor(secret: string, salt: string) {
    this.secret = secret;
    this.salt = salt;
  }
  getSignature(val: string) {
    const vals = str2Buffer(val);
    const key = this.deriveKey();
    const sig = getSignature(vals, key);
    return sig.toString("base64");
  }
  deriveKey() {
    const skey = str2Buffer(this.secret);
    const hmac = createHmac("sha1", skey);
    hmac.update(this.salt);
    return hmac.digest();
  }
  sign(val: string) {
    const sig = this.getSignature(val);
    const vals = str2Buffer(val + "." + sig);
    return buff2Str(vals);
  }
  unsign(signedVal: string) {
    if (!(signedVal.indexOf(".") > -1)) {
      throw Error("No sep found");
    }
    const isept = signedVal.indexOf(".");
    const val = signedVal.slice(0, isept);
    const sig = signedVal.slice(isept + 1);
    return this.verifySignature(val, sig);
  }
  loadUnsign(vals: string) {
    if (this.unsign(vals)) {
      const sval = str2Buffer(vals);
      const sept = str2Buffer(".")[0];
      if (!(sept in sval)) {
        throw Error("No sep found");
      }
      const isept = sval.indexOf(sept);
      const val = sval.subarray(0, isept);

      return Buffer.from(val.toString(), "base64").toString("utf-8");
    }
  }
  verifySignature(val: string, sig: string) {
    return this.getSignature(val) == sig ? true : false;
  }
}

export class sidGenerator {
  signer: signer;
  secret: string;
  constructor(secret: string) {
    this.secret = secret;
    this.signer = new signer(secret, secret + "_salty");
  }
  generate(len = 21) {
    const rbyte = randomBytes(len);
    let lbyte = rbyte.toString("base64");
    if (lbyte.endsWith("=")) {
      lbyte = lbyte.slice(0, -1);
    }
    return this.signer.sign(lbyte);
  }
  _sign(sid: string) {
    return this.signer.sign(sid);
  }
  _unsign(sid: string) {
    return this.signer.unsign(sid);
  }
  _untimed(
    sid: string,
    time?: {
      days?: number;
      hours?: number;
      minutes?: number;
      seconds?: number;
    },
  ) {}
}

export class serverInterface extends sidGenerator {
  sclass: typeof serverSide = serverSide;
  permanent: boolean = false;
  config: sessionConfig;
  constructor(config: sessionConfig, secret: string) {
    super(secret);
    this.config = config;
    this.permanent = config.PERMANENT;
  }
  setCookie(xsesh: serverSide, life: Date | number) {
    let sameSite = null;
    if (this.config.COOKIE_SAMESITE) {
      sameSite = this.config.COOKIE_SAMESITE;
    }

    return cookieDump(this.config.COOKIE_NAME!, xsesh.sid, {
      domain: "",
      path: this.config.COOKIE_PATH,
      httpOnly: this.config.COOKIE_HTTPONLY,
      secure: this.config.COOKIE_SECURE,
      sameSite: sameSite,
      expires: life,
    });
  }
  openSession(sid: string) {
    if (!sid) {
      return new this.sclass(this.generate(), this.permanent).session;
    }
    if (this._unsign(sid)) {
      return this.fetchSession(sid);
    } else {
      return new this.sclass(this.generate(), this.permanent).session;
    }
  }
  fetchSession(sid: string) {
    return {};
  }
}

class cacher {
  path: string;
  constructor(pathName: string = ".sessions") {
    this.path = pathName;
    if (!existsSync(this.path)) {
      mkdirSync(this.path, { recursive: true });
    }
  }
  fileName(fname: string) {
    const bkey = str2Buffer(fname);
    const hash = createHash("md5");
    hash.update(bkey);
    return hash.digest("hex");
  }

  isFile(path: string) {
    try {
      return statSync(path).isFile();
    } catch (err) {
      writeFileSync(path, str2Buffer(""));
    }
  }
  delete(key: string) {
    const gspot = this.path + "/" + this.fileName(key);
    try {
      if (existsSync(gspot)) {
        unlinkSync(gspot);
      }
    } catch (err) {}
  }
  //   -------------------
  set(key: string, data: dict<any>, life: number = 0) {
    const tempFilePath = this.path + "/" + this.fileName(key);
    this.isFile(tempFilePath);
    Object.assign(data, { life: timeDelta(life) });
    writeFileSync(tempFilePath, str2Buffer(JSON.stringify(data)));
  }
  get(key: string) {
    const gspot = this.fileName(key);
    try {
      const rfile = readFileSync(this.path + "/" + gspot);
      const dt = JSON.parse(buff2Str(rfile));
      if (new Date(dt.life).getTime() - new Date().getTime() > 0) {
        return JSON.parse(dt.data);
      } else {
        this.delete(key);
        return null;
      }
    } catch (err) {}
  }
}

class cSession extends serverInterface {
  cacher: cacher;
  sclass = fSession;
  constructor(config: sessionConfig, secret: string, cacherpath = ".sessions") {
    super(config, secret);
    this.cacher = new cacher(cacherpath);
  }
  saveSession(xsesh: serverSide, rsx?: any, deleteMe: boolean = false) {
    const prefs = this.config.KEY_PREFIX + xsesh.sid;
    if (!Object.entries(xsesh.data).length) {
      if (xsesh.modified || deleteMe) {
        this.cacher.delete(prefs);
        if (rsx) {
          const cookie = this.setCookie(xsesh, 0);
          rsx.setHeader("Set-Cookie", cookie);
        }
      }
      return;
    }
    const life = this.config.LIFETIME;
    const data = JSON.stringify(xsesh.data);

    this.cacher.set(prefs, { data }, life);
    if (rsx) {
      const cookie = this.setCookie(xsesh, timeDelta(life));
      rsx.setHeader("Set-Cookie", cookie);
    }
  }
  fetchSession(sid: string) {
    const prefs = this.config.KEY_PREFIX + sid;
    const data = this.cacher.get(prefs);
    return new this.sclass(sid, this.config.PERMANENT, data).session;
  }
}

export class reSession {
  config: sessionConfig;
  secret: string;
  constructor(config: sessionConfig | dict<any>, secret: string) {
    this.config = config as sessionConfig;
    this.secret = secret;
  }
  get(session: string) {
    if (session == "fs") {
    } else if (session == "jwt") {
      return new cSession(this.config, this.secret, this.config.JWT_STORAGE);
    }
    return new cSession(this.config, this.secret, this.config.STORAGE);
  }
}

export function hashedToken(len = 64) {
  return createHash("sha1").update(randomBytes(64)).digest("hex");
}
export class xjwt extends callBack {
  modified: boolean;
  sid: string;
  permanent: boolean;
  constructor(
    sid: string = "",
    permanent: boolean = false,
    initial: dict<string> = {},
  ) {
    super(initial);
    this.modified = false;
    this.sid = sid;
    this.permanent = permanent;
  }
  get jwt() {
    return new Proxy(this, this);
  }
}
export class _jwt extends sidGenerator {
  secret: string;
  salt: string;
  _xjwt = xjwt;
  constructor(secret: string, salt = "salty_jwt") {
    super(secret);
    this.secret = secret;
    this.salt = salt;
  }
  sign(payload: dict<any>) {
    const options = {
      issuer: this.salt, // Issuer of the token
    };
    const datax = {
      data: payload,
    };
    return sign(datax, this.secret, options);
  }
  get random() {
    const options = {
      issuer: this.salt, // Issuer of the token
    };
    const datax = {
      data: hashedToken(),
    };
    return sign(datax, this.secret, options);
  }
  verify(
    payload: string,
    time?: {
      days?: number;
      hours?: number;
      minutes?: number;
      seconds?: number;
    },
  ): dict<string> | null {
    try {
      const ever = verify(payload, this.secret);
      if (ever) {
        const { data, iat, iss } = ever as any;
        if (iss == this.salt) {
          if (time) {
            const { days, hours, minutes, seconds } = time;
            let endD = new Date(iat * 1000);
            if (days) {
              endD = new Date(endD.setDate(endD.getDate() + days));
            } else if (hours) {
              endD = new Date(endD.setHours(endD.getHours() + hours));
            } else if (minutes) {
              endD = new Date(endD.setMinutes(endD.getMinutes() + minutes));
            } else if (seconds) {
              endD = new Date(endD.setSeconds(endD.getSeconds() + seconds));
            }
            if (endD.getTime() - Date.now() > 0) {
              return data as dict<string>;
            }
          } else {
            return data as dict<string>;
          }
        }
      }
    } catch (e) {}

    return null;
  }
  open(
    token: string,
    time?: {
      days?: number;
      hours?: number;
      minutes?: number;
      seconds?: number;
    },
  ) {
    if (token) {
      const tv = this.verify(token, time);
      if (tv) {
        return new this._xjwt(token, true, tv).jwt;
      }
    }
    const rid = this.generate();
    return new this._xjwt(rid).jwt;
  }
  save(xjwts: xjwt) {
    const data = xjwts.data;
    if ("access_token" in data) {
      delete data["access_token"];
    }
    return this.sign(data);
  }
}
