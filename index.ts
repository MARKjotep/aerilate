import {
  Http2ServerResponse,
  createSecureServer,
  ServerHttp2Stream,
} from "node:http2";
import zlib from "node:zlib";
import { writeFileSync, statSync, mkdirSync, readFileSync } from "node:fs";
import { promises as fr } from "node:fs";
import {
  reSession,
  fSession,
  cookieDump,
  timeDelta,
  _jwt,
  xjwt,
  timedJWT,
  serverInterface,
} from "./response";
import { request, strip } from "./request";
// -----------
import { Server, WebSocket } from "ws";
import { lookup } from "mime-types";
import { SupabaseClient } from "@supabase/supabase-js";
import { Client, QueryConfig } from "pg";

/**
 * TODO:
 * 1. Router - done
 * 2. Response - done
 * 3. Request - done
 * 3a Form data and strings - done
 * 4. Session - done
 * 5. Websocket - done
 * 6. CSRF - done
 * 7. JWT auth -
 * 8. GOOGLE Aut -
 * 9. Telegram --- in progress
 * 10. Fix the byte-range request for files - Done∫
 */

// Types -----------------------
export interface dict<T> {
  [Key: string]: T;
}
type V = string | number | boolean;
type meta<T> = {
  charset?: T;
  content?: T;
  "http-equiv"?: T;
  name?: T;
  media?: T;
  url?: T;
};
type link<T> = {
  href?: T;
  hreflang?: T;
  media?: T;
  referrerpolicy?: T;
  rel?: "stylesheet" | "icon" | "manifest" | T;
  sizes?: T;
  title?: T;
  type?: T;
  as?: T;
};

type impmap = {
  imports?: dict<string>;
  scopes?: dict<string>;
  integrity?: dict<string>;
};
type script<T> = {
  async?: T;
  crossorigin?: T;
  defer?: T;
  integrity?: T;
  nomodule?: T;
  referrerpolicy?: T;
  src?: T;
  type?: "text/javascript" | T;
  id?: T;
  importmap?: impmap;
  body?: T;
};
type base = {
  href?: string;
  target?: "_blank" | "_parent" | "_self" | "_top";
};
interface headP {
  title?: string;
  base?: base[];
  meta?: meta<V>[];
  link?: link<V>[];
  script?: script<V>[];
}

export interface sesh_db {
  sid: string;
  data: string;
  expiration: string;
  f_timed?: number;
  [key: string]: string | undefined | boolean | number;
}

interface repsWSS {
  WSS: InstanceType<typeof wss>;
  role: "maker" | "joiner";
}

interface sbase {
  CLIENT: SupabaseClient | null;
  TABLE: string;
}

// ----------------------------

export const { $$ } = (function () {
  const PROCESSES: (() => Promise<void>)[] = [];
  class $$ {
    static set p(a: any) {
      if (Array.isArray(a)) {
        console.log(...a);
      } else {
        console.log(a);
      }
    }
    static get O() {
      return {
        vals: Object.values,
        keys: Object.keys,
        items: Object.entries,
        has: Object.hasOwn,
      };
    }
    static makeID(length: number) {
      let result = "";
      const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
      const nums = "0123456789";

      let counter = 0;
      while (counter < length) {
        let chars = characters + (counter == 0 ? "" : nums);
        const charactersLength = chars.length;
        result += chars.charAt(Math.floor(Math.random() * charactersLength));
        counter += 1;
      }
      return result;
    }
    static makeID2(length: number) {
      let result = "";
      const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
      const nums = "0123456789~!@#$%^()_+|-";

      let counter = 0;
      while (counter < length) {
        let chars = characters + (counter == 0 ? "" : nums);

        const charactersLength = chars.length;
        result += chars.charAt(Math.floor(Math.random() * charactersLength));
        counter += 1;
      }
      return result;
    }
    static makeUUID() {
      let result = "";
      const characters = "abcdef";
      const nums = "0123456789";

      const dashIndex = [8, 13, 18, 23];
      let counter = 0;
      while (counter < 36) {
        let chars = characters + (counter == 0 ? "" : nums);
        const charactersLength = chars.length;
        if (dashIndex.includes(counter)) {
          result += "-";
        } else {
          result += chars.charAt(Math.floor(Math.random() * charactersLength));
        }

        counter += 1;
      }
      return result;
    }
    static make6D(length: number = 6) {
      let result = "";
      const nums = "0123456789";
      let counter = 0;
      while (counter < length) {
        let chars = nums;
        const charactersLength = chars.length;
        result += chars.charAt(Math.floor(Math.random() * charactersLength));
        counter += 1;
      }
      return result;
    }
    static isExpired(datestr: string, minutes: number = 15) {
      const xpire = parseInt(datestr);
      const xdate = new Date(xpire);
      xdate.setMinutes(xdate.getMinutes() + minutes);
      return !(xdate.getTime() > new Date().getTime());
    }

    static process(fn: () => Promise<void>) {
      PROCESSES.push(fn);
    }
  }

  process.on("SIGINT", async () => {
    PROCESSES.forEach(async (fn) => {
      await fn();
    });
    process.exit();
  });

  process.on("SIGTERM", async () => {
    PROCESSES.forEach(async (fn) => {
      await fn();
    });
    process.exit();
  });

  return { $$ };
})();

// Server temporary cache map
export class tempV<T extends fs> {
  key: string;
  data: Map<any, T>;
  constructor({ key }: { key: string }) {
    this.key = key;
    this.data = new Map();
  }
  get(val: string | undefined): T | undefined {
    return this.data.get(val);
  }
  set(data: T) {
    if (this.key in data) {
      this.data.set(data[this.key], data);
    }
  }
  delete(key: string) {
    this.data.delete(key);
  }
}

// Single query --
export class PGCache<T extends bs> {
  client: Client;
  query: string;
  f_timed: number;
  data: Map<any, T>;
  key: string;
  constructor(client: Client, key: string, query: string) {
    this.query = query;
    this.key = key;
    this.f_timed = Date.now();
    this.data = new Map();
    this.client = client;
  }
  async init(val: string): Promise<T | null> {
    const TQ = await this.client.query({
      text: this.query + ` where ${this.key} = $1`,
      values: [val],
    });
    // Delete keys with no value
    for (const [k, v] of this.data) {
      if (!v) {
        this.data.delete(k);
      }
    }
    if (TQ.rowCount) {
      const tr = TQ.rows[0];
      tr.f_timed = Date.now();
      this.data.set(val, tr);
      return tr;
    } else {
      this.data.set(val, null as any);
      return null;
    }
  }
  async checkLast(time: number) {
    const xl = new Date(time);
    xl.setMinutes(xl.getMinutes() + 15);
    if (xl.getTime() < Date.now()) {
      return true;
    }
    return false;
  }
  async get(val: string | undefined): Promise<T | null> {
    if (val) {
      const hdat = this.data.get(val);
      if (hdat == undefined) {
        return await this.init(val);
      } else {
        if (hdat && "f_timed" in hdat) {
          const atv = await this.checkLast(hdat.f_timed!);
          if (atv) {
            return await this.init(val);
          }
        }
        return hdat;
      }
    }
    return null;
  }
  async set(data: T) {
    if (this.key in data) {
      data.f_timed = Date.now();
      this.data.set(data[this.key], data);
    }
  }
  async delete(key: string) {
    this.data.delete(key);
  }
}

// json files
export class ForFS<T extends fs> {
  fs: string;
  f_timed: number;
  data: Map<any, T>;
  key: string;
  dir: string;
  constructor({ dir, fs, key }: { dir: string; fs: string; key: string }) {
    this.dir = dir + "/ffs";
    this.key = key;
    this.f_timed = Date.now();
    this.data = new Map();
    this.fs = this.dir + `/${fs}.json`;
    if (isDir(this.dir) && isFile(this.fs, "{}")) {
      const frr = readFileSync(this.fs);
      if (frr) {
        const FJSON = JSON.parse(frr.toString());
        this.data = new Map($$.O.items(FJSON));
      }
    }
  }
  async get(val: string | undefined): Promise<T | null> {
    const hdat = this.data.get(val);
    if (hdat) return hdat;
    return null;
  }
  async set(data: T) {
    if (this.key in data) {
      const frr = await fr.readFile(this.fs);
      if (frr) {
        const FJSON = JSON.parse(frr.toString());
        const dtk = data[this.key] as string;
        FJSON[dtk] = data;
        await fr.writeFile(this.fs, JSON.stringify(FJSON));
      }
      this.data.set(data[this.key], data);
    }
  }
  async delete(key: string) {
    if (await this.get(key)) {
      const frr = await fr.readFile(this.fs);
      if (frr) {
        const FJSON = JSON.parse(frr.toString());
        if (key in FJSON) {
          delete FJSON[key];
          await fr.writeFile(this.fs, JSON.stringify(FJSON));
        }
        this.data.delete(key);
      }
    }
  }
  async json() {
    const fraw = await fr.readFile(this.fs);
    const JPR = JSON.parse(fraw.toString());
    return $$.O.vals(JPR);
  }
}

const isDir = (path: string) => {
  try {
    return statSync(path).isDirectory();
  } catch (err) {
    mkdirSync(path);
    return true;
  }
};
const isFile = (path: string, data: string = "") => {
  try {
    return statSync(path).isFile();
  } catch (err) {
    writeFileSync(path, Buffer.from(data));
    return true;
  }
};

const wssClients: dict<dict<repsWSS>> = {};
export const { response, session, auth_bearer, jwt, jwt_refresh, wss } =
  (function () {
    class eStream {
      res: Http2ServerResponse | null = null;
      is: ServerHttp2Stream | null = null;
      push({
        id,
        event,
        data,
        retry,
        end,
      }: {
        id: string | number;
        event: string;
        data: string | dict<string>;
        retry?: number;
        end?: boolean;
      }) {
        const res = this.res;
        if (res) {
          if (retry) {
            res.write(`retry: ${retry}\n`);
          }
          res.write(`id: ${id}\n`);
          res.write(`event: ${event}\n`);
          if (typeof data == "object") {
            res.write("data: " + JSON.stringify(data) + "\n\n");
          } else {
            res.write("data: " + data + "\n\n");
          }
          if (end) {
            res.write(`end`);
          }
        }
      }
    }
    class response {
      status: number | null = null;
      session = new fSession().session;
      request = new request("", "", {}, "");
      _headattr: any = {};
      lang: string = "en";
      httpHeader: string[][] = [];
      stream = new eStream();
      jwt = new xjwt().jwt;
      timedJWT = new timedJWT();
      sameSite: "Lax" | null = null;
      async get(...args: any[]): Promise<any> {}
      async post(...args: any[]): Promise<any> {}
      async put(...args: any[]): Promise<any> {}
      async patch(...args: any[]): Promise<any> {}
      async error(...args: any[]): Promise<any> {}
      async eventStream(...args: any[]): Promise<any> {}
      set head(heads: headP) {
        $$.O.items(heads).forEach(([k, v]) => {
          if (k == "title" || k == "base") {
            this._headattr[k] = v;
          } else {
            if (!(k in this._headattr)) {
              this._headattr[k] = v;
            } else {
              this._headattr[k].push(...v);
            }
          }
        });
      }
      setHTTPHeader(headr: string[]) {
        this.httpHeader.push(headr);
      }
      setCookie(
        key: string,
        val: string,
        path: string = "/",
        days: number = 31,
      ) {
        const cd = cookieDump(key, val, {
          expires: timeDelta(days),
          path: path,
          httpOnly: true,
          sameSite: "Strict",
        });
        this.setHTTPHeader(["Set-Cookie", cd]);
      }
      deleteCookie(key: string) {
        this.setCookie(key, "", "/", 0);
      }
      get wssClients() {
        return $$.O.keys(wssClients);
      }
    }
    function session(...itm: any[]) {
      const [a, b, c] = itm;

      const OG: () => any = c.value;

      c.value = async function (args: any = {}) {
        if ("session" in args && args.session) {
          const nms: any = [args];
          return OG.apply(this, nms);
        }
        return null;
      };
      return c;
    }
    function jwt(...itm: any[]) {
      const [a, b, c] = itm;
      const OG: () => any = c.value;
      c.value = async function (args: any = {}) {
        if ("jwt" in args) {
          const nms: any = [args];
          return OG.apply(this, nms);
        }
        return null;
      };
      return c;
    }
    function jwt_refresh(...itm: any[]) {
      const [a, b, c] = itm;
      const OG: () => any = c.value;
      c.value = async function (args: any = {}) {
        if ("jwt_refresh" in args) {
          const nms: any = [args];
          return OG.apply(this, nms);
        }
        return null;
      };
      return c;
    }
    class wss {
      session = new fSession().session;
      socket: null | WebSocket;
      request = new request("", "", {}, "");
      data: dict<V> = {};
      wid: string = "";
      wssURL: string = "";
      role: "maker" | "joiner" | "alien" = "joiner";
      constructor(...args: any[]) {
        this.socket = null;
      }
      async init(...args: any[]) {}
      async onConnect(message?: string) {
        this.send = "connected!";
      }
      async onMessage(message?: string) {}
      async onClose(message?: string) {}
      set send(message: string | object) {
        if (this.socket) {
          if (typeof message == "object") {
            this.socket.send(JSON.stringify(message));
          } else {
            this.socket.send(message);
          }
        }
      }
      set broadcast(message: string | object) {
        if (this.socket) {
          let mess: string = "";
          if (typeof message == "object") {
            mess = JSON.stringify(message);
          } else {
            mess = message;
          }
          $$.O.items(wssClients[this.wssURL]).forEach(([mid, wsx]) => {
            wsx.WSS.onMessage(mess);
          });
        }
      }
      get close() {
        if (this.socket) this.socket.close();
        return;
      }
    }

    // auth_bearer
    // -- Google Auth
    return { response, session, auth_bearer: jwt, jwt, jwt_refresh, wss };
  })();
export const { Aeri, foresight } = (function () {
  class __ {
    static makeID(length: number) {
      let result = "";
      const characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      const charactersLength = characters.length;
      let counter = 0;
      while (counter < length) {
        result += characters.charAt(
          Math.floor(Math.random() * charactersLength),
        );
        counter += 1;
      }
      return result;
    }
    static parseURL(url: string) {
      const parsed: string[] = [];
      const args: string[] = [];

      let murl = url;
      let qurl = "";
      const splitd = url.match(/(?<=\?)[^/].*=?(?=\/|$)/g);
      if (splitd?.[0]) {
        qurl = splitd?.[0];
        murl = url.slice(0, url.indexOf(qurl) - 1);
      }

      const prsed = murl.match(/(?<=\/)[^/].*?(?=\/|$)/g) ?? ["/"];
      const query: dict<string> = {};

      prsed?.forEach((pr) => {
        if (pr.indexOf("<") >= 0) {
          const tgp = pr.match(/(?<=<)[^/].*?(?=>|$)/g);
          if (tgp?.length) {
            const [_type, _arg] = tgp[0].split(":");
            parsed.push(_type);
            args.push(_arg);
          }
        } else {
          parsed.push(pr);
        }
      });

      if (url.slice(-1) == "/" && url.length > 1) {
        parsed.push("/");
      }

      if (qurl) {
        const _qq = decodeURIComponent(qurl);
        const _qstr = _qq.split("&");
        _qstr.forEach((qs) => {
          const [ak, av] = qs.split(/\=(.*)/, 2);
          query[ak] = av;
        });
      }

      return { parsed, args, query };
    }
    static is_number(value: any) {
      return !isNaN(parseFloat(value)) && isFinite(value);
    }
    static type(wrd: string, isFinal: boolean = false) {
      let lit_type: [any, string] | [] = [];
      if (this.is_number(wrd)) {
        const nm = Number(wrd);
        if (Number.isInteger(nm)) {
          lit_type = [nm, "int"];
        } else {
          lit_type = [nm, "float"];
        }
      } else {
        if (isFinal && wrd.indexOf(".") >= 1) {
          lit_type = [wrd, "file"];
        } else {
          let tps = "-";
          if (wrd.length == 36) {
            const dashy = wrd.match(/\-/g);
            if (dashy && dashy.length == 4) {
              tps = "uuid";
            } else {
              tps = "string";
            }
          } else if (wrd != "/") {
            tps = "string";
          }
          lit_type = [wrd, tps];
        }
      }

      return lit_type;
    }
    static args(params: string[], vals: string[]) {
      return params.reduce<dict<string>>((k, v, i) => {
        k[v] = vals[i];
        return k;
      }, {});
    }
    static mimeType(fileStr: string) {
      return lookup(fileStr) || "application/octet-stream";
    }
    static headAttr(v?: headP) {
      const XHD: string[] = [];
      if (v) {
        $$.O.items(v).forEach(([kk, vv]) => {
          if (typeof vv == "string") {
            XHD.push(`<${kk}>${vv}</${kk}>`);
          } else if (Array.isArray(vv)) {
            const rdced = vv.reduce((prv, vl) => {
              let ender = "";
              if (kk == "script") {
                let scrptbdy = "";
                if ("importmap" in vl) {
                  vl["type"] = "importmap";
                  scrptbdy = JSON.stringify(vl.importmap);
                  delete vl.importmap;
                  //
                } else if ("body" in vl) {
                  scrptbdy = vl.body;
                  delete vl.body;
                }
                ender = `${scrptbdy}</${kk}>`;
              }
              prv.push(`<${kk}${__.attr(vl)}>${ender}`);
              return prv;
            }, []);
            XHD.push(...rdced);
          }
        });
      }
      return XHD;
    }
    static attr(attr: dict<string>) {
      const _attr: string[] = [""];
      $$.O.items(attr).forEach(([k, v]) => {
        let to_attr: string = "";
        if (typeof v == "boolean") {
          to_attr = k;
        } else {
          to_attr = `${k}="${v}"`;
        }
        _attr.push(to_attr);
      });
      return _attr.join(" ");
    }
  }
  class foresight {
    rpath: string;
    data: string;
    head: string;
    constructor(rpath: string, data: any = {}) {
      this.rpath = rpath;
      this.data = JSON.stringify(data);
      this.head = "";
    }

    _head() {
      let fs = `<script type="module">`;
      fs += `\nimport x from "${this.rpath}";`;
      fs += `\nx.dom(${this.data});`;
      fs += `\n</script>`;

      return fs;
    }
  }
  class htmlx {
    heads: string[];
    lang: string;
    constructor(heads: any[] = [], lang: string = "en", _session: any) {
      this.heads = this._head(heads);
      this.lang = lang;
    }
    _head(heads: headP[]) {
      const [_h1] = heads;
      return [...__.headAttr(_h1)];
    }
    html(ctx: string | foresight | any = ""): string {
      let bscr = "";
      let _ctx = "";
      if (ctx instanceof foresight) {
        bscr = ctx._head();
      } else {
        _ctx = ctx;
      }
      const _id = $$.makeID(5);
      let fin = "<!DOCTYPE html>";
      fin += `\n<html lang="${this.lang}">`;
      fin += "\n<head>\n";
      fin += this.heads.join("\n");
      fin += "\n" + bscr;
      fin += "\n</head>";
      fin += `\n<body id="${_id}">\n`;
      _ctx && (fin += "\n" + _ctx);
      fin += "\n</body>";
      fin += "\n</html>";
      return fin;
    }
  }
  class fURL {
    url: string;
    rurl: string;
    purl: string[];
    x_args: string[] = [];
    y_args: string[] = [];
    f: typeof response | typeof wss | null;
    isFile: boolean;
    mtype: string;
    broadcastWSS = false;
    maxClient: number | null = null;
    withSession: boolean = false;
    constructor(
      url: string,
      cname: typeof response | typeof wss | null = null,
      isFile: boolean = false,
      session: boolean = false,
    ) {
      this.url = url;
      this.rurl = url;
      const { parsed, args } = __.parseURL(url);
      this.purl = parsed;
      this.x_args = args;
      this.f = cname;
      this.isFile = isFile;
      this.mtype = "";
      if (isFile) {
        this.withSession = session;
        this.mtype = __.mimeType(url);
      }
    }
  }
  class zURL {
    id: string;
    Routes: dict<any> = {};
    FRoutes: dict<any> = {};
    WRoutes: dict<any> = {};
    Folders: string[] = [];
    constructor(id: string) {
      this.id = id;
    }
    set z(furl: fURL) {
      let RT = furl.isFile ? this.FRoutes : this.Routes;
      const RID = this.id;
      furl.purl.forEach((v, i) => {
        if (!(v in RT)) {
          RT[v] = {};
        }
        RT = RT[v];
        if (furl.purl.length - 1 == i) {
          if (!(RID in RT)) {
            RT[RID] = furl;
          } else {
            if (!furl.isFile) {
              throw `URL: ${furl.url} already used in class < ${RT[RID].f.name} >`;
            }
          }
        }
      });
    }
    set wss(furl: fURL) {
      let RT = this.WRoutes;
      const RID = this.id;
      furl.purl.forEach((v, i) => {
        if (!(v in RT)) {
          RT[v] = {};
        }
        RT = RT[v];
        if (furl.purl.length - 1 == i) {
          if (!(RID in RT)) {
            RT[RID] = furl;
          } else {
            if (!furl.isFile) {
              throw `URL: ${furl.url} already used in class < ${RT[RID].f.name} >`;
            }
          }
        }
      });
    }
    set folder(paths: string) {
      paths = strip(paths, ".");
      paths = strip(paths, "/");
      this.Folders.push(paths);
    }
    get(parsed: string[], wss: boolean = false, xurl: string = ""): rsx {
      let isFile: boolean = false;
      let ppop = parsed.slice().pop();
      if (ppop) {
        isFile = __.type(ppop, true).pop() == "file";
      }
      const lenn = parsed.length;
      const args: string[] = [];
      let routeUpdate: number = 0;
      let RT = isFile ? this.FRoutes : this.Routes;
      if (wss) {
        RT = this.WRoutes;
      }
      parsed.forEach((v, i) => {
        const TP = __.type(v, lenn - 1 == i ? true : false);
        for (let i = 0; i < TP.length; i++) {
          let TPX = TP[i];
          if (TPX in RT) {
            RT = RT[TPX];
            routeUpdate += 1;
            break;
          } else {
            if (TPX != "/" && TPX != "-") {
              args.push(TPX);
            }
          }
        }
      });

      if (routeUpdate != lenn) {
        RT = {};
      }
      if (this.id in RT) {
        const RTT: fURL = RT[this.id];
        RTT.y_args = args;
        return new rsx(RTT, 200);
      }
      if (isFile) {
        const pp = parsed.slice(0, -1).join("/");
        const inFol = this.Folders.some((ff) => {
          return pp.startsWith(ff);
        });
        if (inFol) {
          return new rsx(new fURL("." + xurl, null, true), 200);
        }
      }
      return new rsx();
    }
  }
  // --------------------
  const rBytes = new RegExp(/(\d+)(\d*)/, "m");
  class rsx {
    furl: fURL | null;
    status: number;
    headers: string[][] = [];
    constructor(
      furl: fURL | null = null,
      status: number = 404,
      headers: string[][] = [],
    ) {
      this.furl = furl;
      this.status = status;
      if (headers) {
        this.headers.push(...headers);
      }
    }
    setTL(returns: string) {
      this.headers.push(...[["Content-Type", returns]]);
    }
    setHeader(name: string, val: string) {
      this.headers.push([name, val]);
    }
    async file(url: string, mtype: string, range?: string) {
      try {
        const fsx = await fr.readFile(url);
        if (fsx) {
          this.setHeader("Cache-Control", "max-age=31536000");
          if (range) {
            const fssize = fsx.byteLength;
            const rg = rBytes.exec(range);
            if (rg) {
              let byte1 = 0,
                byte2 = 0,
                length = 0;
              if (rg[0]) byte1 = Number(rg[0]);
              if (rg[1]) byte2 = Number(rg[1]);
              length = fssize - byte1;
              if (byte2) length = byte2 + 1 - byte1;
              if (!byte2) byte2 = fssize;
              this.setHeader(
                "Content-Range",
                `bytes ${byte1}-${byte1 + length - 1}/${fssize}`,
              );

              this.setTL(mtype);
              return fsx.subarray(byte1, byte2);
            }
          } else {
            this.setTL(mtype);
            return fsx;
          }
        }
      } catch (err) {
        $$.p = url + " file not found";
      }
      return null;
    }
    async __reqs(app: Aeri, req: request) {
      let sid = "";
      let jwtv = "";
      let refreshjwt: any | null = null;
      if ("session" in req.cookies) {
        // Include the samesite
        sid = req.cookies.session;
      }
      if (req.auth) {
        jwtv = req.auth;
      }
      if ("refresh_token" in req.urlEncoded) {
        refreshjwt = await app.jwtsession.openSession(
          req.urlEncoded.refresh_token,
        );
      }

      return { sid, jwtv, refreshjwt };
    }
    async wss(req: request, _wss: WebSocket, app: Aeri) {
      if (this.furl) {
        const { f, x_args, y_args, rurl, broadcastWSS, maxClient } = this.furl;
        if (f) {
          const z_args = __.args(x_args, y_args);
          const FS: any = new f(z_args);
          // ------
          FS.socket = _wss;
          FS.wssURL = rurl;
          FS.request = req;
          const { sid } = await this.__reqs(app, req);
          if (sid) {
            FS.session = await app.XS.openSession(sid);
          }

          // --------
          if (typeof FS["init"] == "function") await FS.init(z_args);

          const wid = FS.wid ? FS.wid : __.makeID(10);
          FS.wid = wid;
          let allowConnect = false;
          if (broadcastWSS) {
            if (!(rurl in wssClients)) {
              wssClients[rurl] = {};
            }
            //]
            const wslen = $$.O.keys(wssClients[rurl]).length;
            if (maxClient !== null) {
              if (wslen < maxClient) {
                if (!(wid in wssClients[rurl])) {
                  FS.role = wslen == 0 ? "maker" : "joiner";
                  wssClients[rurl][wid] = {
                    WSS: FS,
                    role: FS.role,
                  };
                  allowConnect = true;
                } else {
                }
              } else {
                await FS.onClose("maxClient");
                _wss.close();
              }
            } else {
              if (!(wid in wssClients[rurl])) {
                FS.role = wslen == 0 ? "maker" : "joiner";
                wssClients[rurl][wid] = {
                  WSS: FS,
                  role: FS.role,
                };
                allowConnect = true;
              } else {
              }
            }
          }
          // ------------------
          // On connection allowed
          if (allowConnect) {
            await FS.onConnect();
            //
            _wss.on("message", async (message) => {
              const msg = message.toString("utf-8");
              if (broadcastWSS) {
                $$.O.items(wssClients[rurl]).forEach(async ([mid, wsx]) => {
                  if (mid != wid) {
                    await wsx.WSS.onMessage(msg);
                  }
                });
              } else {
                await FS.onMessage(msg);
              }
            });
            _wss.on("close", async () => {
              if (broadcastWSS) {
                const cwid = wssClients[rurl][wid];
                const crurlen = $$.O.keys(wssClients[rurl]);
                if (crurlen.length == 0) {
                  delete wssClients[rurl];
                } else if (crurlen.length > 1 && cwid.role == "maker") {
                  const newMaker = crurlen[1];
                  wssClients[rurl][newMaker].role = "maker";
                  wssClients[rurl][newMaker].WSS.role = "maker";
                }
                delete wssClients[rurl][wid];
              }
              await FS.onClose();
              _wss.close();
            });
          }
        }
      }
    }
    async eventStream(app: Aeri, req: request, res: Http2ServerResponse) {
      if (this.furl) {
        const { f, url, x_args, y_args } = this.furl;
        if (f) {
          const z_args = __.args(x_args, y_args);
          const FS: any = new f();
          if (typeof FS["eventStream"] == "function") {
            FS.stream.res = res;
            FS.stream.is = res.stream;

            let sid = "";
            if ("session" in req.cookies) {
              sid = req.cookies.session;
            }
            const sesh = await app.XS.openSession(sid);
            if (!sesh.new) {
              Object.assign(z_args, { session: true });
            }
            await FS["eventStream"](z_args);
          }
        }
      }
    }
    async response(
      method: string = "get",
      app: Aeri,
      req: request,
    ): Promise<string | Buffer | null> {
      if (this.furl) {
        const { f, url, x_args, y_args, isFile, mtype, withSession } =
          this.furl;
        if (isFile) {
          if (withSession) {
            const { sid } = await this.__reqs(app, req);
            const sesh = await app.XS.openSession(sid);
            if (sesh.new) {
              this.status = 403;
              return null;
            }
          }
          const byteR = req.headers.range;
          return await this.file(url, mtype, byteR);
        } else if (f) {
          let ipCAN = true;
          if (app.ip.LIMIT && req.ip) {
            ipCAN = app.ipLimiter.check(req.ip);
          }
          if (!ipCAN) {
            this.status = 429;
            return null;
          }
          const FS: any = new f();
          if (typeof FS[method] == "function") {
            const z_args = __.args(x_args, y_args);
            const { sid, jwtv, refreshjwt } = await this.__reqs(app, req);
            const a_args: dict<boolean> = {};
            const sjwt = app._jwt.open(jwtv, { minutes: 30 });
            const sesh = await app.XS.openSession(sid);
            FS.timedJWT._xjwt = app._jwt;
            FS._headattr = app._headattr;

            if (!sjwt.new) {
              a_args["jwt"] = true;
              a_args["jwt_refresh"] = true;
            }
            if (sesh && !sesh.new) {
              a_args["session"] = true;
            }
            if ($$.O.keys(a_args).length) {
              Object.assign(z_args, a_args);
            }

            Object.assign(FS, {
              request: req,
              session: sesh,
              jwt: sjwt,
            });

            // ------------------

            let CTX = await FS[method](z_args);
            this.headers.push(...(FS.httpHeader as string[][]));

            if (FS.session) {
              if (FS.session.modified) {
                await app.XS.saveSession(FS.session, this, false, FS.sameSite);
              } else if (sesh && sid && sesh.new) {
                app.XS.deleteBrowserSession(FS.session, this);
              }
            }

            if (CTX == null) {
              if (method == "get") {
                this.status = 401;
                return null;
              } else if (method == "post") {
                this.status = 404;
                if (jwtv && sjwt.new) {
                  this.status = 401;
                }
                if (FS.status) this.status = FS.status;
                return null;
              }
            } else if (CTX instanceof rsx) {
              this.status = CTX.status;
              this.headers.push(...CTX.headers);
              // ----
              return null;
            }

            // ---------------
            if (method == "get") {
              const htx = new htmlx([FS._headattr], FS.lang, sesh).html(CTX);
              this.setTL("text/html");
              return htx;
            } else {
              let STJ = "";
              let _type = "text/plain";
              if (FS.status) this.status = FS.status;
              //
              if (CTX instanceof xjwt) {
                _type = "application/json";
                if (refreshjwt) {
                  const atk = refreshjwt.data.access_token;
                  if (jwtv == atk) {
                    if (app._jwt.verify(atk, { days: 5 })) {
                      const fjwt = app._jwt.save(refreshjwt);
                      refreshjwt.access_token = fjwt;
                      await app.jwtsession.saveSession(refreshjwt);
                      STJ = JSON.stringify({
                        access_token: fjwt,
                        refresh_token: refreshjwt.sid,
                        status: "ok",
                      });
                    } else {
                      await app.jwtsession.saveSession(refreshjwt, null, true);
                      STJ = JSON.stringify({
                        error: "expired or invald refresh_token provided",
                      });
                    }
                  } else {
                    STJ = JSON.stringify({
                      error: "access_token !== refresh_token",
                    });
                  }
                  // ---------------
                } else if (FS.jwt.modified && FS.jwt.new) {
                  const fjwt = app._jwt.save(FS.jwt);
                  const axjwt = FS.jwt.sid;
                  FS.jwt.access_token = fjwt;
                  await app.jwtsession.saveSession(FS.jwt);
                  STJ = JSON.stringify({
                    access_token: fjwt,
                    refresh_token: axjwt,
                    status: "ok",
                  });
                }
              } else if (typeof CTX == "object") {
                _type = "application/json";
                STJ = JSON.stringify(CTX);
              } else {
                STJ = String(CTX);
              }
              this.setTL(_type);
              return STJ;
            }
          } else {
            this.status = 405;
            return null;
          }
        }
      }
      return null;
    }
  }
  class runner {
    app: Aeri;
    Z: zURL;
    constructor(app: Aeri) {
      this.Z = app.Z;
      this.app = app;
    }
    async wss(req: request, soc: WebSocket) {
      const { parsed, query } = __.parseURL(req.url);
      req.urlQuery = query;
      const reqwss = req.wss;
      if (soc && reqwss) {
        const ZX = this.Z.get(parsed, true);
        if (ZX.furl) {
          ZX.furl.rurl = req.url;
          await ZX.wss(req, soc, this.app);
        } else {
          soc.close();
        }
      }
    }
    async render(req: request, res?: Http2ServerResponse) {
      const { parsed, query } = __.parseURL(req.url);
      req.urlQuery = query;
      const ZX = this.Z.get(parsed, false, req.url);

      if (res && req.isEventStream) {
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
        });
        await ZX.eventStream(this.app, req, res);
      } else {
        if (res) {
          const ctx = await ZX.response(req.method, this.app, req);
          const errs = () => {
            res.statusCode = ZX.status;
            res.end();
          };
          if (ZX.headers && ZX.headers.length) {
            const send = (buffed: Buffer, enc: string) => {
              res.setHeader("Content-Length", buffed.byteLength);
              res.setHeader("Content-Encoding", enc);
              res.end(buffed);
            };
            ZX.headers.forEach(([k, v]) => {
              res.setHeader(k, v);
            });
            res.statusCode = ZX.status;
            if (req.encoding.includes("br")) {
              zlib.brotliCompress(ctx || "", (err, buff) => {
                if (err) return errs();
                send(buff, "br");
              });
            } else {
              zlib.deflate(ctx || "", (err, buff) => {
                if (err) return errs();
                send(buff, "deflate");
              });
            }
          } else {
            errs();
          }
        } else {
          const ctx = await ZX.response(req.method, this.app, req);
          if (ctx) {
            await fr.writeFile("index.html", ctx);
            return ctx;
          }
        }
      }
    }
  }
  // --------------------

  // IP LIMITER
  class ipLimit extends tempV<{ ip: string; request: number; time: number }> {
    seconds: number;
    rate: number;
    constructor({ seconds = 60, rate = 100 }) {
      super({ key: "ip" });
      this.seconds = seconds;
      this.rate = rate;
    }
    check(ip: string) {
      if (!this.data.has(ip)) {
        this.reset(ip);
      }
      let tg = this.get(ip)!;
      if (tg.time <= Date.now()) {
        tg = this.reset(ip);
      }
      tg.request += 1;
      //check the request rate
      if (tg.request > this.rate) {
        return false;
      }
      return true;
    }
    reset(ip: string) {
      const ndate = new Date();
      ndate.setSeconds(ndate.getSeconds() + this.seconds);
      const data = { ip: ip, request: 0, time: ndate.getTime() };
      this.data.set(ip, data);
      return data;
    }
  }

  class _c {
    secret_key: string = $$.makeID(10);
    XS: serverInterface;
    dir = "";
    constructor(dir: string, env_path: string = "") {
      const PRIV = dir + "/private/";
      isDir(PRIV);
      if (!env_path) {
        isFile(PRIV + ".env");
      }
      require("dotenv").config({
        path: env_path ? env_path : PRIV + ".env",
      });
      //
      const sk = process.env.SECRET;
      if (sk) this.secret_key = sk;
      this.session.STORAGE = PRIV + ".sessions";
      this.session.JWT_STORAGE = PRIV + ".jwtsessions";
      this.XS = new reSession(this as any, this.session, this.secret_key).get(
        this.session.INTERFACE,
      );
      //
    }
    init() {
      if (this.postgresClient) {
        this.sessionInterface = "postgres";
      }

      this.XS = new reSession(this as any, this.session, this.secret_key).get(
        this.session.INTERFACE,
      );
    }
    config = {
      APPLICATION_ROOT: "/",
    };

    session = {
      COOKIE_NAME: "session",
      COOKIE_DOMAIN: "127.0.0.1",
      COOKIE_PATH: null,
      COOKIE_HTTPONLY: true,
      COOKIE_SECURE: true,
      REFRESH_EACH_REQUEST: false,
      COOKIE_SAMESITE: "Strict",
      KEY_PREFIX: "session:",
      PERMANENT: true,
      USE_SIGNER: false,
      ID_LENGTH: 32,
      FILE_THRESHOLD: 500,
      LIFETIME: 31,
      MAX_COOKIE_SIZE: 4093,
      INTERFACE: "fs",
      STORAGE: ".sessions",
      JWT_STORAGE: ".jwtsessions",
    };
    supabase: sbase = {
      CLIENT: null,
      TABLE: "",
    };
    postgresClient: Client | null = null;
    google = {
      id: "",
      secret: "",
    };
    set sessionInterface(intrfce: "supabase" | "postgres") {
      this.session.INTERFACE = intrfce;
    }
    get jwtsession() {
      return new reSession(this as any, this.session, this.secret_key).get(
        "jwt",
      );
    }

    ip = {
      LIMIT: false,
      RATE: 100,
      SECONDS: 60,
    };
    ipLimiter = new ipLimit({ rate: this.ip.RATE, seconds: this.ip.SECONDS });
  }
  class Aeri extends _c {
    _headattr: any = {};
    Z: zURL;
    _jwt: _jwt;
    constructor(dir: string, env_path: string = "") {
      super(dir, env_path);
      this.dir = "./" + dir.split("/").slice(-1)[0];
      this.Z = new zURL(__.makeID(15));
      this._jwt = new _jwt(this.secret_key);
    }
    url(url: string) {
      const ins = (f: typeof response) => {
        this.Z.z = new fURL(url, f, false, false);
        return f;
      };
      return ins;
    }
    wss(
      url: string,
      opts: { broadcast: boolean; maxClient?: number } = {
        broadcast: false,
      },
    ) {
      const ins = (f: typeof wss) => {
        const _fr = new fURL(url, f);
        _fr.broadcastWSS = opts.broadcast;
        if (opts.maxClient) {
          _fr.maxClient = opts.maxClient;
        }
        this.Z.wss = _fr;
        return f;
      };
      return ins;
    }
    file(furl: string, session: boolean = false) {
      this.Z.z = new fURL(furl, null, true, session);
      return furl;
    }
    folder(path: string) {
      this.Z.folder = path;
    }
    folders(paths: string[]) {
      paths.forEach((pt) => {
        this.Z.folder = pt;
      });
    }
    redirect(url: string) {
      return new rsx(null, 302, [["Location", url]]);
    }
    // ------------------
    async run({
      url = "",
      method = "GET",
      hostname = "localhost",
      port = 3000,
      options = {},
    }) {
      // -------------------------------------------
      this.init();
      // const { url, method, hostname, port, options } = opt;
      let host = hostname ?? "localhost";
      const RN = new runner(this);
      if (url) {
        const Request = new request(url.trim(), method!, {}, "");
        await RN.render(Request);
      } else {
        // =============
        const sk = process.env.SSL_KEY;
        const sc = process.env.SSL_CERT;

        if (sk && sc) {
          const _options = {
            key: await fr.readFile(sk),
            cert: await fr.readFile(sc),
            allowHTTP1: true,
            ...options,
          };

          const SRVR = createSecureServer(_options, async function (req, res) {
            // -------------------
            if (req.url && req.method) {
              const sk =
                req.headers["x-forwarded-for"] || req.socket.remoteAddress;

              const Request = new request(req.url, req.method, req.headers, sk);
              // -------------------------------------
              if (["POST", "PUT"].includes(req.method)) {
                let buffers: Buffer[] = [];
                req.on("data", (chunk) => {
                  buffers.push(Buffer.from(chunk));
                });
                //----------------------
                req.on("end", async () => {
                  Request.__parseBuffer(Buffer.concat(buffers));
                  await RN.render(Request, res);
                });
              } else {
                if (req.headers.upgrade == "websocket") {
                } else {
                  await RN.render(Request, res);
                }
              }
            }
          });

          new Server({
            server: SRVR as any,
          }).on("connection", async function (ws, req) {
            if (
              req.url &&
              req.method == "GET" &&
              req.headers.upgrade == "websocket"
            ) {
              const Request = new request(
                req.url,
                req.method,
                req.headers,
                req.headers["x-forwarded-for"] || req.socket.remoteAddress,
              );
              await RN.wss(Request, ws);
            } else {
              ws.close();
            }
          });

          SRVR.listen(port, host, () => {
            let sl = `Running ${host}@${port}`;
            console.log(sl);
          });

          if (this.session.INTERFACE == "postgres") {
            await this.postgresClient?.connect();
            const query: QueryConfig = {
              text: `CREATE TABLE IF NOT EXISTS session (
                      sid TEXT,
                      data TEXT,
                      expiration TEXT
          );`,
            };
            await this.postgresClient?.query(query);
            $$.process(async () => {
              await this.postgresClient?.end();
              $$.p = "postgres db connection closed..";
            });
          }
          //
        } else {
          throw Error("SSL_KEY & SSL_CERT path missing in private/.env file");
        }
      }
    }
    set head(heads: headP) {
      $$.O.items(heads).forEach(([k, v]) => {
        if (k == "title" || k == "base") {
          this._headattr[k] = v;
        } else {
          if (!(k in this._headattr)) {
            this._headattr[k] = v;
          } else {
            this._headattr[k].push(...v);
          }
        }
      });
    }
  }

  return { Aeri, foresight };
})();

export const { GOAT } = (function () {
  class G_USER {
    verified = false;
    unique_id = "";
    email = "";
    picture = "";
    given_name = "";
    family_name = "";
    locale = "en";
    access_token = "";
    constructor(user: dict<string>) {
      if (user) {
        const {
          email_verified,
          sub,
          email,
          picture,
          given_name,
          family_name,
          locale,
          access_token,
        } = user;
        this.verified = Boolean(email_verified);
        this.unique_id = sub;
        this.email = email;
        this.picture = picture;
        this.given_name = given_name;
        this.family_name = family_name;
        this.locale = locale;
        this.access_token = access_token;
      }
    }
  }
  class GOAT {
    discovery = "https://accounts.google.com/.well-known/openid-configuration";
    id: string;
    secret: string;
    cfg: dict<any> | null;
    constructor() {
      const { GOOGLE_ID, GOOGLE_SECRET } = process.env;
      this.id = GOOGLE_ID ?? "";
      this.secret = GOOGLE_SECRET ?? "";
      if (!GOOGLE_ID) {
        throw Error("GOOGLE_ID / GOOGLE_SECRET not found un .env");
      }
      this.cfg = null;
    }
    get cfgs() {
      return fetch(this.discovery)
        .then((resp) => {
          return resp.json();
        })
        .then((data) => {
          return data;
        });
    }

    async requestURI(baseURL: string, callbackURL: string = "/callback") {
      const bcall =
        baseURL.endsWith("/") && callbackURL.startsWith("/")
          ? baseURL + callbackURL.slice(1)
          : baseURL + callbackURL;

      const auth_end = "https://accounts.google.com/o/oauth2/v2/auth";
      const xurl = [
        auth_end,
        "?response_type=code&",
        "client_id=",
        encodeURIComponent(this.id),
        "&redirect_uri=",
        encodeURIComponent(`${bcall}`),
        "&scope=openid+email+profile",
        "&state=" + encodeURIComponent($$.makeID2(25)),
      ];

      return xurl.join("");
    }

    async getToken(baseURL: string, code: string): Promise<string> {
      if (!this.cfg) {
        const xcf = await this.cfgs;
        this.cfg = xcf;
      }
      const { token_endpoint } = this.cfg!;
      const data = new URLSearchParams({
        grant_type: "authorization_code", // Custom parameter name-value pairs
        client_id: this.id,
        client_secret: this.secret,
        code: code,
        redirect_uri: baseURL,
      });
      //

      return await fetch(token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: data,
      })
        .then((resp) => {
          return resp.json();
        })
        .then((datas) => datas.access_token);
    }
    async userInfo(access_token: string) {
      if (!this.cfg) {
        const xcf = await this.cfgs;
        this.cfg = xcf;
      }
      const { userinfo_endpoint } = this.cfg!;

      let userinf: dict<any> = {};
      await fetch(userinfo_endpoint, {
        headers: { Authorization: `Bearer ${access_token}` },
      })
        .then((resp) => resp.json())
        .then((datas) => {
          userinf = datas;
        });

      Object.assign(userinf, { access_token });
      return new G_USER(userinf);
    }
  }
  return { GOAT };
})();

interface fs {
  [key: string]: string | undefined | boolean | number;
}
interface bs {
  f_timed?: number;
  [key: string]: string | undefined | boolean | number;
}

/**
 * IDEAS
 * Scheduling software
 * Dashboard
 * Japanese learning
 */
