import { Http2ServerResponse, createSecureServer } from "node:http2";
import zlib from "node:zlib";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import {
  reSession,
  fSession,
  cookieDump,
  timeDelta,
  _jwt,
  xjwt,
} from "./response";
import { request, strip } from "./request";
// -----------
import { Server, WebSocket } from "ws";
import { lookup } from "mime-types";

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
 * 10. Fix the byte-range request for files - Done
 */

// Types -----------------------
interface dict<T> {
  [Key: string]: T;
}
type V = string | number | boolean;
type meta<T> = {
  charset?: T;
  content?: T;
  "http-equiv"?: T;
  name?: T;
  media?: T;
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
type respwss = InstanceType<typeof wss>;

// ----------------------------

export class $$ {
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
}
export const { response, session, jwt, jwt_refresh, wss } = (function () {
  class eStream {
    res: Http2ServerResponse | null = null;
    push({
      id,
      event,
      data,
      retry,
    }: {
      id: string | number;
      event: string;
      data: string | dict<string>;
      retry?: number;
    }) {
      const res = this.res;
      if (res) {
        // res.write()
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
      }
    }
  }
  class response {
    session = new fSession().session;
    request = new request("", "", {});
    _headattr: any = {};
    lang: string = "en";
    httpHeader: string[][] = [];
    eStream = new eStream();
    jwt = new xjwt().jwt;
    get(...args: any[]): any {}
    post(...args: any[]): any {}
    put(...args: any[]): any {}
    patch(...args: any[]): any {}
    error(...args: any[]): any {}
    eventStream(...args: any[]): any {}
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
    setCookie(key: string, val: string, path: string = "/", days: number = 31) {
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
  }
  function session(...itm: any[]) {
    const [a, b, c] = itm;
    const OG: () => any = c.value;
    c.value = function (args: any = {}) {
      if ("session" in args && args.session) {
        return OG.apply(this, args);
      }
      return null;
    };
    return c;
  }
  function jwt(...itm: any[]) {
    const [a, b, c] = itm;
    const OG: () => any = c.value;
    c.value = function (args: any = {}) {
      if ("jwt" in args) {
        return OG.apply(this, args);
      }
      return null;
    };
    return c;
  }
  function jwt_refresh(...itm: any[]) {
    const [a, b, c] = itm;
    const OG: () => any = c.value;
    c.value = function (args: any = {}) {
      if ("jwt_refresh" in args) {
        return OG.apply(this, args);
      }
      return null;
    };
    return c;
  }
  class wss {
    socket: null | WebSocket;
    constructor(...args: any[]) {
      this.socket = null;
    }
    onConnect() {
      this.send = "connected!";
    }
    onMessage(message?: string) {}
    onClose() {}
    set send(message: string | object) {
      if (this.socket) {
        if (typeof message == "object") {
          this.socket.send(JSON.stringify(message));
        } else {
          this.socket.send(message);
        }
      }
    }
    get close() {
      if (this.socket) this.socket.close();
      return;
    }
  }

  // -- Google Auth

  return { response, session, jwt, jwt_refresh, wss };
})();
export const { Aeri, render } = (function () {
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
      const prsed = url.match(/(?<=\/)[^/].*?(?=\/|$)/g) ?? ["/"];
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

      const lval = parsed.pop();
      if (lval) {
        if (lval?.indexOf("?") > 0) {
          const [xurl, qstr] = lval.split(/\?(.*)/, 2);
          const _qq = decodeURIComponent(qstr);
          const _qstr = _qq.split("&");
          _qstr.forEach((qs) => {
            const [ak, av] = qs.split(/\=(.*)/, 2);
            query[ak] = av;
          });
          parsed.push(xurl);
        } else {
          parsed.push(lval);
        }
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
          if (wrd.length >= 36) {
            tps = "uuid";
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
                ender = `</${kk}>`;
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

  class render {
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
      const [_h1, _h2] = heads;
      const xxh = $$.O.items(_h1).reduce<any>((prv, [k, v]) => {
        if (k == "title" || k == "base") {
          let vl = v;
          if (k in _h2) {
            vl = _h2[k];
            delete _h2[k];
          }
          prv[k] = vl;
        } else {
          prv[k] = v;
        }
        return prv;
      }, {});
      return [...__.headAttr(_h2), ...__.headAttr(xxh)];
    }
    html(ctx: string | render | any = ""): string {
      let bscr = "";
      if (ctx instanceof render) {
        bscr = ctx._head();
      }
      const _id = $$.makeID(7);
      let fin = "<!DOCTYPE html>";
      fin += `\n<html lang="${this.lang}">`;
      fin += "\n<head>\n";
      fin += this.heads.join("\n");
      fin += "\n" + bscr;
      fin += "\n</head>";
      fin += `\n<body id="${_id}">\n`;
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
    constructor(
      url: string,
      cname: typeof response | typeof wss | null = null,
      isFile: boolean = false,
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
    file(url: string, mtype: string, range?: string) {
      try {
        const fsx = readFileSync(url);
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
              // Return the Buffered chunk
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
    wss(_wss: WebSocket) {
      const wssClients: dict<dict<respwss>> = {};
      if (this.furl) {
        const { f, x_args, y_args, rurl, broadcastWSS } = this.furl;
        if (f) {
          const z_args = __.args(x_args, y_args);
          const FS: any = new f(z_args);
          const wid = __.makeID(10);
          FS.socket = _wss;
          // --------
          if (broadcastWSS) {
            if (!(rurl in wssClients)) {
              wssClients[rurl] = {};
            }
            if (!(wid in wssClients[rurl])) {
              wssClients[rurl][wid] = FS;
            }
          }

          // ------------------
          FS.onConnect();
          _wss.on("message", (message) => {
            const msg = message.toString("utf-8");
            if (broadcastWSS) {
              $$.O.items(wssClients[rurl]).forEach(([mid, wsx]) => {
                if (mid != wid) {
                  wsx.onMessage(msg);
                }
              });
            } else {
              FS.onMessage(msg);
            }
          });
          _wss.on("close", () => {
            FS.onClose();
            if (broadcastWSS) {
              delete wssClients[rurl][wid];
            }
            _wss.close();
          });
        }
      }
    }
    eventStream(app: Aeri, req: request, res: Http2ServerResponse) {
      if (this.furl) {
        const { f, url, x_args, y_args } = this.furl;
        if (f) {
          const z_args = __.args(x_args, y_args);
          const FS: any = new f();
          if (typeof FS["eventStream"] == "function") {
            FS.eStream.res = res;
            let sid = "";
            if ("session" in req.cookies) {
              sid = req.cookies.session;
            }
            const sesh = app.xsession.openSession(sid);
            if (!sesh.new) {
              Object.assign(z_args, { session: true });
            }
            // Object.assign(z_args, { write: res.write });
            FS["eventStream"](z_args);
          }
        }
      }
    }
    __reqs(app: Aeri, req: request) {
      let sid = "";
      let jwtv = "";
      let refreshjwt: any | null = null;

      if ("session" in req.cookies) {
        sid = req.cookies.session;
      }
      if (req.auth) {
        jwtv = req.auth;
      }
      if ("refresh_token" in req.urlEncoded) {
        refreshjwt = app.jwtsession.openSession(req.urlEncoded.refresh_token);
      }

      return { sid, jwtv, refreshjwt };
    }
    async response(
      method: string = "get",
      app: Aeri,
      req: request,
    ): Promise<string | Buffer | null> {
      if (this.furl) {
        const { f, url, x_args, y_args, isFile, mtype } = this.furl;
        if (isFile) {
          const byteR = req.headers.range;
          return this.file(url, mtype, byteR);
        } else if (f) {
          const FS: any = new f();

          if (typeof FS[method] == "function") {
            const z_args = __.args(x_args, y_args);

            const { sid, jwtv, refreshjwt } = this.__reqs(app, req);

            const a_args: dict<boolean> = {};
            const sjwt = app._jwt.open(jwtv, { minutes: 30 });
            const sesh = !jwtv ? app.xsession.openSession(sid) : null;

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

            if (CTX == null) {
              if (method == "get") {
                this.status = 401;
                return null;
              } else if (method == "post") {
                let nst = { error: "not found" };
                if (jwtv && sjwt.new) {
                  nst = { error: "Authorization" };
                }
                let xnst = JSON.stringify(nst);
                this.setTL("application/json");
                return xnst;
              }
            } else if (CTX instanceof rsx) {
              this.status = CTX.status;
              this.headers = CTX.headers;
              return null;
            }

            if (FS.session.modified) {
              app.xsession.saveSession(FS.session, this);
            }

            // ---------------
            if (method == "get") {
              const htx = new htmlx(
                [FS._headattr, app._headattr],
                FS.lang,
                sesh,
              ).html(CTX);
              this.setTL("text/html");
              return htx;
            } else if (method == "post") {
              let STJ = "{}";
              if (CTX instanceof xjwt) {
                if (refreshjwt) {
                  const atk = refreshjwt.data.access_token;
                  if (jwtv == atk) {
                    if (app._jwt.verify(atk, { days: 5 })) {
                      const fjwt = app._jwt.save(refreshjwt);
                      refreshjwt.access_token = fjwt;
                      app.jwtsession.saveSession(refreshjwt);
                      STJ = JSON.stringify({
                        access_token: fjwt,
                        refresh_token: refreshjwt.sid,
                        status: "ok",
                      });
                    } else {
                      app.jwtsession.saveSession(refreshjwt, null, true);
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
                  app.jwtsession.saveSession(FS.jwt);
                  STJ = JSON.stringify({
                    access_token: fjwt,
                    refresh_token: axjwt,
                    status: "ok",
                  });
                }
              } else if (typeof CTX == "object") {
                STJ = JSON.stringify(CTX);
              }
              this.setTL("application/json");
              return STJ;
            }
          }
        }
      } else {
        // Check if file and folder
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
          ZX.wss(soc);
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
        ZX.eventStream(this.app, req, res);
      } else {
        const ctx = await ZX.response(req.method, this.app, req);
        if (res) {
          const errs = () => {
            res.statusCode = 404;
            res.end();
          };
          if (ctx) {
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
          if (ctx) {
            writeFileSync("index.html", ctx);
            return ctx;
          }
        }
      }
    }
  }
  // --------------------

  const isDir = (path: string) => {
    try {
      return statSync(path).isDirectory();
    } catch (err) {
      mkdirSync(path);
      return true;
    }
  };
  const isFile = (path: string) => {
    try {
      return statSync(path).isFile();
    } catch (err) {
      writeFileSync(path, Buffer.from(""));
      return true;
    }
  };
  class _c {
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
    }
    secret_key: string = $$.makeID(10);
    config = {
      APPLICATION_ROOT: "/",
      CSRF_TIME_LIMIT: 600,
    };
    session = {
      COOKIE_NAME: "session",
      COOKIE_DOMAIN: "127.0.0.1",
      COOKIE_PATH: null,
      COOKIE_HTTPONLY: true,
      COOKIE_SECURE: false,
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
    google = {
      id: "",
      secret: "",
    };
    set sessionInterface(intrfce: "fs" | "supabase" | "sql") {
      this.session.INTERFACE = intrfce;
    }
    get xsession() {
      return new reSession(this.session, this.secret_key).get(
        this.session.INTERFACE,
      );
    }
    get jwtsession() {
      return new reSession(this.session, this.secret_key).get("jwt");
    }
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    temp_samesite = "";
  }
  class Aeri extends _c {
    _headattr: any = {};
    Z: zURL;
    _jwt: _jwt;
    constructor(dir: string, env_path: string = "") {
      super(dir, env_path);
      this.Z = new zURL(__.makeID(15));
      this._jwt = new _jwt(this.secret_key);
    }
    url(url: string) {
      const ins = (f: typeof response) => {
        this.Z.z = new fURL(url, f);
        return f;
      };
      return ins;
    }
    wss(url: string, opts = { broadcast: false }) {
      const ins = (f: typeof wss) => {
        const _fr = new fURL(url, f);
        _fr.broadcastWSS = opts.broadcast;
        this.Z.wss = _fr;
        return f;
      };
      return ins;
    }
    file(furl: string, _session: boolean = false) {
      this.Z.z = new fURL(furl, null, true);
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
    redir(url: string) {
      return new rsx(null, 302, [["Location", url]]);
    }
    // ------------------
    async run(
      opt: {
        url?: string;
        method?: string;
        hostname?: string;
        port?: number;
        options?: any;
      } = {
        url: "",
        method: "GET",
        hostname: "localhost",
        port: 3000,
        options: {},
      },
    ) {
      // -------------------------------------------
      const { url, method, hostname, port, options } = opt;
      let host = hostname ?? "localhost";

      const RN = new runner(this);
      if (url) {
        const Request = new request(url, method!, {});
        await RN.render(Request);
      } else {
        // =============
        const sk = process.env.SSL_KEY;
        const sc = process.env.SSL_CERT;

        if (sk && sc) {
          const _options = {
            key: readFileSync(sk),
            cert: readFileSync(sc),
            allowHTTP1: true,
            ...options,
          };

          const SRVR = createSecureServer(_options, async function (req, res) {
            // -------------------
            if (req.url && req.method) {
              const Request = new request(req.url, req.method, req.headers);
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
              const Request = new request(req.url, req.method, req.headers);
              await RN.wss(Request, ws);
            } else {
              ws.close();
            }
          });

          SRVR.listen(port, host, () => {
            let sl = `Running ${host}@${port}`;
            console.log(sl);
          });
          //
        } else {
          throw Error("SSL_KEY & SSL_CERT path missing in .__/.env file");
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

  return { Aeri, render };
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
        } = user;
        this.verified = Boolean(email_verified);
        this.unique_id = sub;
        this.email = email;
        this.picture = picture;
        this.given_name = given_name;
        this.family_name = family_name;
        this.locale = locale;
      }
    }
  }
  class GOAT {
    discovery = "https://accounts.google.com/.well-known/openid-configuration";
    id: string;
    secret: string;
    cfg: dict<any> | null;
    constructor(id: string, secret: string) {
      this.id = "";
      this.secret = "";
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
      if (!this.cfg) {
        const xcf = await this.cfgs;
        this.cfg = xcf;
      }
      const { authorization_endpoint } = this.cfg!;

      const xurl = [
        authorization_endpoint,
        "?response_type=code&",
        "client_id=",
        encodeURIComponent(this.id),
        "&redirect_uri=",
        encodeURIComponent(`${baseURL}${callbackURL}`),
        "&scope=openid+email+profile",
      ];
      return xurl.join("");
    }
    async userInfo(baseURL: string, code: string) {
      if (!this.cfg) {
        const xcf = await this.cfgs;
        this.cfg = xcf;
      }
      const { token_endpoint, userinfo_endpoint } = this.cfg!;
      const data = new URLSearchParams({
        grant_type: "authorization_code", // Custom parameter name-value pairs
        client_id: this.id,
        client_secret: this.secret,
        code: code,
        redirect_uri: baseURL,
      });

      let access_tok: string | null = null;
      await fetch(token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: data,
      })
        .then((resp) => {
          return resp.json();
        })
        .then((datas) => {
          access_tok = datas.access_token;
        });

      let userinf: dict<any> = {};
      if (access_tok) {
        await fetch(userinfo_endpoint, {
          headers: { Authorization: `Bearer ${access_tok}` },
        })
          .then((resp) => resp.json())
          .then((datas) => {
            userinf = datas;
          });
      }

      return new G_USER(userinf);
    }
  }
  return { GOAT };
})();

class tg {}

/**
 * IDEAS
 * Record player.
 * Scheduling software
 * Dashboard
 * Japanese learning
 */
