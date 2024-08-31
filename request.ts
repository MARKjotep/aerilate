import { IncomingHttpHeaders } from "node:http2";
import { promises as fr } from "node:fs";
import { createHash } from "node:crypto";

export interface dict<T> {
  [Key: string]: T;
}

class _Event {}
class _Start extends _Event {
  data: Buffer = Buffer.from("");
}
class _Info extends _Event {
  name: string = "";
  headers: dict<string> = {};
}
class _File extends _Event {
  name: string = "";
  filename: string = "";
  headers: dict<string> = {};
}
class _Data extends _Event {
  data: Buffer = Buffer.from("");
  moreData: boolean = false;
}
class _Finale extends _Event {
  data: Buffer = Buffer.from("");
}
class _NeedData extends _Event {}

const state = {
  START: "START",
  INFO: "INFO",
  DATA_S: "DATA_S",
  DATA_X: "DATA_X",
  FINALE: "FINALE",
  END: "END",
};

//----------------------------
function rindex(arr: string, el: string) {
  for (let i = arr.length - 1; i >= 0; i--) {
    if (arr[i] === el) return i;
  }
  return -1; // Element not found
}
export function strip(char: string, tostrip: string) {
  if (char.startsWith(tostrip)) {
    char = char.slice(1);
  }
  if (char.endsWith(tostrip)) {
    char = char.slice(0, -1);
  }
  return char;
}
function escapeR(str: string) {
  return str.replace(/[/\-\\^$*+?.()|[\]{}]/g, "\\$&");
}
function chunkBuffer(buffer: Buffer, size: number) {
  const result: Buffer[] = [];
  for (let offset = 0; offset < buffer.length; ) {
    const end = Math.min(offset + size, buffer.length);
    result.push(buffer.subarray(offset, end));
    offset = end;
  }
  return result;
}
const LINE_BREAK = "(?:\r\n|\n|\r)";
const RE = {
  boundary: (bnd: string, brk: string = LINE_BREAK) =>
    new RegExp(
      `${brk}?--${escapeR(bnd)}(--[^\S\n\r]*${brk}?|[^\S\n\r]*${brk})`,
      "m",
    ),
  endBound: (bnd: string, brk: string = LINE_BREAK) =>
    new RegExp(
      `${brk}--${escapeR(bnd)}(--[^S\n\r]*${brk}?|[^S\n\r]*${brk})`,
      "m",
    ),
  lastNewline: (data: string) => {
    let last_nl = data.length;
    let last_cr = data.length;
    const nl = rindex(data, "\n");
    const cr = rindex(data, "\r");
    if (nl >= 0) {
      last_nl = nl;
    }
    if (cr >= 0) {
      last_cr = cr;
    }

    return Math.min(last_nl, last_cr);
  },
  blank: new RegExp("(?:\r\n\r\n|\r\r|\n\n)", "m"),
  linebreak: new RegExp(LINE_BREAK, "m"),
};
class fileStorage {
  filename = "";
  name = "";
  contentType = "";
  headers: dict<string> = {};
  stream: Buffer;
  constructor(buffed: Buffer, _file: _File) {
    this.stream = buffed;
    this.filename = _file.filename;
    this.name = _file.name;
    this.headers = _file.headers;
    if ("content-type" in this.headers) {
      this.contentType = this.headers["content-type"];
    }
  }

  async save(dir: string = "./", filename?: string) {
    await fr.writeFile(dir + (filename ?? this.filename), this.stream);
    return `${filename ?? this.filename} saved!`;
  }
  close() {}
}
class _f {
  boundary: string;
  buff: Buffer = Buffer.from("");
  complete: boolean = false;
  state: string = state.START;
  constructor(boundary: string) {
    this.boundary = boundary;
  }
  data(buffed: Buffer | null) {
    if (!buffed) {
      this.complete = true;
    } else {
      this.buff = Buffer.concat([this.buff, buffed]);
    }
  }
  pHead(data: Buffer) {
    const opts: dict<string> = {};
    let datax = data.toString("latin1");
    let dsp = datax.replaceAll(":", "=").replaceAll("\r\n", ";");
    dsp.split(";").forEach((ds) => {
      const [na, va] = ds.trim().split("=");
      opts[na] = strip(va.trim(), '"');
    });
    return opts;
  }
  pData(data: Buffer, start: boolean = false): [Buffer, number, boolean] {
    let d_start = 0;
    if (start) {
      const ry = /(?:\r\n\r\n)/m;
      const match = ry.exec(data.toString("latin1"));
      if (match) {
        d_start = match.index + match[0].length;
      }
    }

    const boundary = "--" + this.boundary;
    let d_end = 0;
    let d_inx = 0;
    let more_data = false;

    if (this.buff.toString("latin1").indexOf(boundary) == -1) {
      d_end = d_inx =
        RE.lastNewline(data.slice(d_start).toString("latin1")) + d_start;
      if (data.length - d_end > ("\n" + boundary).length) {
        d_end = d_inx = data.length;
      }
      more_data = true;
    } else {
      const mtc = RE.endBound(this.boundary).exec(data.toString("latin1"));
      if (mtc) {
        if (mtc[1].startsWith("--")) {
          this.state = state.FINALE;
        } else {
          this.state = state.INFO;
        }
        d_end = mtc.index;
        d_inx = mtc.index + mtc[0].length;
      } else {
        d_end = d_inx =
          RE.lastNewline(data.subarray(d_start).toString("latin1")) + d_start;
        more_data = true;
      }
    }

    return [data.subarray(d_start, d_end), d_inx, more_data];
  }
  get next() {
    let _data: _Event = new _NeedData();
    if (this.state == state.START) {
      const rg = RE.boundary(this.boundary).exec(this.buff.toString("latin1"));
      if (rg) {
        if (rg[1].startsWith("--")) {
          this.state = state.END;
        } else {
          this.state = state.INFO;
        }
        const xdata = this.buff.subarray(0, rg.index);
        this.buff = this.buff.subarray(rg[0].length);
        const std = new _Start();
        std.data = xdata;
        _data = std;
      }
    } else if (this.state == state.INFO) {
      const rg = RE.blank.exec(this.buff.toString("latin1"));
      if (rg) {
        // Content disposition
        const opt = this.pHead(this.buff.subarray(0, rg.index));
        this.buff = this.buff.subarray(
          Math.floor((rg.index + rg[0].length) / 2),
        );
        const name = opt.name;
        const fname = opt.filename;
        if (fname) {
          const nf = new _File();
          nf.filename = fname;
          nf.name = name;
          nf.headers = opt;
          _data = nf;
        } else {
          const nf = new _Info();
          nf.name = name;
          nf.headers = opt;
          _data = nf;
        }
        this.state = state.DATA_S;
      }
    } else if (this.state == state.DATA_S) {
      const [dat, d_inx, more_data] = this.pData(this.buff, true);
      this.buff = this.buff.subarray(d_inx);
      const dx = new _Data();
      dx.data = dat;
      dx.moreData = more_data;
      _data = dx;
      if (more_data) {
        this.state = state.DATA_X;
      }
    } else if (this.state == state.DATA_X) {
      const [dat, d_inx, more_data] = this.pData(this.buff);
      this.buff = this.buff.subarray(d_inx);
      if (dat.length || !more_data) {
        const dx = new _Data();
        dx.data = dat;
        dx.moreData = more_data;
        _data = dx;
      }
      //
    } else if (this.state == state.FINALE && this.complete) {
      const dx = new _Finale();
      dx.data = this.buff;
      _data = dx;
      this.buff = Buffer.from("");
      this.state = state.END;
    }

    return _data;
  }
}

export class request {
  headers: IncomingHttpHeaders;
  files: dict<fileStorage> = {};
  json: dict<any> = {};
  texts: dict<string> = {};
  urlEncoded: dict<string> = {};
  url: string;
  method: string;
  urlQuery: dict<string> = {};
  cookies: dict<string> = {};
  wssID = "";
  isEventStream = false;
  auth = "";
  host = "";
  path = "";
  ip: string = "";
  constructor(
    url: string,
    method: string,
    headers: IncomingHttpHeaders,
    ip: string | string[] | undefined,
  ) {
    this.headers = headers;
    this.url = url;
    this.method = method.toLowerCase();
    this.__proc;
    this.host = this.headers[":scheme"] + "://" + this.headers[":authority"];
    let _path = (this.headers[":path"] as string) ?? this.url;
    this.path = _path.split("?")[0];
    if (ip) {
      if (Array.isArray(ip)) {
        this.ip = ip[0];
      } else {
        this.ip = ip;
      }
    }
  }
  get contentType() {
    return this.headers["content-type"];
  }
  get boundary() {
    const ctype = this.contentType;
    if (ctype && ctype.indexOf("multipart/form-data") >= 0) {
      const tail = ctype.split(";", 2)[1];
      return tail.trim().split("=")[1];
    }
    return null;
  }
  get wss() {
    if ("upgrade" in this.headers) {
      const wssKey = this.headers["sec-websocket-key"]!;
      const wsVersion = this.headers["sec-websocket-version"]!;
      const cstr = wssKey + this.wssID;
      const shas = createHash("sha1");
      shas.update(cstr);
      const wsData = shas.digest("base64");

      return {
        Upgrade: "websocket",
        Connection: "Upgrade",
        "Sec-WebSocket-Accept": wsData,
        "Sec-WebSocket-Version": wsVersion,
      };
    }
    return null;
  }
  get encoding(): string[] {
    const encd = this.headers["accept-encoding"];
    if (typeof encd == "string") {
      return encd.split(", ");
    }
    return [];
  }
  __parseBuffer(buffed: Buffer) {
    const ctype = this.contentType;
    const boundary = this.boundary;

    if (ctype && buffed.byteLength) {
      if (boundary) {
        const parser = new _f(boundary);
        const FC: dict<fileStorage> = {};
        const FN: dict<string> = {};
        let cpart: _Info | _File = new _Info();
        let container: Buffer = Buffer.alloc(0);
        let cnk = 0;
        chunkBuffer(buffed, 6 * 1024 * 1024).forEach((chunk) => {
          parser.data(chunk);
          // ----------------
          let _next: any = parser.next;
          while (!(_next instanceof _Finale || _next instanceof _NeedData)) {
            if (_next instanceof _Info) {
              cpart = _next;
              container = Buffer.alloc(0);
            } else if (_next instanceof _File) {
              cpart = _next;
              container = Buffer.alloc(0);
            } else if (_next instanceof _Data) {
              container = Buffer.concat([container, _next.data]);
              if (!_next.moreData && cpart.name) {
                // Saving the container
                if (cpart instanceof _Info) {
                  FN[cpart.name] = container.toString("latin1");
                } else {
                  FC[cpart.name] = new fileStorage(
                    Buffer.from(container),
                    cpart,
                  );
                }
              }
            }
            _next = parser.next;
          }
        });

        this.files = FC;
        this.texts = FN;
      } else if (ctype.indexOf("x-www-form-urlencoded") >= 0) {
        const qr: dict<string> = {};
        const _qq = decodeURIComponent(buffed.toString());
        const _qstr = _qq.split("&");
        _qstr.forEach((qs) => {
          const [ak, av] = qs.split(/\=(.*)/, 2);
          qr[ak] = av;
        });
        this.urlEncoded = qr;
      } else if (ctype == "application/json") {
        const bs = buffed.toString();
        this.json = JSON.parse(bs);
      }
    }
  }
  get __proc() {
    const headers = this.headers;
    if ("cookie" in headers) {
      const Dcx = headers.cookie;
      if (Dcx) {
        Dcx.split(";").forEach((d) => {
          const [key, val] = d.trim().split(/=(.*)/s);
          this.cookies[key] = val;
        });
      }
    }
    if ("accept" in headers) {
      const Dc = headers.accept;
      if (Dc == "text/event-stream") {
        this.isEventStream = true;
      }
    }
    if ("authorization" in headers) {
      const auths = headers.authorization;
      if (auths) {
        const [bear, token] = auths.split(" ", 2);
        if (bear.trim() == "Bearer") {
          this.auth = token.trim();
        }
      }
    }

    return;
  }
  get baseURL(): string {
    const urls: string[] = [];
    let auth = (this.headers[":authority"] as string) ?? "localhost:3000";
    let _path = (this.headers[":path"] as string) ?? this.url;

    urls.push(
      (this.headers[":scheme"] as string) ?? "https",
      "://",
      auth,
      _path.split("?")[0],
    );

    return urls.join("");
  }
}
