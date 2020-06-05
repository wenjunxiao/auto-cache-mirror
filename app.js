const fs = require('fs');
const path = require('path');
const tls = require('tls');
const net = require('net');
const dns = require('dns');
const forge = require('node-forge');
const crypto = require('crypto');
const zlib = require("zlib");
const qs = require('querystring');
const urlParse = require('url').parse;
const {
  spawn,
  execSync
} = require('child_process');
const pki = forge.pki;
const asn1 = forge.asn1;

function getArg (name, defVal) {
  name = '--' + name;
  let pos = process.argv.indexOf(name);
  if (pos > 0 && pos + 1 < process.argv.length) {
    pos += 1;
    let rs = [process.argv[pos]];
    pos = process.argv.indexOf(name, pos);
    while (pos > 0 && pos + 1 < process.argv.length) {
      pos += 1;
      rs.push(process.argv[pos]);
      pos = process.argv.indexOf(name, pos);
    }
    if (rs.length > 1) return rs;
    return rs[0];
  }
  return defVal;
}

function addr2obj (addr) {
  if (addr) {
    if (/^(?:(\w+):\/\/)?([^:\/]+)(?::(\d+))?/.test(addr)) {
      return { protocol: RegExp.$1 || 'http', host: RegExp.$2, port: RegExp.$3 || null };
    }
    const [host, port] = addr.split(':');
    return { host, port: port || null };
  }
}

let nameservers = getArg('dns');
if (nameservers && nameservers.length > 0) {
  dns.setServers(nameservers.concat(dns.getServers()));
}

const CRLF = Buffer.from('\n');
const EMPTY = Buffer.alloc(0);
const SYS_PROXY = addr2obj(getArg('proxy')) || {};
const SYS_REDIRECTS = {};
const REDIRECT_CONF = getArg('redirect');
const BASE_DIR = getArg('cache-dir', path.resolve(process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE, '.cache-mirror'));
if (REDIRECT_CONF) {
  fs.readFileSync(REDIRECT_CONF).toString('utf-8').split('\n').forEach(line => {
    let [m, k, v] = line.split(/\s+/);
    if (m && k && v) {
      SYS_REDIRECTS[m + ' ' + k] = v;
    }
  });
}
let HOSTS = {};
function loadHosts (filename) {
  fs.readFile(filename, (err, buffer) => {
    if (err) {
      HOSTS = {};
    } else {
      HOSTS = buffer.toString('utf-8').split('\n').reduce((r, line) => {
        if (/^\s*(\w[^#\s]+)((?:\s+[^#\s]+)+)/.test(line)) {
          let ip = RegExp.$1;
          let alias = RegExp.$2.split(/\s+/);
          for (let a of alias) {
            if (a) {
              r[a] = ip;
            }
          }
        }
        return r;
      }, {});
    }
    console.log('load hosts => %s %j', filename, HOSTS);
  });
}
const lookup = (function () {
  let hostFile = getArg('hosts');
  if (!hostFile) return;
  if (hostFile !== 'false') {
    fs.watch(hostFile, () => {
      loadHosts(hostFile);
    });
    loadHosts(hostFile);
  }
  return function (hostname, options, callback) {
    let ip = HOSTS[hostname];
    if (ip) {
      return callback(null, ip, 4);
    } else if (options.family === 4) {
      dns.resolve4(hostname, (err, addresses) => {
        if (err) return callback(err);
        callback(err, addresses[0], options.family);
      });
    } else if (options.family === 6) {
      dns.resolve6(hostname, (err, addresses) => {
        if (err) return callback(err);
        callback(err, addresses[0], options.family)
      });
    } else {
      dns.resolve4(hostname, (err, addresses) => {
        if (err) {
          dns.resolve6(hostname, (err, addresses) => {
            if (err) return callback(err);
            callback(err, addresses[0], 6);
          });
        } else {
          callback(err, addresses[0], 4);
        }
      });
    }
  }
})();

function md5 (buf) {
  return crypto
    .createHash('md5')
    .update(buf)
    .digest('hex').toUpperCase();
}

function resolveFile (...args) {
  try {
    return path.resolve(BASE_DIR, ...args);
  } catch (err) {
    console.log('resolve file error =>', args);
    throw err;
  }
}

const readFile = filename => {
  return new Promise(resolve => {
    fs.readFile(filename, (err, data) => {
      if (err) return resolve(null);
      return resolve(data);
    })
  })
}

function loadKeys () {
  try {
    const privatePem = fs.readFileSync(resolveFile('root.key'));
    const privateKey = pki.privateKeyFromPem(privatePem);
    const publicKey = pki.publicKeyFromPem(fs.readFileSync(resolveFile('root.pub')));
    return {
      privatePem,
      privateKey,
      publicKey
    }
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw err;
    }
    const keys = pki.rsa.generateKeyPair(2048);
    const privatePem = Buffer.from(pki.privateKeyToPem(keys.privateKey));
    try {
      fs.mkdirSync(BASE_DIR, { recursive: true });
    } catch (e) {/* ignore */ }
    fs.writeFileSync(resolveFile('root.key'), privatePem);
    fs.writeFileSync(resolveFile('root.pub'), pki.publicKeyToPem(keys.publicKey));
    return {
      privatePem,
      privateKey: keys.privateKey,
      publicKey: keys.publicKey
    }
  }
}

function getLocalIP () {
  let ips = [];
  let ifaces = require('os').networkInterfaces();
  Object.keys(ifaces).forEach(ifname => {
    let alias = 0;
    ifaces[ifname].forEach(iface => {
      if ('IPv4' !== iface.family || iface.internal !== false) {
        return;
      }
      if (alias === 0) {
        ips.push({
          name: ifname,
          ip: iface.address,
          netmask: iface.netmask,
          iface
        })
      }
      ++alias;
    });
  });
  if (ips.length > 0) {
    return (ips.filter(ip => !(/.255$/.test(ip.netmask)))[0] || ips[0]).ip
  } else {
    return '127.0.0.1';
  }
}

function getLocalId () {
  let id = getArg('id');
  if (id === 'true' || id === true) return getLocalIP();
  if (id) return id;
  return require('os').hostname();
}

function loadRootCert (keys) {
  const crtFile = resolveFile('root.crt');
  try {
    return pki.certificateFromPem(fs.readFileSync(crtFile));
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw err;
    }
    let cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 50);
    var attrs = [{
      name: 'commonName',
      value: 'Auto Cache Mirror@' + getLocalId()
    }, {
      shortName: 'OU',
      value: 'Cache'
    }, {
      name: 'organizationName',
      value: 'Mirror'
    }, {
      name: 'localityName',
      value: 'Local'
    }, {
      shortName: 'ST',
      value: 'Network'
    }, {
      name: 'countryName',
      value: 'CN'
    }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([{
      name: 'basicConstraints',
      critical: true,
      cA: true
    }, {
      name: 'keyUsage',
      critical: true,
      keyCertSign: true,
      digitalSignature: true,
      cRLSign: true
    }, {
      name: 'subjectKeyIdentifier',
      hash: true
    }, {
      name: 'authorityKeyIdentifier',
      keyid: 'always',
      issuer: true
    }]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    const pem = Buffer.from(pki.certificateToPem(cert));
    console.log('init root cert =>', crtFile);
    fs.writeFileSync(crtFile, pem);
    return pki.certificateFromPem(pem);
  }
}

const {
  privatePem,
  privateKey,
  publicKey
} = loadKeys();
const root = loadRootCert({
  privatePem,
  privateKey,
  publicKey
});
const GIT_BIN = getArg('--git') || execSync('which git || echo').toString('utf-8').trim();
const GIT_CORE = GIT_BIN && execSync(`"${GIT_BIN}" --exec-path`).toString('utf-8').trim();

function issuerCert (privateKey, publicKey, cert1, altNames, subject, extensions) {
  const cert = pki.createCertificate();
  cert.publicKey = publicKey;
  if (cert1) {
    cert.validity = cert1.validity;
  } else {
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
  }
  if (subject) {
    cert.setSubject(subject);
  } else {
    cert.setSubject(cert1.subject.attributes.map(a => {
      return {
        shortName: a.shortName,
        value: a.valueTagClass === asn1.Type.UTF8 ? forge.util.decodeUtf8(a.value) : a.value,
        valueTagClass: a.valueTagClass
      }
    }));
  }
  cert.setIssuer(root.subject.attributes.map(a => {
    return {
      shortName: a.shortName,
      value: a.valueTagClass === asn1.Type.UTF8 ? forge.util.decodeUtf8(a.value) : a.value,
      valueTagClass: a.valueTagClass
    }
  }));
  const excludes = [
    'cRLDistributionPoints', 'certificatePolicies', 'authorityInfoAccess', 'authorityKeyIdentifier'
  ];
  if (!extensions) {
    extensions = cert1.extensions.filter(e => !excludes.includes(e.name)).map(ext => {
      ext = Object.assign({}, ext);
      delete ext.id;
      return ext;
    });
  }
  if (Array.isArray(altNames)) {
    let subjectAlt = extensions.filter(e => e.name === 'subjectAltName')[0];
    if (!subjectAlt) {
      subjectAlt = {
        name: 'subjectAltName',
        altNames: []
      };
      extensions.push(subjectAlt);
    }
    subjectAlt.altNames = subjectAlt.altNames.concat(altNames)
  }
  cert.setExtensions(extensions);
  cert.sign(privateKey, forge.md.sha256.create());
  const pem = pki.certificateToPem(cert);
  return Buffer.from(pem);
}

const handler = socket => {
  const port = socket.localPort;
  socket.reqId = 'REQ' + Date.now();
  socket.once('readable', chunk => {
    chunk = socket.read() || EMPTY;
    if (chunk[0] === 0x16) { // the type of tls message
      socket.unshift(chunk); // put the chunk back to socket which will be used by TLSSocket
      // https://wiki.osdev.org/TLS_Handshake#Client_Hello_Message
      // ==== Record Header =======
      // 0   => the type of tls message
      //        0x16 Handshake
      //        0x14 Change Cipher Spec
      //        0x15 Alert
      //        0x17 Application Data 
      // 1~2 => version
      //        0x0301 TLS1.0
      //        0x0302 TLS1.1
      //        0x0303 TLS1.2
      // 3~4 => length of contained packet
      //        0x00de
      // let len = chunk.readInt16BE(3);
      // ==== Handshake Header =======
      // 5   => handshake message type
      //        0x00 Hello Request
      //        0x01 Client Hello
      //        0x02 Server Hello
      //        0x0b Certificate
      //        0x0c Server Key Exchange
      //        0x0d Certificate Request
      //        0x0e Server Hello Done
      //        0x0f Certificate Verify 
      //        0x10 Client Key Exchange
      //        0x14 Finished
      // 6~8 => three-byte length
      //        0x0000da 218
      // let size = chunk.readUIntBE(6, 3);
      //  9~10 => version
      //          0x0303 TLS 1.2
      // 11~43 => 32-bytes random client data
      // 44    => session ID length=0 if it was not null, it would be followed by the session ID
      let offset = 44 + chunk.readInt8(43);
      // offset~+2 => Cipher Suites Length
      offset += 2 + chunk.readInt16BE(offset);
      // offset~+1 => number of compression methods
      offset += 1 + chunk.readInt8(offset);
      // offset~+2 => extensions length
      let extSize = chunk.readInt16BE(offset);
      offset += 2;
      let ext = chunk.slice(offset, offset + extSize);
      let extOffset = 0;
      let hostname = socket.localAddress;
      while (extOffset < ext.length - 1) {
        let extType = ext.readUIntBE(extOffset, 2);
        if (extType === 0x0000) { // server_name
          extOffset += 6;
          if (ext[extOffset] === 0x00) { // server name type=host_name
            extOffset += 1;
            let l = ext.readInt16BE(extOffset);
            extOffset += 2;
            hostname = ext.toString('utf-8', extOffset, extOffset + l);
            extOffset += l;
            break;
          }
        } else {
          extOffset += 2;
          extOffset += 2 + ext.readInt16BE(extOffset);
        }
      }
      let isLocal = false;
      if (/^(.*)\.local$/.test(hostname)) {
        hostname = RegExp.$1;
        isLocal = true;
      }
      // 不允许IP直接连接
      if (net.isIP(hostname)) {
        return socket.end();
      }
      // 读取证书
      const certFile = resolveFile(hostname, '.cert');
      readFile(certFile).then(certPem => {
        if (!certPem) return [false, null];
        const cls = new tls.TLSSocket(socket, {
          isServer: true,
          key: privatePem,
          cert: certPem
        });
        cls.reqId = socket.reqId;
        return new Promise((resolve) => {
          cls.once('readable', () => {
            let host, method, url, httpVersion;
            let header = cls.read() || EMPTY;
            let chunks = [];
            let pos = 0;
            do {
              let p = header.indexOf(CRLF, pos);
              if (p < 0) {
                let chunk = cls.read();
                if (chunk) {
                  header = Buffer.concat([header, chunk]);
                  continue;
                } else {
                  break;
                }
              }
              let s = header.toString('utf-8', pos, p);
              if (!url && /^(\w+)\s*(\S+)\s*(HTTP\/\S+)/i.test(s)) {
                method = RegExp.$1;
                url = RegExp.$2;
                httpVersion = RegExp.$3;
                chunks.push(header.slice(pos, p + CRLF.length));
              } else if (!host && /^(Host:\s*)(.*)(\s*)$/i.test(s)) {
                let prefix = RegExp.$1;
                let suffix = RegExp.$3;
                host = RegExp.$2;
                if (/^(.*):(.*)/.test(host)) {
                  host = RegExp.$1;
                  port = parseInt(RegExp.$2, 10) || port;
                }
                if (isLocal && /^(.*)\.local$/i.test(host)) {
                  host = RegExp.$1;
                  chunks.push(Buffer.from(prefix + host + suffix, 'utf-8'));
                } else {
                  chunks.push(header.slice(pos, p + CRLF.length));
                }
              } else {
                chunks.push(header.slice(pos, p + CRLF.length));
              }
              pos = p + CRLF.length;
            } while (!(host && url));
            if (!url || !host) {
              console.log('[%s] invalid https request =>', cls.reqId, header.length, header.toString('utf-8'));
              return cls.end();
            }
            let { pathname, query } = urlParse(url);
            if (checkGit(host, port, pathname, header, pos, cls, query, method, httpVersion, url)) {
              return resolve([true, cls, header]);
            }
            chunks.push(header.slice(pos));
            let chunk = cls.read();
            while (chunk) {
              chunks.push(chunk);
              chunk = cls.read();
            }
            header = Buffer.concat(chunks);
            const filename = resolveFile(host, port.toString(), pathname.replace(/^\/*/, ''), md5(header));
            fs.stat(filename, (_, stat) => {
              if (stat && stat.size > 0) {
                console.log('[%s] cache =>', cls.reqId, method, host, port, url, filename);
                fs.createReadStream(filename).pipe(cls);
                return resolve([true, cls, header]);
              };
              return resolve([false, cls, header]);
            });
          });
        });
      }).then(([cached, cls, header]) => {
        if (cached) return;
        const options = { rejectUnauthorized: false, servername: hostname, lookup };
        if (SYS_PROXY.host) {
          const proxyOpts = {
            rejectUnauthorized: false,
            host: SYS_PROXY.host,
            port: SYS_PROXY.port
          };
          console.log('[%s] connect proxy => %s:%s', socket.reqId, SYS_PROXY.host, SYS_PROXY.port);
          const proxy = net.connect(proxyOpts, () => {
            console.log('[%s] proxy connected => %s:%s', socket.reqId, hostname, port);
            proxy.write(`CONNECT ${hostname}:${port} HTTP/1.1\r\n\r\n`);
          });
          return proxy.once('readable', () => {
            console.log('[%s] proxy readable => %s:%s', socket.reqId, hostname, port);
            let tmp = EMPTY;
            let pos = 0;
            do {
              let p = tmp.indexOf(CRLF, pos);
              if (p < 0) {
                let chunk = proxy.read();
                if (chunk) {
                  tmp = Buffer.concat([tmp, chunk]);
                  continue;
                } else {
                  break;
                }
              }
              let s = tmp.toString('utf-8', pos, p);
              pos = p + CRLF.length;
              if (/^HTTP\/\S+\s+(\d+)/i.test(s) && /Connection established/i.test(s) && checkBodyStart(tmp, pos)) {
                console.log('[%s] https proxy status =>', socket.reqId, s);
                tmp = tmp.slice(p + 4);
                break;
              }
            } while (pos < tmp.length);
            options.socket = proxy;
            connectTLS(socket, options, cls, header, certFile, isLocal, port);
          });
        }
        options.host = hostname;
        options.port = port;
        connectTLS(socket, options, cls, header, certFile, isLocal, port);
      }).catch(err => {
        console.log('[%s] error =>', socket.reqId, err);
      });
    } else { // http
      if (SYS_PROXY.host) {
        let host, method, url, httpVersion;
        let header = chunk;
        let pos = 0;
        do {
          let p = header.indexOf(CRLF, pos);
          if (p < 0) {
            let chunk = socket.read();
            if (chunk) {
              header = Buffer.concat([header, chunk]);
              continue;
            } else {
              break;
            }
          }
          let s = header.toString('utf-8', pos, p);
          if (!url && /^(\w+)\s*(\S+)\s*(HTTP\/\S+)/i.test(s)) {
            method = RegExp.$1;
            url = RegExp.$2;
            httpVersion = RegExp.$3;
          } else if (!host && /^(Host:\s*)(.*)(\s*)$/i.test(s)) {
            host = RegExp.$2;
            if (/^(.*):(.*)/.test(host)) {
              host = RegExp.$1;
              port = parseInt(RegExp.$2, 10) || port;
            }
          }
          pos = p + CRLF.length;
        } while (!(host && url));
        if (!url || !host || !method || !httpVersion) {
          console.log('[%s] invalid http request =>', socket.reqId, header.toString('utf-8'));
          return socket.end();
        }
        if (net.isIP(host)) {
          return cachePipe(socket, null, port, header, null);
        }
        const proxyOpts = {
          host: SYS_PROXY.host,
          port: SYS_PROXY.port
        };
        console.log('[%s] connect proxy => %s:%s', socket.reqId, SYS_PROXY.host, SYS_PROXY.port);
        const proxy = net.connect(proxyOpts, () => {
          console.log('[%s] proxy connected => %s:%s', socket.reqId, host, port);
          proxy.write(`CONNECT ${host}:${port} HTTP/1.1\r\n\r\n`);
        });

        return proxy.once('readable', () => {
          console.log('[%s] proxy readable => %s:%s', socket.reqId, host, port);
          let tmp = EMPTY;
          let pos = 0;
          do {
            let p = tmp.indexOf(CRLF, pos);
            if (p < 0) {
              let chunk = proxy.read();
              if (chunk) {
                tmp = Buffer.concat([tmp, chunk]);
                continue;
              } else {
                break;
              }
            }
            let s = tmp.toString('utf-8', pos, p);
            pos = p + CRLF.length;
            if (/^HTTP\/\S+\s+(\d+)/i.test(s) && /Connection established/i.test(s) && checkBodyStart(tmp, pos)) {
              console.log('[%s] http proxy status =>', socket.reqId, s);
              tmp = tmp.slice(p + 4);
              break;
            }
          } while (pos < tmp.length);
          cachePipe(socket, proxy, port, header, null);
        });
      } else {
        cachePipe(socket, null, port, chunk, null);
      }
    }
  });
};

function connectTLS (socket, options, cls, header, certFile, isLocal, port) {
  const sls = tls.connect(options, () => {
    if (!cls) {
      const csr = sls.getPeerCertificate(true);
      const cert1 = pki.certificateFromAsn1(asn1.fromDer(csr.raw.toString('binary')));
      const certPem = issuerCert(privateKey, publicKey, cert1);
      ensureDir(path.dirname(certFile)).then(() => {
        fs.writeFile(certFile, certPem, () => {
          console.log('[%s] cached cert =>', socket.reqId, certFile);
        });
      });
      cls = new tls.TLSSocket(socket, {
        isServer: true,
        key: privatePem,
        cert: certPem
      });
      cls.reqId = socket.reqId;
      cls.once('readable', () => {
        cachePipe(cls, sls, port, EMPTY, isLocal ? (host) => {
          if (/^(.*)\.local$/i.test(host)) {
            return RegExp.$1;
          }
          return host;
        } : null);
      });
    } else {
      cachePipe(cls, sls, port, header, null);
    }
  });
}

function checkGit (host, port, pathname, header, pos, client, query, method, httpVersion, url) {
  if (/^\/[^/]+\/[^/]+\/(HEAD|info\/refs|objects\/info\/.*|git-(upload|receive)-pack)$/.test(pathname)) {
    console.log('[%s] git =>', client.reqId, method, host, url, resolveFile(host));
    pathname = pathname.replace(/^(?:\/[^\/]+){2}/, $0 => {
      if (/.git$/.test($0)) {
        return $0;
      }
      return $0 + '.git';
    });
    let chunks = [];
    const headers = {};
    pos = 0;
    do {
      let p = header.indexOf(CRLF, pos);
      if (p < 0) {
        let chunk = client.read();
        if (chunk) {
          header = Buffer.concat([header, chunk]);
          continue;
        } else {
          break;
        }
      }
      if (checkBodyStart(header, pos)) {
        pos = p + CRLF.length;
        break;
      }
      let s = header.toString('utf-8', pos, p);
      if (/^([^:]+):\s*(.*)(\s*)/i.test(s)) {
        headers[RegExp.$1.toLowerCase()] = RegExp.$2;
      }
      pos = p + CRLF.length;
    } while (pos < header.length);
    chunks.push(header.slice(pos));
    let chunk = client.read();
    while (chunk) {
      chunks.push(chunk);
      chunk = client.read();
    }
    let body = Buffer.concat(chunks);
    if (headers['content-encoding'] === 'gzip') {
      body = zlib.gunzipSync(body);
    }
    const env = {
      PATH_INFO: pathname,
      GIT_PROJECT_ROOT: resolveFile(host),
      GIT_HTTP_EXPORT_ALL: '',
      REMOTE_USER: '',
      QUERY_STRING: query || '',
      REQUEST_METHOD: method,
      CONTENT_TYPE: headers['content-type'] || '',
      CONTENT_LENGTH: body.length,
      DOCUMENT_URI: pathname,
      REQUEST_URI: url
    }
    console.log('[%s] git req => %s %j', client.reqId, pathname, headers);
    let repoHead = resolveFile(host, pathname.replace(/^\/([^/]+\/[^/]+).*$/, '$1'), 'HEAD');
    return statAsync(repoHead).then(stat => {
      if (!(stat && stat.size > 0)) {
        const baseUrl = (client instanceof tls.TLSSocket ? 'https' : 'http') + '://' + host + ':' + port;
        return gitClone(env.GIT_PROJECT_ROOT, pathname, baseUrl, client);
      }
    }).then(() => {
      return pipeGit(pathname, env, client, body, httpVersion, client);
    }).then(() => {
      client.end();
    }).catch(err => {
      console.error('[%s] git error =>', client.reqId, pathname, err);
      client.end();
    });
  }
}

function statAsync (filename) {
  return new Promise(resolve => {
    fs.stat(filename, (_, stat) => {
      return resolve(stat);
    })
  })
}

function cachePipe (client, server, port, header, mapper) {
  let method, host, url, httpVersion, userAgent;
  let pos = 0;
  let chunks = [];
  do {
    let p = header.indexOf(CRLF, pos);
    if (p < 0) {
      let chunk = client.read();
      if (chunk) {
        header = Buffer.concat([header, chunk]);
        continue;
      } else {
        break;
      }
    }
    let s = header.toString('utf-8', pos, p);
    if (!url && /^(\w+)\s*(\S+)\s*(HTTP\/\S+)/i.test(s)) {
      method = RegExp.$1;
      url = RegExp.$2;
      httpVersion = RegExp.$3;
      chunks.push(header.slice(pos, p + CRLF.length));
    } else if (!userAgent && /^(\s*User-Agent:\s*)(.*)(\s*)$/i.test(s)) {
      userAgent = RegExp.$2;
      chunks.push(header.slice(pos, p + CRLF.length));
    } else if (!host && /^(\s*Host:\s*)(.*)(\s*)$/i.test(s)) {
      let prefix = RegExp.$1;
      let suffix = RegExp.$3;
      host = RegExp.$2;
      if (/^(.*):(.*)/.test(host)) {
        host = RegExp.$1;
        port = parseInt(RegExp.$2, 10) || port;
      }
      if (mapper) {
        host = mapper(host);
        chunks.push(Buffer.from(prefix + host + suffix, 'utf-8'));
      } else {
        chunks.push(header.slice(pos, p + CRLF.length));
      }
    } else {
      chunks.push(header.slice(pos, p + CRLF.length));
    }
    pos = p + CRLF.length;
  } while (!(host && url && userAgent));
  chunks.push(header.slice(pos));
  let chunk = client.read();
  while (chunk) {
    chunks.push(chunk);
    chunk = client.read();
  }
  if (!url || !host) {
    console.log('[%s] cache pipe invalid request =>', client.reqId, header.toString('utf-8'));
    client.end();
    return;
  }
  if (net.isIP(host)) {
    return manage(client, header, method, url, httpVersion);
  }
  let { pathname, query } = urlParse(url);
  if (checkGit(host, port, pathname, header, pos, client, query, method, httpVersion, url, userAgent)) {
    return;
  }
  const filename = resolveFile(host, port.toString(), pathname.replace(/^\/*/, ''), md5(Buffer.concat(chunks)));
  fs.stat(filename, (_, stat) => {
    if (stat && stat.size > 0) {
      console.log('[%s] cache =>', client.reqId, method, host, port, url, filename);
      return fs.createReadStream(filename).pipe(client)
    };
    console.log('[%s] request =>', client.reqId, method, host, port, url, filename);
    let tmpfile = filename + '.' + client.reqId;
    Promise.all([
      createWriteStream(tmpfile),
      createWriteStream(filename + '.REQ')
    ]).then(([stream, req]) => {
      let key = method + ' ' + host + ':' + port + pathname;
      let location = SYS_REDIRECTS[key];
      if (location) {
        console.log('[%s] system redirect =>', client.reqId, location);
        connectLocation(location, httpVersion, userAgent, client).then(server => {
          pipeServer(client, server, stream, method, host, url, httpVersion, userAgent);
        }).catch(err => {
          console.log('[%s] redirect error =>', client.reqId, err);
          client.end();
          stream.close();
        });
        if (server) {
          server.end();
          server = null;
        }
      } else if (server) {
        server.write(Buffer.concat(chunks));
      } else {
        const options = { port, host, lookup };
        server = net.connect(options, () => {
          server.write(Buffer.concat(chunks));
        });
      }
      client.once('cache-complete', () => {
        fs.rename(tmpfile, filename, () => {
          console.log('[%s] cached =>', client.reqId, filename);
        });
      });
      req.write(header);
      client.on('end', () => {
        client.ended = true;
        client.write = () => { };
        console.log('[%s] client end.', client.reqId);
        req.close();
      });
      client.on('error', (err) => {
        console.log('[%s] client error =>', client.reqId, err);
        client.write = () => { };
      });
      if (server) {
        server.on('error', err=>{
          console.log('[%s] server error =>', client.reqId, err);
        });
        client.on('data', buf => {
          req.write(buf);
          server.write(buf);
        });
        if (server.connecting) {
          server.on('connect', () => {
            pipeServer(client, server, stream, method, host, url, httpVersion, userAgent);
          });
        } else {
          pipeServer(client, server, stream, method, host, url, httpVersion, userAgent);
        }
      } else {
        client.on('data', buf => {
          req.write(buf);
        });
      }
    }).catch(err => {
      console.error('[%s] cache request error =>', client.reqId, method, host, url, err);
      client.end();
    });
  });
}

function checkBodyStart (buf, pos) {
  if (buf[pos] === 0x0d && buf[pos + 1] === 0x0a) {
    return 2;
  } else if (buf[pos] === 0x0a) {
    return 1;
  }
  return 0;
}

function printProgress (id, progress) {
  if (process.stdout.clearLine) {
    process.stdout.clearLine();
    process.stdout.cursorTo(0);
    process.stdout.write(id + progress);
  }
}

function pipeServer (client, server, stream, method, host, url, httpVersion, userAgent) {
  console.log('[%s][%s] pipe from server => %s:%s', client.reqId, server.localPort, server.remoteAddress, server.remotePort);
  server.reqId = server.localPort;
  let checked = false, location; // 检查HTTP状态
  server.on('error', (err) => {
    console.log('[%s] server error =>', client.reqId, err);
    if (!location) {
      client.end();
      stream.close();
    }
  });
  server.on('end', () => {
    console.log('[%s][%s] server end(%s).', client.reqId, server.reqId, !!location);
    if (!location) {
      client.end();
      if (checked) {
        stream.close();
        client.emit('cache-complete');
      }
    }
  });
  let tmp = EMPTY;
  let pos = 0, status;
  let contentStart = false;
  let contentLength = -1;
  let receiveLength = 0;
  let rsp = EMPTY;
  let rpos = 0;
  const title = `[${client.reqId}][${server.reqId}] received => `;
  const checkReceived = buf => {
    if (contentStart) {
      receiveLength += buf.length;
      if (contentLength > 0) {
        printProgress(title, receiveLength + '/' + contentLength);
        if (contentLength === receiveLength) {
          process.stdout.write('\n');
          console.log('[%s][%s] content complete =>', client.reqId, server.reqId, receiveLength);
          server.end();
        }
      }
    } else {
      rsp = Buffer.concat([rsp, buf]);
      do {
        let p = rsp.indexOf(CRLF, rpos);
        if (p > 0) {
          let s = rsp.toString('utf-8', rpos, p);
          rpos = p + CRLF.length;
          let started = checkBodyStart(rsp, rpos);
          // console.log('receiveLength =>', started);
          if (started > 0) {
            contentStart = true;
            receiveLength = rsp.length - rpos - started;
            if (contentLength < 0) {
              console.log('[%s] not content length =>', client.reqId, rsp.toString('utf-8', 0, rpos));
            } else if (contentLength === receiveLength) {
              console.log('[%s][%s] content complete =>', client.reqId, server.reqId, receiveLength);
              server.end();
            } else {
              console.log('[%s] content length =>', client.reqId, contentLength, receiveLength);
            }
            break;
          }
          if (/^\s*Content-Length:\s*(\d+)\s*$/i.test(s)) {
            contentLength = parseInt(RegExp.$1);
          }
        } else {
          break;
        }
      } while (!contentStart);
    }
  };
  server.on('data', buf => {
    if (checked) {
      stream.write(buf);
      client.write(buf);
      checkReceived(buf);
    } else {
      tmp = Buffer.concat([tmp, buf]);
      do {
        let p = tmp.indexOf(CRLF, pos);
        if (p > 0) {
          let s = tmp.toString('utf-8', pos, p);
          pos = p + CRLF.length;
          if (status === 301 || status === 302) {
            if (/^\s*location:\s*(.*)\s*$/i.test(s)) {
              location = RegExp.$1;
              server.end();
              console.log('[%s] redirect url =>', client.reqId, location);
              connectLocation(location, httpVersion, userAgent, client).then(server => {
                pipeServer(client, server, stream, method, host, url, httpVersion, userAgent);
              }).catch(err => {
                console.log('[%s] redirect error =>', client.reqId, err);
                client.end();
                stream.close();
              });
            }
          }
          if (/^HTTP\/\S+\s+(\d+)/i.test(s)) {
            status = parseInt(RegExp.$1, 10);
            console.log('[%s][%s] server status =>', client.reqId, server.reqId, status);
            if (status === 301 || status === 302) {
              continue;
            }
            checked = true;
            stream.write(tmp);
            client.write(tmp);
            checkReceived(tmp);
          }
        } else {
          break;
        }
      } while (!checked);
    }
  });
}

function connectLocation (location, httpVersion, agent, client) {
  let locUrl = urlParse(location);
  if (/^https/.test(locUrl.protocol)) {
    locUrl.port = locUrl.port || 443;
  } else {
    locUrl.port = locUrl.port || 80;
  }
  const options = {
    host: locUrl.hostname,
    port: locUrl.port,
    lookup
  };
  let protocol = locUrl.protocol;
  if (SYS_PROXY.host) {
    options.host = SYS_PROXY.host;
    options.port = SYS_PROXY.port;
    protocol = SYS_PROXY.protocol;
  }
  return new Promise((_resolve, _reject) => {
    let done = false;
    const resolve = (server) => {
      if (!done) {
        done = true;
        _resolve(server)
      }
    };
    const reject = (err) => {
      if (!done) {
        done = true;
        _reject(err)
      }
    };
    const writeReq = server => {
      const reqData = [
        `GET ${locUrl.path} ${httpVersion}`,
        `Host: ${locUrl.hostname}`,
        `User-Agent: ${agent}`,
        'Accept: */*',
        '\r\n'
      ];
      const data = reqData.join('\r\n');
      if (!SYS_PROXY.host) {
        server.write(Buffer.from(data, 'utf-8'));
        return resolve(server);
      }
      server.once('readable', () => {
        console.log('[%s] location proxy readable.', client.reqId);
        let tmp = server.read() || EMPTY;
        let pos = 0;
        do {
          let p = tmp.indexOf(CRLF, pos);
          if (p < 0) {
            let chunk = server.read();
            if (chunk) {
              tmp = Buffer.concat([tmp, chunk]);
              continue;
            } else {
              break;
            }
          }
          let s = tmp.toString('utf-8', pos, p);
          pos = p + CRLF.length;
          if (/^HTTP\/\S+\s+(\d+)/i.test(s) && /Connection established/i.test(s) && checkBodyStart(tmp, pos)) {
            console.log('[%s] location proxy status =>', client.reqId, s);
            tmp = tmp.slice(p + 4);
            break;
          }
        } while (pos < tmp.length);
        if (tmp.length > 0) {
          console.log('[%s] location proxy error =>', client.reqId, tmp.toString('utf-8'));
        }
        if (/^https/.test(locUrl.protocol)) {
          console.log('[%s] location attach proxy...', client.reqId)
          const proxy = tls.connect({ socket: server, rejectUnauthorized: false }, () => {
            console.log('[%s] location proxy attached.', client.reqId)
            proxy.write(Buffer.from(data, 'utf-8'));
            resolve(proxy);
          }).once('error', reject);
        } else {
          server.write(Buffer.from(data, 'utf-8'));
          resolve(server);
        }
      });
      server.write(`CONNECT ${locUrl.hostname}:${locUrl.port} ${httpVersion}\r\n`);
      server.write(`Host: ${locUrl.hostname}:${locUrl.port}\r\n`);
      server.write(`User-Agent: ${agent}\r\n`);
      server.write(`Proxy-Connection: close\r\n`);
      server.write(`\r\n`);
    };
    if (/^https/.test(protocol)) {
      options.port = options.port || 443;
      options.rejectUnauthorized = false;
      console.log('[%s] connect location => %j', client.reqId, options);
      const server = tls.connect(options, () => {
        writeReq(server);
      });
      server.once('error', reject);
      return server;
    }
    options.port = options.port || 80;
    console.log('[%s] connect location => %j', client.reqId, options);
    const server = net.connect(options, () => {
      console.log('[%s] location connected => %j', client.reqId, options);
      writeReq(server);
    });
    server.once('error', reject);
    return server;
  });
}

function gitClone (root, pathname, baseUrl, client) {
  const env = {
    GIT_BIN,
    GIT_ROOT: root,
    GIT_BASE: baseUrl
  };
  if (/^\/([^/]+)\/([^/]+?)(\.git)?(?:\/|$)/.test(pathname)) {
    env.GIT_USER = RegExp.$1;
    env.GIT_PROJECT = RegExp.$2;
  }
  const p = spawn(path.resolve(__dirname, 'git-clone.sh'), {
    env
  });
  console.log('[%s] spawn =>', client.reqId, pathname, p.pid);
  p.stdout.on('data', buf => {
    process.stdout.write(buf);
  });
  p.stderr.on('data', buf => {
    process.stderr.write(buf);
  });
  return new Promise((resolve, reject) => {
    p.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        return reject(new Error('code: ' + code));
      }
    });
  });
}

function pipeGit (pathname, env, cls, body, httpVersion, client) {
  const p = spawn(path.resolve(GIT_CORE, 'git-http-backend'), {
    env,
  });
  return new Promise((resolve, reject) => {
    p.once('git-done', err => {
      if (err) {
        return reject(err);
      }
      return resolve(err);
    });
    let writeHeader = true;
    p.stdout.on('data', buf => {
      if (writeHeader) {
        cls.write(`${httpVersion} 200 OK\r\n`);
        writeHeader = false;
      }
      cls.write(buf);
    });
    p.stderr.on('data', buf => {
      p.emit('git-done', new Error(buf.toString('utf-8')))
    });
    p.on('error', err => {
      console.error('[%s] git error =>', client.reqId, err);
      p.emit('git-done', err);
    });
    p.on('close', (code) => {
      console.log('[%s] git done =>', client.reqId, pathname, code);
      if (code === 0) {
        p.emit('git-done');
      } else {
        p.emit('git-done', new Error('code: ' + code));
      }
    });
    p.stdin.write(body);
  });
}

function ensureDir (dir) {
  return new Promise((resolve, reject) => {
    fs.exists(dir, exists => {
      if (exists) return resolve(dir);
      ensureDir(path.dirname(dir)).then(() => {
        fs.mkdir(dir, err => {
          if (err && err.code !== 'EEXIST') return reject(err);
          return resolve(dir);
        });
      });
    });
  });
}

function manage (client, header, method, url, httpVersion) {
  let { pathname, query } = urlParse(url);
  if (pathname === '/root.crt') {
    client.write(`${httpVersion} 200 OK\r\n`);
    client.write('Server: AutoCacheMirror\r\n');
    client.write('Content-Type: application/x-x509-ca-cert\r\n');
    let pem = pki.certificateToPem(root);
    client.write(`Content-Length: ${pem.length}\r\n`);
    client.write('\r\n');
    client.end(pem);
    return;
  } else if (pathname.startsWith('/api/')) {
    client.write(`${httpVersion} 200 OK\r\n`);
    client.write('Server: AutoCacheMirror\r\n');
    client.write('Content-Type: application/json\r\n');
    client.write('\r\n');
    if (pathname === '/api/proxy') {
      if (method === 'GET') {
        return client.end(JSON.stringify(SYS_PROXY));
      } else if (method === 'POST') {
        query = qs.parse(query);
        let p = addr2obj(query.addr) || {};
        SYS_PROXY.protocol = p.protocol;
        SYS_PROXY.host = p.host;
        SYS_PROXY.port = p.port;
        return client.end(JSON.stringify(SYS_PROXY));
      }
    } else if (pathname === '/api/redirect') {
      if (method === 'GET') {
        return client.end(JSON.stringify(SYS_REDIRECTS));
      } else if (method === 'POST' || method === 'PUT') {
        query = qs.parse(query);
        if (query.src) {
          SYS_REDIRECTS[query.src] = query.dst;
        }
        if (query.persistence === 'true') {
          return fs.appendFile(REDIRECT_CONF, Buffer.from('\n' + query.src + ' ' + query.dst), () => {
            return client.end(JSON.stringify(SYS_REDIRECTS));
          })
        }
        return client.end(JSON.stringify(SYS_REDIRECTS));
      } else if (method === 'DELETE') {
        query = qs.parse(query);
        if (query.src) {
          delete SYS_REDIRECTS[query.src];
        }
        return client.end(JSON.stringify(SYS_REDIRECTS));
      }
    }
  }
  client.write(`${httpVersion} 200 OK\r\n`);
  client.write('Content-Type: text/html;charset=utf-8\r\n');
  client.write('\r\n');
  client.write('自动缓存镜像服务，只需要把域名绑定到地址: ' + client.localAddress + '，即可自动缓存所有请求的资源，加速再次访问<br/>');
  if (SYS_PROXY.host) {
    client.write('当前使用代理服务: ' + SYS_PROXY.protocol + '://' + SYS_PROXY.host + ':' + SYS_PROXY.port + '<br/>');
  }
  client.write('为了支持https，需要在客户端安装根证书<br/><code>');
  client.write(`\tLinux: curl http://${client.localAddress}:${client.localPort}/root.crt >> /etc/pki/tls/certs/ca-bundle.crt <br/>`);
  client.write(`\tMacOS: 从 http://${client.localAddress}:${client.localPort}/root.crt 下载之后安装，并信任 <br/>`);
  client.write(`\tnpm: curl http://${client.localAddress}:${client.localPort}/root.crt >> ~/.extra.crt 并设置环境变量 echo "export NODE_EXTRA_CA_CERTS=$HOME/.extra.crt" >> ~/.bash_profile <br/>`);
  client.write(`</code>`);
  client.write('当前缓存目录: ' + BASE_DIR + '<br/>');
  client.end();
}

function createWriteStream (filename) {
  return ensureDir(path.dirname(filename)).then(() => {
    return fs.createWriteStream(filename);
  })
}

function createServer (port, host) {
  return new Promise(resolve => {
    const server = net.createServer(handler).listen(port, host, () => {
      return resolve(server.address().port);
    });
  })
}

const appHost = getArg('host', '0.0.0.0');
Promise.all([
  createServer(443, appHost),
  createServer(80, appHost)
]).then(ports => {
  console.log('server ports => %j', ports);
});
