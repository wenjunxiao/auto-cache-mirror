const fs = require('fs');
const path = require('path');
const tls = require('tls');
const net = require('net');
const dns = require('dns');
const forge = require('node-forge');
const crypto = require('crypto');
const zlib = require("zlib");
const urlParse = require('url').parse;
const {
  spawn,
  execSync
} = require('child_process');
const pki = forge.pki;
const asn1 = forge.asn1;

function getArg (name, defVal) {
  let pos = process.argv.indexOf('--' + name);
  if (pos > 0 && pos + 1 < process.argv.length) {
    return process.argv[pos + 1];
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

const CRLF = Buffer.from('\r\n');
const EMPTY = Buffer.alloc(0);
const PROXY = addr2obj(getArg('proxy'))
const BASE_DIR = getArg('cache-dir', path.resolve(process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE, '.cache-mirror'));
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
    fs.watch(hostFile, (_, filename) => {
      loadHosts(filename);
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
  return path.resolve(BASE_DIR, ...args);
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
    console.log(ips)
    return (ips.filter(ip => !(/.255$/.test(ip.netmask)))[0] || ips[0]).ip
  } else {
    return '127.0.0.1';
  }
}

function getLocalId() {
  let id = getArg('id');
  if (id === 'true' || id === true) return getLocalIP();
  if (id) return id;
  return require('os').hostname();
}

console.log('v===>',getLocalId());

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
              if (!url && /^(\w+)\s*(\S+)\s*HTTP\/(\S+)/i.test(s)) {
                method = RegExp.$1;
                url = RegExp.$2;
                httpVersion = RegExp.$3;
                chunks.push(header.slice(pos, p + 2));
              } else if (!host && /^(Host:\s*)(.*)(\s*)$/.test(s)) {
                let prefix = RegExp.$1;
                let suffix = RegExp.$3;
                host = RegExp.$2;
                if (/^(.*):(.*)/.test(host)) {
                  host = RegExp.$1;
                  port = parseInt(RegExp.$2, 10) || port;
                }
                if (isLocal && /^(.*)\.local$/.test(host)) {
                  host = RegExp.$1;
                  chunks.push(Buffer.from(prefix + host + suffix, 'utf-8'));
                } else {
                  chunks.push(header.slice(pos, p + 2));
                }
              } else {
                chunks.push(header.slice(pos, p + 2));
              }
              pos = p + 2;
            } while (!(host && url));
            if (!url) {
              console.log('no url =>', header.toString('utf-8'));
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
                console.log('cache =>', method, host, url, filename);
                fs.createReadStream(filename).pipe(cls);
                return resolve([true, cls, header]);
              };
              return resolve([false, cls, header]);
            });
            // const stream = fs.createReadStream(filename);
            // stream.once('error', () => {
            //   return resolve([false, cls, header]);
            // }).once('end', () => {
            //   console.log('cache =>', method, host, url, filename);
            //   return resolve([true, cls, header]);
            // }).pipe(cls);
          });
        });
      }).then(([cached, cls, header]) => {
        if (cached) return;
        const options = { rejectUnauthorized: false, servername: hostname, lookup };
        const sls = tls.connect(port, hostname, options, () => {
          if (!cls) {
            const csr = sls.getPeerCertificate(true);
            const cert1 = pki.certificateFromAsn1(asn1.fromDer(csr.raw.toString('binary')));
            const certPem = issuerCert(privateKey, publicKey, cert1);
            ensureDir(path.dirname(certFile)).then(() => {
              fs.writeFile(certFile, certPem, () => {
                console.log('cache cert =>', certFile);
              });
            });
            cls = new tls.TLSSocket(socket, {
              isServer: true,
              key: privatePem,
              cert: certPem
            });
            cls.once('readable', () => {
              cachePipe(cls, sls, port, EMPTY, isLocal ? (host) => {
                if (/^(.*)\.local$/.test(host)) {
                  return RegExp.$1;
                }
                return host;
              } : null);
            });
          } else {
            cachePipe(cls, sls, port, header, null);
          }
        });
      }).catch(err => {
        console.log('error =>', err);
      });
    } else { // http
      cachePipe(socket, null, port, chunk, null);
    }
  });
};

function checkGit (host, port, pathname, header, pos, client, query, method, httpVersion, url) {
  if (/^\/[^/]+\/[^/]+\/(HEAD|info\/refs|objects\/info\/.*|git-(upload|receive)-pack)$/.test(pathname)) {
    console.log('git =>', method, host, url, resolveFile(host));
    pathname = pathname.replace(/^(?:\/[^\/]+){2}/, $0 => {
      if (/.git$/.test($0)) {
        return $0;
      }
      return $0 + '.git';
    });
    let chunks = [];
    const headers = {};
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
      if (p === pos) {
        pos = p + 2;
        break;
      }
      let s = header.toString('utf-8', pos, p);
      if (/^([^:]+):\s*(.*)(\s*)/i.test(s)) {
        headers[RegExp.$1.toLowerCase()] = RegExp.$2;
      }
      pos = p + 2;
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
      DOCUMENT_URI: pathname
    }
    let repoHead = resolveFile(host, pathname.replace(/^\/([^/]+\/[^/]+).*$/, '$1'), 'HEAD');
    return statAsync(repoHead).then(stat => {
      if (!(stat && stat.size > 0)) {
        const baseUrl = (client instanceof tls.TLSSocket ? 'https' : 'http') + '://' + host + ':' + port;
        return gitClone(env.GIT_PROJECT_ROOT, pathname, baseUrl);
      }
    }).then(() => {
      return pipeGit(pathname, env, client, body, httpVersion);
    }).then(() => {
      client.end();
    }).catch(err => {
      console.error('git error =>', err);
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
      chunks.push(header.slice(pos, p + 2));
    } else if (!userAgent && /^(User-Agent:\s*)(.*)(\s*)$/.test(s)) {
      userAgent = RegExp.$2;
      chunks.push(header.slice(pos, p + 2));
    } else if (!host && /^(Host:\s*)(.*)(\s*)$/.test(s)) {
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
        chunks.push(header.slice(pos, p + 2));
      }
    } else {
      chunks.push(header.slice(pos, p + 2));
    }
    pos = p + 2;
  } while (!(host && url && userAgent));
  chunks.push(header.slice(pos));
  let chunk = client.read();
  while (chunk) {
    chunks.push(chunk);
    chunk = client.read();
  }
  if (!url) {
    console.log('no url =>', header.toString('utf-8'));
    client.end();
    return;
  }
  if (net.isIP(host)) {
    return manage(client, header, method, url, httpVersion);
  }
  let { pathname, query } = urlParse(url);
  if (checkGit(host, port, pathname, header, pos, client, query, method, httpVersion, url)) {
    return;
  }
  const filename = resolveFile(host, port.toString(), pathname.replace(/^\/*/, ''), md5(Buffer.concat(chunks)));
  fs.stat(filename, (_, stat) => {
    if (stat && stat.size > 0) {
      console.log('cache =>', method, host, url, filename);
      return fs.createReadStream(filename).pipe(client)
    };
    console.log('request =>', method, host, url, filename);
    let tmpfile = filename + '.' + Date.now();
    Promise.all([
      createWriteStream(tmpfile),
      createWriteStream(filename + '.REQ')
    ]).then(([stream, req]) => {
      if (server) {
        server.write(Buffer.concat(chunks));
      } else {
        const options = { port, host, lookup };
        server = net.connect(options, () => {
          server.write(Buffer.concat(chunks));
        });
      }
      client.once('cache-complete', () => {
        fs.rename(tmpfile, filename, () => {
          console.log('cached =>', filename);
        });
      });
      req.write(header);
      client.on('end', () => {
        req.close();
      });
      client.on('data', buf => {
        req.write(buf);
        server.write(buf);
      });
      pipeServer(client, server, stream, method, host, url, httpVersion, userAgent);
    }).catch(err => {
      console.error('cache request error =>', method, host, url, err);
      client.end();
    });
  });
}

function pipeServer (client, server, stream, method, host, url, httpVersion, userAgent) {
  console.log('pipe from server => %j %s:%s', server.address(), server.remoteAddress, server.remotePort);
  let checked = false, location; // 检查HTTP状态
  server.on('error', (err) => {
    console.log('server error =>', err);
    if (!location) {
      client.end();
      stream.close();
    }
  });
  server.on('end', () => {
    console.log('server end.');
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
  server.on('data', buf => {
    if (checked) {
      stream.write(buf);
      client.write(buf);
    } else {
      tmp = Buffer.concat([tmp, buf]);
      do {
        let p = tmp.indexOf(CRLF, pos);
        if (p > 0) {
          let s = tmp.toString('utf-8', pos, p);
          pos = p + 2;
          if (status === 301 || status === 302) {
            if (/^\s*location:\s*(.*)$/i.test(s)) {
              location = RegExp.$1;
              server.end();
              console.log('redirect url =>', location);
              connectLocation(location, httpVersion, userAgent).then(server => {
                pipeServer(client, server, stream, method, host, url);
              }).catch(err => {
                console.log('redirect error =>', err);
                client.end();
                stream.close();
              });
            }
          }
          if (/^HTTP\/\S+\s+(\d+)/.test(s)) {
            status = parseInt(RegExp.$1, 10);
            // if (server.proxied && !proxied) {
            //   console.log('proxy status =>', status, s);
            //   if (/Connection established/i.test(s) && tmp.indexOf(CRLF, pos) === pos) {
            //     proxied = true;
            //     tmp = tmp.slice(pos + 2);
            //   }
            //   status = 0;
            //   pos = 0;
            //   continue;
            // }
            console.log('server status =>', status);
            if (status === 301 || status === 302) {
              continue;
            }
            checked = true;
            stream.write(tmp);
            client.write(tmp);
          }
        } else {
          break;
        }
      } while (!checked);
    }
  });
}

function connectLocation (location, httpVersion, agent) {
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
  if (PROXY) {
    options.host = PROXY.host;
    options.port = PROXY.port;
    protocol = PROXY.protocol;
  }
  return new Promise((resolve, reject) => {
    const writeReq = server => {
      const reqData = [
        `GET ${locUrl.path} ${httpVersion}`,
        `Host: ${locUrl.hostname}`,
        `User-Agent: ${agent}`,
        'Accept: */*',
        '\r\n'
      ];
      const data = reqData.join('\r\n');
      if (!PROXY) {
        server.write(Buffer.from(data, 'utf-8'));
        return resolve(server);
      }
      server.once('readable', () => {
        let tmp = EMPTY;
        let pos = 0;
        do {
          let p = tmp.indexOf(CRLF, pos);
          if (p < 0) {
            let chunk = server.read();
            if (chunk) {
              console.log('chunk ==>', chunk.toString('utf-8'));
              tmp = Buffer.concat([tmp, chunk]);
              continue;
            } else {
              break;
            }
          }
          let s = tmp.toString('utf-8', pos, p);
          pos = p + 2;
          if (/^HTTP\/\S+\s+(\d+)/.test(s) && /Connection established/i.test(s) && tmp.indexOf(CRLF, pos) === pos) {
            console.log('proxy status =>', s);
            tmp = tmp.slice(p + 4);
            break;
          }
        } while (pos < tmp.length);
        if (tmp.length > 0) {
          server.unshift(tmp);
        }
        if (/^https/.test(locUrl.protocol)) {
          server = tls.connect({ socket: server, rejectUnauthorized: false }, () => {
            server.write(Buffer.from(data, 'utf-8'));
            resolve(server);
          });
        } else {
          server.write(Buffer.from(data, 'utf-8'));
          resolve(server);
        }
      });
      server.write(`CONNECT ${locUrl.hostname}:${locUrl.port} ${httpVersion}\r\n\r\n`);
    };
    if (/^https/.test(protocol)) {
      options.port = options.port || 443;
      options.rejectUnauthorized = false;
      const server = tls.connect(options, () => {
        writeReq(server);
      });
      server.once('error', reject);
      return server;
    }
    options.port = options.port || 80;
    const server = net.connect(options, () => {
      writeReq(server);
    });
    server.once('error', reject);
    return server;
  });
}

function gitClone (root, pathname, baseUrl) {
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
  console.log('spawn =>', pathname, p.pid);
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

function pipeGit (pathname, env, cls, body, httpVersion) {
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
      console.error('git error =>', err);
      p.emit('git-done', err);
    });
    p.on('close', (code) => {
      console.log('git done =>', pathname, code);
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
  }
  client.write(`${httpVersion} 200 OK\r\n`);
  client.write('Content-Type: text/html;charset=utf-8\r\n');
  client.write('\r\n');
  client.write('自动缓存镜像服务，只需要把域名绑定到地址: ' + client.localAddress + '，即可自动缓存所有请求的资源，加速再次访问<br/>');
  if (PROXY) {
    client.write('当前使用代理服务: ' + PROXY.protocol + '://' + PROXY.host + ':' + PROXY.port + '<br/>');
  }
  client.write('为了支持https，需要在客户端安装根证书<br/><code>');
  client.write(`\tLinux: curl http://${client.localAddress}:${client.localPort}/root.crt >> /etc/pki/tls/certs/ca-bundle.crt <br/>`);
  client.write(`\tMacOS: 从 http://${client.localAddress}:${client.localPort}/root.crt 下载之后安装，并信任 <br/>`);
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
