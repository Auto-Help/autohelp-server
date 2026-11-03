// Loaded into the server process by the tests only (node --require), never in
// production. Lets tests move the clock and simulate disk faults without any
// test hooks inside index.js.
//
//   AH_FAKE_CLOCK=1      Date.now() = real time + offset; the parent process
//                        advances it with an IPC message { advanceMs }.
//   AH_FS_FAULT=write2   the 2nd write into UPLOAD_DIR fails with ENOSPC.
//   AH_FS_FAULT=access   UPLOAD_DIR reports as not writable.
"use strict";

const fs = require("node:fs");
const path = require("node:path");

if (process.env.AH_FAKE_CLOCK === "1") {
  // Both Date.now() and `new Date()` follow the fake clock.
  const RealDate = Date;
  const realNow = RealDate.now;
  let offset = 0;
  function FakeDate(...args) {
    if (!new.target) return RealDate();
    return args.length ? new RealDate(...args) : new RealDate(realNow() + offset);
  }
  FakeDate.prototype = RealDate.prototype;
  FakeDate.now = () => realNow() + offset;
  FakeDate.parse = RealDate.parse;
  FakeDate.UTC = RealDate.UTC;
  global.Date = FakeDate;

  process.on("message", (m) => {
    if (m && typeof m.advanceMs === "number") offset += m.advanceMs;
    if (m && typeof m.setNow === "number") offset = m.setNow - realNow();
    process.send({ offset });
  });
}

const fault = process.env.AH_FS_FAULT;
const uploadDir = path.resolve(process.env.UPLOAD_DIR || "");
const inUploads = (p) => path.resolve(String(p)).startsWith(uploadDir + path.sep);

if (fault === "write2") {
  const realWrite = fs.writeFileSync;
  let writes = 0;
  fs.writeFileSync = function (file, ...rest) {
    if (typeof file === "string" && inUploads(file) && ++writes === 2) {
      const err = new Error("ENOSPC: no space left on device (simulated)");
      err.code = "ENOSPC";
      throw err;
    }
    return realWrite.call(this, file, ...rest);
  };
}

if (fault === "access") {
  const realAccess = fs.accessSync;
  fs.accessSync = function (p, ...rest) {
    if (path.resolve(String(p)) === uploadDir) {
      const err = new Error("EACCES (simulated)");
      err.code = "EACCES";
      throw err;
    }
    return realAccess.call(this, p, ...rest);
  };
}
