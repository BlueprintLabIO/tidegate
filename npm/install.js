#!/usr/bin/env node
// Postinstall: download the platform-matched tidegate binary from the
// GitHub release matching this package version. The npm package is a thin
// wrapper; the real program is the Rust binary (esbuild/Biome pattern).
'use strict'
const fs = require('fs')
const path = require('path')
const https = require('https')
const { execSync } = require('child_process')

const VERSION = require('./package.json').version
const REPO = 'BlueprintLabIO/tidegate'

function target() {
  const p = process.platform
  const a = process.arch
  const os = p === 'darwin' ? 'apple-darwin' : p === 'linux' ? 'unknown-linux-gnu' : null
  const arch = a === 'arm64' ? 'aarch64' : a === 'x64' ? 'x86_64' : null
  if (!os || !arch) {
    console.error(`tidegate: no prebuilt binary for ${p}/${a}. Build from source: cargo install tidegate`)
    process.exit(0) // don't hard-fail the install; leave a clear message
  }
  return `${arch}-${os}`
}

function download(url, dest, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 10) return reject(new Error('too many redirects'))
    https.get(url, { headers: { 'User-Agent': 'tidegate-npm' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume()
        return resolve(download(res.headers.location, dest, redirects + 1))
      }
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode} for ${url}`))
      const file = fs.createWriteStream(dest)
      res.pipe(file)
      file.on('finish', () => file.close(resolve))
    }).on('error', reject)
  })
}

async function main() {
  const trip = target()
  const binName = process.platform === 'win32' ? 'tidegate.exe' : 'tidegate'
  const asset = `tidegate-${trip}.tar.gz`
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${asset}`
  const binDir = path.join(__dirname, 'bin')
  fs.mkdirSync(binDir, { recursive: true })
  const tarPath = path.join(binDir, asset)
  try {
    await download(url, tarPath)
    execSync(`tar -xzf "${tarPath}" -C "${binDir}"`, { stdio: 'ignore' })
    fs.unlinkSync(tarPath)
    fs.chmodSync(path.join(binDir, binName), 0o755)
    console.log(`tidegate ${VERSION} installed (${trip})`)
  } catch (e) {
    console.error(`tidegate: could not fetch the prebuilt binary (${e.message}).`)
    console.error(`Install from source instead: cargo install tidegate`)
    // Soft-fail: the wrapper's bin/tidegate.js will print guidance if run.
  }
}

main()
