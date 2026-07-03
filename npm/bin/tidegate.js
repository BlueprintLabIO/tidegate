#!/usr/bin/env node
// Launcher: exec the downloaded platform binary, forwarding all args + stdio.
'use strict'
const path = require('path')
const fs = require('fs')
const { spawnSync } = require('child_process')

const binName = process.platform === 'win32' ? 'tidegate.exe' : 'tidegate'
const bin = path.join(__dirname, binName)

if (!fs.existsSync(bin)) {
  console.error('tidegate: the native binary is missing.')
  console.error('Reinstall (npm install -g tidegate) or build from source: cargo install tidegate')
  process.exit(1)
}

const res = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' })
process.exit(res.status === null ? 1 : res.status)
