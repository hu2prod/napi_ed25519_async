#!/usr/bin/env iced
# probably optimal is UV_THREADPOOL_SIZE=8
ed25519 = require("ed25519")
mod = require("./index")
console.log "UV_THREADPOOL_SIZE=#{process.env.UV_THREADPOOL_SIZE}"


duration    = 1000 # быстрее результаты, чуть меньше точность
batch_size  = 1000
# ###################################################################################################
#    correctness sync
# ###################################################################################################
seed    = Buffer.alloc 32
message = Buffer.from "message"
bad_sign= Buffer.alloc 64
{
  privateKey: prv_key
  publicKey : pub_key
} = keypair = ed25519.MakeKeypair seed

prv_key2 = Buffer.alloc 64
pub_key2 = Buffer.alloc 32
mod.make_keypair_sync seed, pub_key2, prv_key2

if !pub_key.equals pub_key2
  throw new Error "!pub_key.equals pub_key2"


sign = ed25519.Sign message, keypair

sign2 = Buffer.alloc 64
mod.sign_pk_sync message, prv_key2, sign2

if !sign.equals sign2
  throw new Error "!sign.equals sign2"

if !ed25519.Verify message, sign, pub_key
  throw new Error "!verify of correct signature"

if !mod.verify_sync message, sign, pub_key
  throw new Error "!verify of correct signature"

if ed25519.Verify message, bad_sign, pub_key
  throw new Error "verify of incorrect signature"

if mod.verify_sync message, bad_sign, pub_key
  throw new Error "verify of incorrect signature"

# ###################################################################################################
#    correctness async
# ###################################################################################################

await mod.verify message, sign, pub_key, defer(err, res)
if !res
  throw new Error "!verify of correct signature"

await mod.verify message, bad_sign, pub_key, defer(err, res)
if res
  throw new Error "verify of incorrect signature"

# ###################################################################################################

verify_base = (message, sign, pub_key, cb)->
  cb null, ed25519.Verify message, sign, pub_key

verify_mod = mod.verify

# ###################################################################################################
bench_seq = (name, fn, cb)->
  start_ts = Date.now()
  
  i = 0
  loop
    message.writeUInt32BE i, 0
    await fn message, sign, pub_key, defer(err); return cb err if err
    
    if i % 100 == 0
      elp_ts = Date.now() - start_ts
      break if elp_ts > duration
    i++
  
  hashrate = i/(elp_ts/100)
  console.log "seq #{name} #{hashrate.toFixed(2)}"
  cb()

bench_par = (name, fn, cb)->
  start_ts = Date.now()
  
  hash_count = 0
  loop
    await
      for i in [0 ... batch_size]
        # немного некорректно
        loc_message = Buffer.from message
        loc_message.writeUInt32BE i, 0
        fn loc_message, sign, pub_key, defer()
    
    hash_count += batch_size
    elp_ts = Date.now() - start_ts
    break if elp_ts > duration
  
  hashrate = hash_count/(elp_ts/100)
  console.log "par #{name} #{hashrate.toFixed(2)}"
  cb()

await bench_seq "base", verify_base, defer(err); return cb err if err
await bench_par "mod ", verify_mod , defer(err); return cb err if err
