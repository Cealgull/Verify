import { Buffer } from "buffer";
import crypto from "k6/crypto";
import nacl from "tweetnacl";
import http from "k6/http";

export default function () {
  const keypair = nacl.sign.keyPair.fromSeed(new Uint8Array(crypto.randomBytes(32)));
  const pub = Buffer.from(keypair.publicKey).toString("base64");
  const headers = {
    "content-type": "application/json",
    signature: "HACK",
  };
  const payload = JSON.stringify({
    pub: pub,
  });
  http.post("http://localhost:8080/cert/sign", payload, {
    headers,
  });
}
