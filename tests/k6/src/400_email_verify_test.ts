import http from "k6/http";

export default function () {
  const number = Math.floor(Math.random() * 1000000);
  const payload = JSON.stringify({
    account: "user" + number.toString(),
    code: number.toString().padStart(6, "0"),
  });
  const headers = { "content-type": "application/json" };
  http.post("http://localhost:8080/email/verify", payload, { headers });
}
