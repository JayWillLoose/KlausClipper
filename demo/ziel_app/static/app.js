// ÜBUNGSZIEL – absichtlich unsicher
const config = { awsKey: "AKIAIOSFODNN7EXAMPLE", api: "/api/rechnungen/" };

const name = new URLSearchParams(location.search).get("name") || "Gast";
document.getElementById("gruss").innerHTML = "Hallo " + name; // XSS

function speichereLogin(token) {
  localStorage.setItem("auth_token", token);
}

window.addEventListener("message", (e) => { eval(e.data); });
